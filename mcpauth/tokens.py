"""Token lifecycle for mcp-auth-hardened (NEW code): refresh-token rotation with reuse detection, revocation list,
introspection, rate limiting, lockout, and the mock-issuer endpoint logic (RFC 6749 / 7009 / 7662 subsets).

Refresh state machine (per family): each refresh token is ``active`` until used once -> ``used``; presenting a ``used`` token is
*reuse* (theft indicator) and revokes the whole family: every refresh token becomes ``revoked`` and every access token carrying that
``fam`` claim is rejected from then on. Verified by ``refreshcheck.py`` (bounded exhaustive model check) and tests.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import closing

from . import contracts
from .audit import AuditLog
from .auth import ALL_SCOPES, DEFAULT_CLIENTS, AuthError, parse_scopes

contracts.declare("AUTH-1", "a refresh family never has more than one active refresh token")
contracts.declare("AUTH-2", "a revoked family has no active refresh token and no refresh can succeed in it")
contracts.declare("AUTH-3", "scope of a refreshed token is a subset of the family's granted scope (no escalation)")


class GrantError(Exception):
    def __init__(self, error, description, status=400, headers=None):
        super().__init__("%s: %s" % (error, description))
        self.error, self.description, self.status, self.headers = error, description, status, headers or {}


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------- audit sink
class TokenAudit:
    """Hash-chained JWT/token event log (reuses the AuditLog chain format: seq/prev/hash, canonical JSON)."""

    def __init__(self, path, fsync=True):
        self.log = AuditLog(path, fsync=fsync)

    def __call__(self, event, **detail):
        detail = {k: v for k, v in detail.items() if v not in (None, "")}
        return self.log.append("event", json.dumps(dict(detail, event=event), sort_keys=True), "auth", "", str(detail.get("sub", ""))[:64])

    def verify(self, *a, **kw):
        return self.log.verify(*a, **kw)

    def tail(self, n=10):
        return self.log.tail(n)


# --------------------------------------------------------------------------------------- limits
class RateLimiter:
    """Token bucket per key: ``burst`` tokens, refilled at ``rate`` per second."""

    def __init__(self, rate, burst, clock=time.time):
        self.rate, self.burst, self.clock = float(rate), float(burst), clock
        self.buckets = {}
        self._lock = threading.Lock()

    def allow(self, key):
        """Returns (allowed, retry_after_seconds)."""
        now = self.clock()
        with self._lock:
            if len(self.buckets) > 20000:
                self.buckets.clear()
            tokens, last = self.buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self.buckets[key] = (tokens - 1, now)
                return True, 0.0
            self.buckets[key] = (tokens, now)
            return False, (1 - tokens) / self.rate if self.rate > 0 else 3600.0


class Lockout:
    """After ``threshold`` failures within ``window`` seconds a key is locked for ``duration`` seconds."""

    def __init__(self, threshold=20, window=60, duration=30, clock=time.time):
        self.threshold, self.window, self.duration, self.clock = threshold, window, duration, clock
        self.fails = {}
        self.locked = {}
        self._lock = threading.Lock()

    def remaining(self, key):
        now = self.clock()
        with self._lock:
            until = self.locked.get(key)
            if until is None:
                return 0.0
            if now >= until:
                del self.locked[key]
                self.fails.pop(key, None)
                return 0.0
            return until - now

    def failure(self, key):
        """Record a failure; returns True if this failure triggered a lockout."""
        now = self.clock()
        with self._lock:
            if len(self.fails) > 20000:
                self.fails.clear()
            recent = [t for t in self.fails.get(key, []) if now - t < self.window] + [now]
            self.fails[key] = recent
            if len(recent) >= self.threshold and key not in self.locked:
                self.locked[key] = now + self.duration
                return True
        return False

    def success(self, key):
        with self._lock:
            self.fails.pop(key, None)


# --------------------------------------------------------------------------------------- storage
class AuthStore:
    def __init__(self, path, clock=time.time):
        self.path = path
        self.clock = clock
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with closing(self._conn()) as c:
            c.execute("PRAGMA journal_mode = WAL")
            with c:
                c.executescript("""
                CREATE TABLE IF NOT EXISTS revoked_jti (jti TEXT PRIMARY KEY, exp REAL NOT NULL, reason TEXT NOT NULL, at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS families (fam TEXT PRIMARY KEY, client TEXT NOT NULL, sub TEXT NOT NULL, scope TEXT NOT NULL,
                    created REAL NOT NULL, revoked_at REAL, revoked_reason TEXT);
                CREATE TABLE IF NOT EXISTS refresh (hash TEXT PRIMARY KEY, fam TEXT NOT NULL REFERENCES families(fam), parent TEXT,
                    status TEXT NOT NULL CHECK (status IN ('active','used','revoked')), created REAL NOT NULL, expires REAL NOT NULL, used_at REAL);
                CREATE INDEX IF NOT EXISTS idx_refresh_fam ON refresh(fam);""")

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)  # explicit BEGIN IMMEDIATE below
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA synchronous = FULL")
        c.execute("PRAGMA foreign_keys = ON")
        return c

    def is_revoked(self, jti, fam=None):
        with closing(self._conn()) as c:
            r = c.execute("SELECT reason FROM revoked_jti WHERE jti = ?", (jti,)).fetchone()
            if r:
                return "jti:" + r["reason"]
            if fam:
                r = c.execute("SELECT revoked_reason FROM families WHERE fam = ? AND revoked_at IS NOT NULL", (fam,)).fetchone()
                if r:
                    return "family:" + (r["revoked_reason"] or "")
        return None

    def revoke_jti(self, jti, exp, reason):
        with closing(self._conn()) as c:
            c.execute("INSERT OR REPLACE INTO revoked_jti (jti, exp, reason, at) VALUES (?,?,?,?)", (jti, exp, reason, self.clock()))
            c.execute("DELETE FROM revoked_jti WHERE exp < ?", (self.clock() - 86400,))  # entries are useless long after expiry

    def list_revoked(self, limit=50):
        with closing(self._conn()) as c:
            return {"jti": [dict(r) for r in c.execute("SELECT * FROM revoked_jti ORDER BY at DESC LIMIT ?", (limit,))],
                    "families": [dict(r) for r in c.execute("SELECT fam, client, sub, revoked_at, revoked_reason FROM families WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC LIMIT ?", (limit,))]}


class TokenService:
    def __init__(self, auth, store, access_ttl=900, refresh_ttl=7 * 86400, audit=None):
        self.auth, self.store = auth, store
        self.access_ttl, self.refresh_ttl = access_ttl, refresh_ttl
        self.clock = auth.clock
        self._audit = audit or (lambda *a, **k: None)

    # ---- issuing
    def issue(self, client_id, subject, scopes, offline=False, ttl=None):
        scopes = [s for s in scopes if s != "offline_access"]
        fam = secrets.token_hex(8) if offline else None
        access = self.auth.mint(subject=subject, scopes=scopes, ttl=ttl or self.access_ttl, client_id=client_id, family=fam)
        out = {"access_token": access, "token_type": "Bearer", "expires_in": ttl or self.access_ttl, "scope": " ".join(scopes)}
        if offline:
            rt = "rt_" + secrets.token_urlsafe(32)
            now = self.clock()
            with closing(self.store._conn()) as c:
                c.execute("BEGIN IMMEDIATE")
                c.execute("INSERT INTO families (fam, client, sub, scope, created) VALUES (?,?,?,?,?)", (fam, client_id, subject, " ".join(scopes), now))
                c.execute("INSERT INTO refresh (hash, fam, parent, status, created, expires) VALUES (?,?,?,?,?,?)",
                          (sha256_hex(rt), fam, None, "active", now, now + self.refresh_ttl))
                c.execute("COMMIT")
            out["refresh_token"] = rt
            self._audit("refresh_issued", fam=fam, sub=subject, client_id=client_id)
        return out

    # ---- rotation
    def refresh(self, refresh_token, client_id, scopes=None):
        if not isinstance(refresh_token, str) or not refresh_token.startswith("rt_") or len(refresh_token) > 200:
            self._audit("refresh_rejected", reason="malformed", client_id=client_id)
            raise GrantError("invalid_grant", "invalid refresh token")
        h = sha256_hex(refresh_token)
        now = self.clock()
        with closing(self.store._conn()) as c:
            c.execute("BEGIN IMMEDIATE")  # serialises concurrent presentations of the same token
            try:
                row = c.execute("SELECT * FROM refresh WHERE hash = ?", (h,)).fetchone()
                if row is None or not hmac.compare_digest(row["hash"], h):
                    c.execute("COMMIT")
                    self._audit("refresh_rejected", reason="unknown", client_id=client_id)
                    raise GrantError("invalid_grant", "invalid refresh token")
                fam = c.execute("SELECT * FROM families WHERE fam = ?", (row["fam"],)).fetchone()
                if fam["client"] != client_id:
                    c.execute("COMMIT")
                    self._audit("refresh_rejected", reason="client_mismatch", fam=fam["fam"], client_id=client_id)
                    raise GrantError("invalid_grant", "invalid refresh token")
                if fam["revoked_at"] is not None or row["status"] == "revoked":
                    c.execute("COMMIT")
                    self._audit("refresh_rejected", reason="family_revoked", fam=fam["fam"], client_id=client_id)
                    raise GrantError("invalid_grant", "refresh token revoked")
                if row["status"] == "used":
                    self._revoke_family_tx(c, fam["fam"], "reuse_detected")
                    c.execute("COMMIT")
                    self._audit("reuse_detected", fam=fam["fam"], sub=fam["sub"], client_id=client_id)
                    raise GrantError("invalid_grant", "refresh token reuse detected; the whole token family has been revoked")
                if now >= row["expires"]:
                    c.execute("UPDATE refresh SET status='revoked' WHERE hash = ?", (h,))
                    c.execute("COMMIT")
                    self._audit("refresh_rejected", reason="expired", fam=fam["fam"], client_id=client_id)
                    raise GrantError("invalid_grant", "refresh token expired")
                granted = set(fam["scope"].split())
                want = set(scopes) if scopes else granted
                if not want <= granted:
                    c.execute("COMMIT")
                    self._audit("refresh_rejected", reason="scope_escalation", fam=fam["fam"], client_id=client_id)
                    raise GrantError("invalid_scope", "requested scope exceeds the originally granted scope")
                contracts.check("AUTH-3", want <= granted, "scope escalation on refresh")
                new_rt = "rt_" + secrets.token_urlsafe(32)
                c.execute("UPDATE refresh SET status='used', used_at=? WHERE hash = ?", (now, h))
                c.execute("INSERT INTO refresh (hash, fam, parent, status, created, expires) VALUES (?,?,?,?,?,?)",
                          (sha256_hex(new_rt), fam["fam"], h, "active", now, now + self.refresh_ttl))
                n_active = c.execute("SELECT COUNT(*) FROM refresh WHERE fam = ? AND status = 'active'", (fam["fam"],)).fetchone()[0]
                contracts.check("AUTH-1", n_active == 1, lambda: "family %s has %d active refresh tokens" % (fam["fam"], n_active))
                c.execute("COMMIT")
            except GrantError:
                raise
            except Exception:
                try:
                    c.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        ordered = sorted(want)
        access = self.auth.mint(subject=fam["sub"], scopes=ordered, ttl=self.access_ttl, client_id=client_id, family=fam["fam"])
        self._audit("refresh", fam=fam["fam"], sub=fam["sub"], client_id=client_id)
        return {"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl, "scope": " ".join(ordered), "refresh_token": new_rt}

    def _revoke_family_tx(self, c, fam, reason):
        c.execute("UPDATE families SET revoked_at = ?, revoked_reason = ? WHERE fam = ? AND revoked_at IS NULL", (self.clock(), reason, fam))
        c.execute("UPDATE refresh SET status = 'revoked' WHERE fam = ? AND status != 'revoked'", (fam,))
        n_active = c.execute("SELECT COUNT(*) FROM refresh WHERE fam = ? AND status = 'active'", (fam,)).fetchone()[0]
        contracts.check("AUTH-2", n_active == 0, "revoked family still has active refresh tokens")

    def revoke_family(self, fam, reason="revoked"):
        with closing(self.store._conn()) as c:
            c.execute("BEGIN IMMEDIATE")
            self._revoke_family_tx(c, fam, reason)
            c.execute("COMMIT")
        self._audit("revoke", kind="family", fam=fam, reason=reason)

    # ---- revoke / introspect (RFC 7009 / 7662 semantics)
    def revoke_token(self, token, requester, requester_is_admin=False, reason="client_request"):
        """Never raises for unknown tokens (RFC 7009). Returns a short status for the audit trail."""
        if isinstance(token, str) and token.startswith("rt_"):
            with closing(self.store._conn()) as c:
                row = c.execute("SELECT r.fam, f.client FROM refresh r JOIN families f ON f.fam = r.fam WHERE r.hash = ?", (sha256_hex(token),)).fetchone()
            if row is None:
                self._audit("revoke", kind="refresh", result="unknown", client_id=requester)
                return "unknown"
            if row["client"] != requester and not requester_is_admin:
                self._audit("revoke_denied", kind="refresh", fam=row["fam"], client_id=requester)
                return "denied"
            self.revoke_family(row["fam"], reason)
            return "revoked_family"
        try:
            claims = self.auth.inspect(token)
        except AuthError:
            self._audit("revoke", kind="access", result="invalid", client_id=requester)
            return "invalid"
        if claims.get("client_id") != requester and not requester_is_admin:
            self._audit("revoke_denied", kind="access", jti=claims["jti"], client_id=requester)
            return "denied"
        self.store.revoke_jti(claims["jti"], claims["exp"], reason)
        self._audit("revoke", kind="access", jti=claims["jti"], sub=claims["sub"], client_id=requester, reason=reason)
        return "revoked_jti"

    def introspect(self, token):
        now = self.clock()
        if isinstance(token, str) and token.startswith("rt_"):
            with closing(self.store._conn()) as c:
                row = c.execute("SELECT r.status, r.expires, f.* FROM refresh r JOIN families f ON f.fam = r.fam WHERE r.hash = ?", (sha256_hex(token),)).fetchone()
            if row is None or row["status"] != "active" or row["revoked_at"] is not None or now >= row["expires"]:
                return {"active": False}
            return {"active": True, "token_type": "refresh_token", "scope": row["scope"], "client_id": row["client"], "sub": row["sub"], "exp": int(row["expires"])}
        try:
            claims = self.auth.inspect(token)
        except AuthError:
            return {"active": False}
        if now >= claims["exp"] or self.store.is_revoked(claims["jti"], claims.get("fam")):
            return {"active": False}
        out = {"active": True, "token_type": "Bearer", "scope": " ".join(claims["_granted"]), "client_id": claims.get("client_id", ""),
               "sub": claims["sub"], "exp": claims["exp"], "iat": claims["iat"], "jti": claims["jti"], "iss": claims["iss"],
               "aud": claims["aud"], "kid": claims["_kid"]}
        return out

    def family_state(self, fam):
        with closing(self.store._conn()) as c:
            f = c.execute("SELECT * FROM families WHERE fam = ?", (fam,)).fetchone()
            rows = [dict(r) for r in c.execute("SELECT status, COUNT(*) n FROM refresh WHERE fam = ? GROUP BY status", (fam,))] if f else []
        return None if f is None else {"revoked": f["revoked_at"] is not None, "counts": {r["status"]: r["n"] for r in rows}}


# --------------------------------------------------------------------------------------- the mock issuer
class OidcIssuer:
    """HTTP-independent endpoint logic. Every method returns (status, body_dict, extra_headers)."""

    def __init__(self, auth, service, lockout, clients=None):
        self.auth, self.service, self.lockout = auth, service, lockout
        self.clients = dict(clients or DEFAULT_CLIENTS)
        self._audit = service._audit

    def client_secret(self, client_id):
        digest = hmac.new(self.auth.keyring.client_master_secret, b"mcpauth-client:" + client_id.encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()[:32]

    def discovery_document(self):
        iss = self.auth.issuer.rstrip("/")
        algs = sorted({k["alg"] for k in self.auth.keyring.keys if k["status"] != "revoked"})
        return {"issuer": self.auth.issuer, "token_endpoint": iss + "/oauth/token", "jwks_uri": iss + "/.well-known/jwks.json",
                "introspection_endpoint": iss + "/oauth/introspect", "revocation_endpoint": iss + "/oauth/revoke",
                "grant_types_supported": ["client_credentials", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                "response_types_supported": [], "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": algs,
                "scopes_supported": list(ALL_SCOPES) + ["offline_access"],
                "x-mcp-note": "simplified mock issuer: HS256 keys are listed in jwks_uri WITHOUT secrets; not OIDC-certified"}

    def jwks(self):
        return {"keys": [k for k in self.auth.keyring.public_view() if k["status"] != "revoked"]}

    # -- client authentication with lockout
    def _client(self, authz, form):
        client_id = secret = None
        if authz and authz.lower().startswith("basic "):
            try:
                raw = base64.b64decode(authz[6:].strip(), validate=True).decode("utf-8")
                client_id, _, secret = raw.partition(":")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                raise GrantError("invalid_client", "malformed Basic credentials", 401)
        else:
            client_id, secret = form.get("client_id"), form.get("client_secret")
        if not client_id or secret is None:
            raise GrantError("invalid_client", "client authentication required", 401)
        key = "client:" + client_id[:64]
        wait = self.lockout.remaining(key)
        if wait > 0:
            self._audit("lockout_block", client_id=client_id[:64])
            raise GrantError("temporarily_unavailable", "too many failed attempts; retry later", 429, {"Retry-After": str(int(wait) + 1)})
        known = client_id in self.clients
        expected = self.client_secret(client_id if known else "unknown")
        if not (hmac.compare_digest(expected.encode("utf-8"), secret.encode("utf-8")) and known):
            if self.lockout.failure(key):
                self._audit("lockout", client_id=client_id[:64])
            self._audit("client_auth_failed", client_id=client_id[:64])
            raise GrantError("invalid_client", "bad client credentials", 401)
        self.lockout.success(key)
        return client_id

    def token_request(self, authz, form):
        try:
            client_id = self._client(authz, form)
            grant = form.get("grant_type")
            allowed = self.clients[client_id]
            if grant == "client_credentials":
                requested = form.get("scope")
                scopes = tuple(requested.split()) if requested else tuple(s for s in allowed if s != "offline_access")
                if not scopes or any(s not in allowed for s in scopes):
                    raise GrantError("invalid_scope", "scope not permitted for this client")
                offline = "offline_access" in scopes
                body = self.service.issue(client_id, client_id, scopes, offline=offline)
            elif grant == "refresh_token":
                scopes = form.get("scope", "").split() or None
                body = self.service.refresh(form.get("refresh_token", ""), client_id, scopes)
            else:
                raise GrantError("unsupported_grant_type", "client_credentials or refresh_token")
            return 200, body, {"Pragma": "no-cache"}
        except GrantError as exc:
            return exc.status, {"error": exc.error, "error_description": exc.description}, dict(exc.headers, Pragma="no-cache")

    def introspect_request(self, authz, form):
        try:
            client_id = self._client(authz, form)
        except GrantError as exc:
            return exc.status, {"error": exc.error, "error_description": exc.description}, exc.headers
        if "auth:admin" not in self.clients[client_id]:
            self._audit("introspect_denied", client_id=client_id)
            return 403, {"error": "access_denied", "error_description": "client may not introspect"}, {}
        res = self.service.introspect(form.get("token", ""))
        self._audit("introspect", client_id=client_id, active=res["active"])
        return 200, res, {"Cache-Control": "no-store"}

    def revoke_request(self, authz, form):
        try:
            client_id = self._client(authz, form)
        except GrantError as exc:
            return exc.status, {"error": exc.error, "error_description": exc.description}, exc.headers
        self.service.revoke_token(form.get("token", ""), client_id, "auth:admin" in self.clients[client_id])
        return 200, {}, {}
