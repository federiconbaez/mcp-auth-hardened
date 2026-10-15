"""Hardened simplified-OIDC token validation (NEW code for mcp-auth-hardened; base64url helpers adapted from mcp-forge).

THIS IS NOT FULL OIDC AND NOT CERTIFIED. What is implemented:

* A keyring with several signing keys identified by ``kid``: HS256 (symmetric, secret never published) and RS256
  (hand-written PKCS#1 v1.5 verification, public key publishable in a JWKS document).
* Key lifecycle: active -> retired (verifies until ``retired_until``) -> revoked/expired (rejected). Rotation does not invalidate
  tokens signed by the previous key during the grace period.
* Algorithm pinning: the header ``alg`` must equal the algorithm recorded for that ``kid`` (blocks alg-confusion and ``none``).
* Claim validation: iss, aud, sub, exp, iat, nbf, jti (required), clock-skew leeway, scope parsing + implication expansion.
* Revocation: per-``jti`` and per-refresh-family (checked on every request, also on long-lived stdio sessions).
* Hash-chained token audit log: every issue/validate/reject/revoke/refresh/reuse/key event.

Not implemented: authorization-code flow + PKCE, end-user id_tokens, dynamic client registration, JWKS fetching/caching
by a remote client, mTLS/DPoP, token binding.
"""

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time

from . import rsa

MAX_TOKEN_LEN = 8192
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
KID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
BASE_SCOPE = "mcp"
ALL_SCOPES = ("mcp", "tools:read", "tools:write", "resources:read", "prompts:read", "memory:read", "memory:write",
              "memory:admin", "audit:read", "auth:admin")
# a scope on the left also grants every scope on the right (documented, tested; never implicit beyond this table)
IMPLIES = {"tools:write": ("tools:read",), "memory:admin": ("memory:write", "memory:read"), "memory:write": ("memory:read",)}
DEFAULT_AUDIENCE = "mcp-auth-hardened"
DEFAULT_ISSUER = "http://127.0.0.1:8765"
ALGS = ("HS256", "RS256")

# client registry for the mock issuer: client_id -> scopes it may request (+offline_access for refresh tokens)
DEFAULT_CLIENTS = {
    "demo-client": ("mcp", "tools:read", "tools:write", "resources:read", "prompts:read", "memory:read", "memory:write", "memory:admin",
                    "audit:read", "offline_access"),
    "readonly-client": ("mcp", "tools:read", "resources:read", "prompts:read", "memory:read", "offline_access"),
    "admin-client": ALL_SCOPES + ("offline_access",),
}


class AuthError(Exception):
    """Token or credential rejected. ``error`` follows RFC 6750 / RFC 6749 names."""

    def __init__(self, error, description, status=401, reason=None):
        super().__init__("%s: %s" % (error, description))
        self.error = error
        self.description = description
        self.status = status
        self.reason = reason or description  # short machine-ish reason for the audit log


# ---- base64url (strict, canonical) ---------------------------------------
def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    if not isinstance(text, str) or not B64URL_RE.match(text) or len(text) % 4 == 1:
        raise ValueError("invalid base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("invalid base64url")
    if b64url_encode(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


def _json_b64(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def parse_scopes(claim):
    if isinstance(claim, str):
        return set(claim.split())
    if isinstance(claim, list) and all(isinstance(x, str) for x in claim):
        return set(claim)
    return set()


def expand_scopes(granted):
    out = set(granted)
    changed = True
    while changed:
        changed = False
        for s in list(out):
            for implied in IMPLIES.get(s, ()):
                if implied not in out:
                    out.add(implied)
                    changed = True
    return out


def fingerprint(token):
    """Short non-reversible handle for logs (never log the token itself)."""
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()[:16]


# ---- keyring ----------------------------------------------------------------
class Keyring:
    """Persistent set of signing keys: <data_dir>/keys.json (0600), or a single in-memory HS256 key from $MCP_FORGE_SECRET.

    Key record: {"kid", "alg", "status": active|retired|revoked, "created", "retired_until"?, "secret"(hex, HS256) | "rsa": {n,e,d}(hex)}
    """

    def __init__(self, path=None, env_secret=None, clock=time.time, grace=86400):
        self.path = path
        self.clock = clock
        self.grace = grace
        self.keys = []
        if env_secret:
            self.keys = [{"kid": "env", "alg": "HS256", "status": "active", "created": int(clock()), "secret": env_secret.encode("utf-8").hex()}]
            self.path = None
        elif path:
            self._load_or_init()

    # -- persistence
    def _load_or_init(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), mode=0o700, exist_ok=True)
        if not os.path.exists(self.path):
            self.keys = [self._new_hs256()]
            try:
                self._write_new()
            except FileExistsError:
                pass
        self.reload()

    def _write_new(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"keys": self.keys, "client_master": secrets.token_hex(32)}, fh)

    def reload(self):
        if not self.path:
            return
        for _ in range(100):  # another process may still be writing the file
            try:
                with open(self.path) as fh:
                    doc = json.load(fh)
                self.keys = doc["keys"]
                self.client_master = doc["client_master"].encode("ascii")
                return
            except (ValueError, KeyError, FileNotFoundError):
                time.sleep(0.02)
        raise ValueError("keys file unreadable: %s" % self.path)

    def _save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"keys": self.keys, "client_master": self.client_master.decode("ascii")}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    @property
    def client_master_secret(self):
        return getattr(self, "client_master", None) or hashlib.sha256(b"env-client-master:" + bytes.fromhex(self.keys[0]["secret"])).digest()

    # -- key creation
    def _kid(self):
        return "k-" + secrets.token_hex(4)

    def _new_hs256(self):
        return {"kid": self._kid(), "alg": "HS256", "status": "active", "created": int(self.clock()), "secret": secrets.token_hex(32)}

    def _activate(self, key):
        for k in self.keys:
            if k["status"] == "active":
                k["status"] = "retired"
                k["retired_until"] = int(self.clock()) + self.grace
        self.keys.append(key)
        self._save()
        return key

    def rotate(self, alg="HS256", bits=2048):
        """Create a new active key; the previous active key becomes retired for ``grace`` seconds."""
        self.reload()
        if alg == "HS256":
            key = self._new_hs256()
        elif alg == "RS256":
            k = rsa.generate_key(bits)
            key = {"kid": self._kid(), "alg": "RS256", "status": "active", "created": int(self.clock()),
                   "rsa": {"n": "%x" % k["n"], "e": "%x" % k["e"], "d": "%x" % k["d"]}}
        else:
            raise ValueError("alg must be HS256 or RS256")
        return self._activate(key)

    def add_rsa_public(self, kid, n, e):
        """Trust an externally generated RSA public key (verify-only)."""
        if not KID_RE.match(kid) or self.get(kid):
            raise ValueError("bad or duplicate kid")
        key = {"kid": kid, "alg": "RS256", "status": "retired", "created": int(self.clock()), "retired_until": int(self.clock()) + 10 * 365 * 86400,
               "rsa": {"n": "%x" % n, "e": "%x" % e}}
        self.keys.append(key)
        self._save()
        return key

    def set_status(self, kid, status):
        self.reload()
        key = self.get(kid)
        if key is None:
            raise ValueError("unknown kid")
        if status == "revoked":
            key["status"] = "revoked"
        elif status == "retired":
            key["status"] = "retired"
            key["retired_until"] = int(self.clock()) + self.grace
        self._save()
        return key

    # -- lookup
    def get(self, kid):
        for k in self.keys:
            if k["kid"] == kid:
                return k
        return None

    def active(self):
        for k in reversed(self.keys):
            if k["status"] == "active":
                return k
        raise ValueError("no active key")

    def usable(self, key):
        """(ok, reason) for verification at the current time."""
        if key["status"] == "revoked":
            return False, "signing key revoked"
        if key["status"] == "retired" and self.clock() >= key.get("retired_until", 0):
            return False, "signing key retired (grace period over)"
        return True, ""

    def public_view(self):
        """What may be published (JWKS-like). HS256 secrets and RSA private exponents are NEVER included."""
        out = []
        for k in self.keys:
            item = {"kid": k["kid"], "alg": k["alg"], "use": "sig", "status": k["status"], "created": k["created"]}
            if k["alg"] == "RS256":
                n, e = int(k["rsa"]["n"], 16), int(k["rsa"]["e"], 16)
                item.update({"kty": "RSA", "n": rsa.int_to_b64u(n), "e": rsa.int_to_b64u(e)})
            else:
                item.update({"kty": "oct", "x-note": "symmetric key: secret withheld, cannot be published; verify through introspection"})
            out.append(item)
        return out

    # -- signing / verifying primitives
    def sign(self, signing_input, key):
        if key["alg"] == "HS256":
            return hmac.new(bytes.fromhex(key["secret"]), signing_input, hashlib.sha256).digest()
        r = key["rsa"]
        if "d" not in r:
            raise ValueError("verify-only key cannot sign")
        return rsa.sign(signing_input, int(r["n"], 16), int(r["d"], 16))

    def check_signature(self, signing_input, signature, key):
        if key["alg"] == "HS256":
            return hmac.compare_digest(hmac.new(bytes.fromhex(key["secret"]), signing_input, hashlib.sha256).digest(), signature)
        return rsa.verify(signing_input, signature, int(key["rsa"]["n"], 16), int(key["rsa"]["e"], 16))


class Authenticator:
    """Validates tokens against a Keyring, a revocation oracle and an audit sink."""

    def __init__(self, keyring, issuer, audience=DEFAULT_AUDIENCE, leeway=30, clock=time.time, allow_kidless=False,
                 revocations=None, audit=None):
        self.keyring = keyring
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.clock = clock
        self.allow_kidless = allow_kidless
        self.revocations = revocations   # object with is_revoked(jti, fam) -> reason|None
        self.audit = audit               # callable(event, **detail) or None

    # -- audit helper
    def _emit(self, event, **detail):
        if self.audit:
            self.audit(event, **detail)

    # -- issuing
    def mint(self, subject="demo-user", scopes=ALL_SCOPES, ttl=3600, audience=None, issuer=None, not_before_offset=0,
             issued_at_offset=0, client_id=None, family=None, kid=None, extra=None):
        key = self.keyring.get(kid) if kid else self.keyring.active()
        if key is None:
            raise ValueError("unknown kid")
        now = int(self.clock())
        claims = {"iss": issuer or self.issuer, "sub": subject, "aud": audience or self.audience, "iat": now + issued_at_offset,
                  "nbf": now + not_before_offset, "exp": now + int(ttl), "scope": " ".join(scopes), "jti": secrets.token_hex(12)}
        if client_id:
            claims["client_id"] = client_id
        if family:
            claims["fam"] = family
        claims.update(extra or {})
        header = {"alg": key["alg"], "typ": "JWT", "kid": key["kid"]}
        signing_input = ("%s.%s" % (_json_b64(header), _json_b64(claims))).encode("ascii")
        token = signing_input.decode("ascii") + "." + b64url_encode(self.keyring.sign(signing_input, key))
        self._emit("issue", jti=claims["jti"], sub=subject, kid=key["kid"], alg=key["alg"], scope=claims["scope"], fp=fingerprint(token),
                   exp=claims["exp"], client_id=client_id or "", fam=family or "")
        return token

    # -- verification
    def verify(self, token, required_scopes=(), source=""):
        try:
            claims = self._verify(token, required_scopes)
        except AuthError as exc:
            self._emit("reject", reason=exc.reason, error=exc.error, fp=fingerprint(token) if isinstance(token, str) else "", source=source)
            raise
        self._emit("validate", jti=claims["jti"], sub=claims["sub"], kid=claims["_kid"], source=source)
        return claims

    def _parse(self, token):
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LEN:
            raise AuthError("invalid_token", "token missing or too long", reason="missing_or_too_long")
        if not TOKEN_RE.match(token):
            raise AuthError("invalid_token", "token contains characters outside the base64url/JWS alphabet", reason="bad_alphabet")
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthError("invalid_token", "token is not a compact JWS (3 parts)", reason="not_jws")
        try:
            header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
            signature = b64url_decode(parts[2])
        except (ValueError, UnicodeDecodeError):
            raise AuthError("invalid_token", "malformed token encoding", reason="bad_encoding")
        if not isinstance(header, dict):
            raise AuthError("invalid_token", "header must be an object", reason="bad_header")
        return parts, header, signature

    def _verify(self, token, required_scopes, check_time=True, check_revocation=True):
        parts, header, signature = self._parse(token)
        alg = header.get("alg")
        if alg not in ALGS:
            raise AuthError("invalid_token", "unsupported or missing alg (HS256 and RS256 only)", reason="alg_not_allowed")
        signing_input = (parts[0] + "." + parts[1]).encode("ascii")
        kid = header.get("kid")
        if kid is None:
            if not (self.allow_kidless and alg == "HS256"):
                raise AuthError("invalid_token", "missing kid", reason="missing_kid")
            candidates = [k for k in self.keyring.keys if k["alg"] == "HS256" and self.keyring.usable(k)[0]]
            key = None
            for k in candidates:  # constant-time per key; no early exit on first mismatch timing beyond key count
                if self.keyring.check_signature(signing_input, signature, k):
                    key = k
            if key is None:
                raise AuthError("invalid_token", "signature verification failed", reason="bad_signature")
        else:
            if not isinstance(kid, str) or not KID_RE.match(kid):
                raise AuthError("invalid_token", "malformed kid", reason="bad_kid")
            key = self.keyring.get(kid)
            if key is None:
                raise AuthError("invalid_token", "unknown kid", reason="unknown_kid")
            if key["alg"] != alg:
                raise AuthError("invalid_token", "alg does not match the key's algorithm", reason="alg_confusion")
            ok, why = self.keyring.usable(key)
            if not ok:
                raise AuthError("invalid_token", why, reason=why.replace(" ", "_"))
            if not self.keyring.check_signature(signing_input, signature, key):
                raise AuthError("invalid_token", "signature verification failed", reason="bad_signature")
        try:
            claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise AuthError("invalid_token", "malformed claims", reason="bad_claims")
        if not isinstance(claims, dict):
            raise AuthError("invalid_token", "claims must be an object", reason="bad_claims")
        now = self.clock()
        if claims.get("iss") != self.issuer:
            raise AuthError("invalid_token", "wrong issuer", reason="wrong_issuer")
        aud = claims.get("aud")
        auds = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
        if self.audience not in auds:
            raise AuthError("invalid_token", "wrong audience", reason="wrong_audience")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise AuthError("invalid_token", "missing sub", reason="missing_sub")
        if not isinstance(claims.get("jti"), str) or not claims["jti"]:
            raise AuthError("invalid_token", "missing jti", reason="missing_jti")
        if not _num(claims.get("exp")):
            raise AuthError("invalid_token", "missing exp", reason="missing_exp")
        if check_time and now >= claims["exp"] + self.leeway:
            raise AuthError("invalid_token", "token expired", reason="expired")
        if not _num(claims.get("iat")):
            raise AuthError("invalid_token", "missing iat", reason="missing_iat")
        if check_time and claims["iat"] > now + self.leeway:
            raise AuthError("invalid_token", "iat is in the future", reason="iat_future")
        if "nbf" in claims:
            if not _num(claims["nbf"]):
                raise AuthError("invalid_token", "bad nbf", reason="bad_nbf")
            if check_time and claims["nbf"] > now + self.leeway:
                raise AuthError("invalid_token", "token not yet valid (nbf)", reason="nbf_future")
        if check_revocation and self.revocations is not None:
            why = self.revocations.is_revoked(claims["jti"], claims.get("fam"))
            if why:
                raise AuthError("invalid_token", "token has been revoked", reason="revoked:" + why)
        granted = parse_scopes(claims.get("scope"))
        effective = expand_scopes(granted)
        missing = [s for s in required_scopes if s not in effective]
        if missing:
            raise AuthError("insufficient_scope", "missing scope: " + " ".join(missing), status=403, reason="insufficient_scope")
        claims["_scopes"] = sorted(effective)
        claims["_granted"] = sorted(granted)
        claims["_kid"] = key["kid"]
        claims["_alg"] = key["alg"]
        return claims

    def inspect(self, token):
        """Signature+claims check ignoring time and revocation (used by revoke/introspect to read jti safely). Raises AuthError."""
        return self._verify(token, (), check_time=False, check_revocation=False)

    def still_valid(self, claims):
        """Per-request re-check on long-lived (stdio) sessions: not expired, not revoked, key still usable."""
        if self.clock() >= claims["exp"] + self.leeway:
            return False
        key = self.keyring.get(claims.get("_kid", ""))
        if key is not None and not self.keyring.usable(key)[0]:
            return False
        if self.revocations is not None and self.revocations.is_revoked(claims["jti"], claims.get("fam")):
            return False
        return True
