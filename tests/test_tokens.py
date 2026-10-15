"""Refresh rotation + reuse detection, revocation endpoints, lockout, rate limiting, JWKS no-leak, model check."""
import base64
import json
import os
import threading
import unittest
import urllib.parse
from unittest import mock

from tests import helpers
from tests.helpers import TempDirTestCase, make_server
from tests.test_http_e2e import Base, Http
from mcpauth import refreshcheck
from mcpauth.auth import Authenticator, Keyring
from mcpauth.tokens import AuthStore, GrantError, Lockout, RateLimiter, TokenAudit, TokenService


class Clk:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


def svc_for(tmp, clk, **kw):
    auth = Authenticator(Keyring(None, env_secret="svc-secret-0123456789abcdef"), "http://i", leeway=0, clock=clk)
    store = AuthStore(os.path.join(tmp, "a.sqlite3"), clock=clk)
    auth.revocations = store
    audit = TokenAudit(os.path.join(tmp, "t.log"), fsync=False)
    return TokenService(auth, store, audit=audit, **kw), audit


def err(fn, *a, **k):
    try:
        fn(*a, **k)
    except GrantError as exc:
        return exc.error
    return None


class RefreshRotation(TempDirTestCase):
    def setUp(self):
        super().setUp()
        os.makedirs(self.tmp, exist_ok=True)
        self.clk = Clk()
        self.svc, self.audit = svc_for(self.tmp, self.clk, access_ttl=100, refresh_ttl=1000)

    def issue(self):
        return self.svc.issue("demo-client", "alice", ["mcp", "tools:read", "memory:read"], offline=True)

    def test_rotation_issues_new_token_and_marks_old_used(self):
        a = self.issue()
        b = self.svc.refresh(a["refresh_token"], "demo-client")
        self.assertNotEqual(a["refresh_token"], b["refresh_token"])
        fam = self.svc.auth.inspect(a["access_token"])["fam"]
        self.assertEqual(self.svc.family_state(fam)["counts"], {"active": 1, "used": 1})

    def test_reuse_revokes_whole_family_including_newest_and_access_tokens(self):
        a = self.issue()
        b = self.svc.refresh(a["refresh_token"], "demo-client")
        self.assertEqual(err(self.svc.refresh, a["refresh_token"], "demo-client"), "invalid_grant")  # replay of the old token
        self.assertEqual(err(self.svc.refresh, b["refresh_token"], "demo-client"), "invalid_grant")  # newest now dead too
        fam = self.svc.auth.inspect(b["access_token"])["fam"]
        self.assertTrue(self.svc.family_state(fam)["revoked"])
        self.assertFalse(self.svc.introspect(b["access_token"])["active"])
        self.assertFalse(self.svc.introspect(a["access_token"])["active"])
        with self.assertRaises(Exception):
            self.svc.auth.verify(b["access_token"], [])

    def test_other_family_unaffected(self):
        a, o = self.issue(), self.issue()
        a2 = self.svc.refresh(a["refresh_token"], "demo-client")
        err(self.svc.refresh, a["refresh_token"], "demo-client")
        self.assertIn("refresh_token", self.svc.refresh(o["refresh_token"], "demo-client"))

    def test_no_scope_escalation_and_downscope_allowed(self):
        a = self.issue()
        self.assertEqual(err(self.svc.refresh, a["refresh_token"], "demo-client", ["mcp", "memory:admin"]), "invalid_scope")
        b = self.svc.refresh(a["refresh_token"], "demo-client", ["mcp"])  # token was not consumed by the refused request
        self.assertEqual(b["scope"], "mcp")

    def test_client_binding_expiry_malformed(self):
        a = self.issue()
        self.assertEqual(err(self.svc.refresh, a["refresh_token"], "admin-client"), "invalid_grant")
        for bad in (None, "", "rt_" + "x" * 300, "nope", 5, "rt_unknown"):
            self.assertEqual(err(self.svc.refresh, bad, "demo-client"), "invalid_grant", bad)
        self.clk.t += 1001
        self.assertEqual(err(self.svc.refresh, a["refresh_token"], "demo-client"), "invalid_grant")

    def test_concurrent_presentation_of_same_token_exactly_one_wins(self):
        a = self.issue()
        results = []

        def go():
            results.append(err(self.svc.refresh, a["refresh_token"], "demo-client") or "ok")

        ts = [threading.Thread(target=go) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(results.count("ok"), 1, results)
        fam = self.svc.auth.inspect(a["access_token"])["fam"]
        self.assertEqual(self.svc.family_state(fam)["counts"].get("active", 0), 0 if self.svc.family_state(fam)["revoked"] else 1)

    def test_refresh_tokens_stored_only_as_hashes(self):
        a = self.issue()
        import sqlite3
        c = sqlite3.connect(os.path.join(self.tmp, "a.sqlite3"))
        dump = "\n".join(str(r) for r in c.execute("SELECT * FROM refresh"))
        c.close()
        self.assertNotIn(a["refresh_token"], dump)

    def test_introspection_and_revoke_token(self):
        a = self.issue()
        self.assertTrue(self.svc.introspect(a["access_token"])["active"])
        self.assertTrue(self.svc.introspect(a["refresh_token"])["active"])
        self.assertEqual(self.svc.introspect("garbage"), {"active": False})
        self.svc.revoke_token(a["access_token"], "demo-client")
        self.assertFalse(self.svc.introspect(a["access_token"])["active"])
        self.svc.revoke_token(a["refresh_token"], "demo-client")
        self.assertFalse(self.svc.introspect(a["refresh_token"])["active"])
        self.assertEqual(err(self.svc.refresh, a["refresh_token"], "demo-client"), "invalid_grant")

    def test_non_admin_cannot_revoke_someone_elses_token(self):
        a = self.issue()
        self.svc.revoke_token(a["access_token"], "readonly-client")  # silently ignored per RFC 7009 semantics
        self.assertTrue(self.svc.introspect(a["access_token"])["active"])
        self.svc.revoke_token(a["access_token"], "admin-client", requester_is_admin=True)
        self.assertFalse(self.svc.introspect(a["access_token"])["active"])

    def test_audit_chain_and_events(self):
        a = self.issue()
        b = self.svc.refresh(a["refresh_token"], "demo-client")
        err(self.svc.refresh, a["refresh_token"], "demo-client")
        self.assertTrue(self.audit.verify()["ok"])
        with open(os.path.join(self.tmp, "t.log")) as fh:
            ev = [json.loads(json.loads(l)["payload"])["event"] for l in fh]
        self.assertEqual(ev[0], "refresh_issued")
        self.assertIn("reuse_detected", ev)
        with open(os.path.join(self.tmp, "t.log")) as fh:
            self.assertNotIn(a["refresh_token"], fh.read())


class Limits(unittest.TestCase):
    def test_rate_limiter_bucket_refill_and_isolation(self):
        clk = Clk()
        rl = RateLimiter(rate=1, burst=3, clock=clk)
        self.assertEqual([rl.allow("a")[0] for _ in range(5)][:3], [True, True, True])
        self.assertFalse(rl.allow("a")[0])
        self.assertTrue(rl.allow("b")[0])
        clk.t += 2
        self.assertTrue(rl.allow("a")[0])
        self.assertTrue(rl.allow("a")[0])
        self.assertFalse(rl.allow("a")[0])

    def test_lockout_window_duration_success_reset(self):
        clk = Clk()
        lo = Lockout(threshold=3, window=60, duration=30, clock=clk)
        self.assertEqual(lo.remaining("k"), 0)
        self.assertFalse(lo.failure("k"))
        self.assertFalse(lo.failure("k"))
        self.assertTrue(lo.failure("k"))
        self.assertGreater(lo.remaining("k"), 0)
        clk.t += 31
        self.assertEqual(lo.remaining("k"), 0)
        lo.failure("k")
        lo.success("k")
        lo.failure("k")
        self.assertFalse(lo.failure("k"), "success() cleared the counter")
        clk.t += 120
        for _ in range(2):
            self.assertFalse(lo.failure("z"))
        clk.t += 61
        self.assertFalse(lo.failure("z"), "failures outside the window do not count")


class Endpoints(Base):
    def setUp(self):
        super().setUp()
        self.server = make_server(self.data_dir, issuer=None)
        self.t = helpers.start_http(self.server)
        self.addCleanup(self.t.shutdown)
        self.c = Http(self.t.port)

    def form(self, path, fields, client="demo-client", secret=None):
        secret = secret if secret is not None else self.t.issuer.client_secret(client)
        h = {"Content-Type": "application/x-www-form-urlencoded",
             "Authorization": "Basic " + base64.b64encode(("%s:%s" % (client, secret)).encode()).decode()}
        st, data = self.c.req("POST", path, urllib.parse.urlencode(fields), h)
        return st, json.loads(data) if data else {}

    def test_jwks_and_discovery_do_not_leak_secrets(self):
        self.t.auth.keyring.rotate("RS256", 1024)
        raw = []
        for path in ("/.well-known/jwks.json", "/.well-known/openid-configuration"):
            st, data = self.c.req("GET", path)
            self.assertEqual(st, 200)
            raw.append(data)
        blob = "".join(raw)
        for k in self.t.auth.keyring.keys:
            for fld in ("secret",):
                if fld in k:
                    self.assertNotIn(k[fld], blob)
            if "rsa" in k:
                self.assertNotIn(str(k["rsa"]["d"]), blob)
        self.assertNotIn(self.t.auth.keyring.client_master_secret.hex() if isinstance(self.t.auth.keyring.client_master_secret, bytes) else "?", blob)
        jwks = json.loads(raw[0])
        kinds = {k["kty"] for k in jwks["keys"]}
        self.assertEqual(kinds, {"RSA", "oct"})
        for k in jwks["keys"]:
            self.assertNotIn("k", k)
            for forbidden in ("d", "p", "q", "dp", "dq", "qi", "secret"):
                self.assertNotIn(forbidden, k)
            self.assertIn("kid", k)

    def test_revoked_keys_disappear_from_jwks(self):
        kid = self.t.auth.keyring.active()["kid"]
        self.t.auth.keyring.rotate("HS256")
        self.t.auth.keyring.set_status(kid, "revoked")
        st, data = self.c.req("GET", "/.well-known/jwks.json")
        self.assertNotIn(kid, data)

    def test_client_credentials_refresh_reuse_over_http(self):
        st, a = self.form("/oauth/token", {"grant_type": "client_credentials", "scope": "mcp tools:read offline_access"})
        self.assertEqual(st, 200, a)
        st, b = self.form("/oauth/token", {"grant_type": "refresh_token", "refresh_token": a["refresh_token"]})
        self.assertEqual(st, 200)
        st, e = self.form("/oauth/token", {"grant_type": "refresh_token", "refresh_token": a["refresh_token"]})
        self.assertEqual((st, e["error"]), (400, "invalid_grant"))
        st, e = self.form("/oauth/token", {"grant_type": "refresh_token", "refresh_token": b["refresh_token"]})
        self.assertEqual((st, e["error"]), (400, "invalid_grant"))
        mcp = Http(self.t.port, b["access_token"])
        st, out = mcp.rpc(helpers.init_msg())
        self.assertEqual(st, 401, "access token of a revoked family is rejected by the MCP endpoint")

    def test_scope_not_permitted_and_unsupported_grant(self):
        st, e = self.form("/oauth/token", {"grant_type": "client_credentials", "scope": "auth:admin"}, client="readonly-client")
        self.assertEqual((st, e["error"]), (400, "invalid_scope"))
        st, e = self.form("/oauth/token", {"grant_type": "password"})
        self.assertEqual((st, e["error"]), (400, "unsupported_grant_type"))

    def test_introspection_requires_admin_client(self):
        st, a = self.form("/oauth/token", {"grant_type": "client_credentials", "scope": "mcp"})
        st, r = self.form("/oauth/introspect", {"token": a["access_token"]}, client="demo-client")
        self.assertEqual(st, 403)
        st, r = self.form("/oauth/introspect", {"token": a["access_token"]}, client="admin-client")
        self.assertEqual((st, r["active"], r["scope"]), (200, True, "mcp"))
        self.assertNotIn("secret", json.dumps(r))
        st, r = self.form("/oauth/introspect", {"token": "x.y.z"}, client="admin-client")
        self.assertEqual(r, {"active": False})

    def test_revoke_endpoint(self):
        st, a = self.form("/oauth/token", {"grant_type": "client_credentials", "scope": "mcp"})
        st, _ = self.form("/oauth/revoke", {"token": a["access_token"]})
        self.assertEqual(st, 200)
        self.assertEqual(Http(self.t.port, a["access_token"]).rpc(helpers.init_msg())[0], 401)

    def test_client_lockout_after_repeated_failures(self):
        codes = [self.form("/oauth/token", {"grant_type": "client_credentials"}, secret="wrong%d" % i)[0] for i in range(25)]
        self.assertIn(429, codes)
        st, _ = self.form("/oauth/token", {"grant_type": "client_credentials"})  # even the right secret waits out the lockout
        self.assertEqual(st, 429)

    def test_handler_crash_returns_500_not_dropped_connection(self):
        with mock.patch.object(type(self.t.issuer), "token_request", side_effect=RuntimeError("boom")):
            st, data = self.c.req("POST", "/oauth/token", "grant_type=client_credentials", {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(st, 500)
        self.assertEqual(json.loads(data), {"error": "server_error"})


class RefreshModelCheck(unittest.TestCase):
    def test_depth3_all_sequences_pass(self):
        stats = refreshcheck.check(3)
        self.assertTrue(stats["ok"], stats["violations"][:2])
        self.assertEqual(stats["sequences"], 7 ** 3)
        self.assertGreater(stats["results"]["ok"], 50)
        self.assertGreater(stats["results"]["invalid_grant"], 50)
        self.assertGreater(stats["results"]["invalid_scope"], 10)

    def test_injected_bug_no_reuse_detection_is_caught(self):
        orig = TokenService._revoke_family_tx
        with mock.patch.object(TokenService, "_revoke_family_tx", lambda self_, c, fam, reason: None if reason == "reuse_detected" else orig(self_, c, fam, reason)):
            stats = refreshcheck.check(3, alphabet=("refresh_A_newest", "refresh_A_first", "refresh_A_prev"))
        self.assertFalse(stats["ok"])
        self.assertTrue(any("refresh_A_first" in v["trace"] or "refresh_A_prev" in v["trace"] for v in stats["violations"]))

    def test_injected_bug_scope_escalation_is_caught(self):
        orig = TokenService.refresh
        def lax(self_, rt, client, scopes=None):
            return orig(self_, rt, client, None)
        with mock.patch.object(TokenService, "refresh", lax):
            stats = refreshcheck.check(2, alphabet=("escalate_A", "refresh_A_newest"))
        self.assertFalse(stats["ok"])


if __name__ == "__main__":
    unittest.main()
