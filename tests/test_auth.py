"""Hardened auth: keyring, kid rotation, RS256 JWTs, claims, leeway, revocation, scope implication, audit chain."""
import base64
import json
import os
import unittest

from tests.helpers import TempDirTestCase
from mcpauth.audit import verify_file
from mcpauth.auth import ALL_SCOPES, Authenticator, AuthError, Keyring, b64url_decode, b64url_encode, expand_scopes, parse_scopes
from mcpauth.tokens import AuthStore, TokenAudit

ISS = "http://issuer.test"


class Clk:
    def __init__(self, t=1_800_000_000):
        self.t = t

    def __call__(self):
        return self.t


def mk(tmp, clk=None, **kw):
    clk = clk or Clk()
    kr = Keyring(os.path.join(tmp, "keys.json"), clock=clk)
    return Authenticator(kr, ISS, "aud-1", clock=clk, **kw), kr, clk


def reason(a, token, scopes=()):
    try:
        a.verify(token, scopes)
    except AuthError as exc:
        return exc.reason
    return None


def retoken(token, header=None, claims=None, sig=None):
    h, c, s = token.split(".")
    if header is not None:
        h = b64url_encode(json.dumps(header).encode())
    if claims is not None:
        c = b64url_encode(json.dumps(claims).encode())
    return ".".join([h, c, sig if sig is not None else s])


class KeyringTests(TempDirTestCase):
    def test_keys_file_is_0600_and_public_view_never_leaks_secrets(self):
        a, kr, _ = mk(self.tmp)
        mode = os.stat(os.path.join(self.tmp, "keys.json")).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        kr.rotate("RS256", 1024)
        view = json.dumps(kr.public_view())
        for k in kr.keys:
            if "secret" in k:
                self.assertNotIn(k["secret"], view)
            if "rsa" in k:
                self.assertNotIn(k["rsa"]["d"], view)
        self.assertNotIn('"k"', view)
        self.assertIn("RSA", view)
        self.assertIn("oct", view)

    def test_env_secret_gives_single_in_memory_key(self):
        kr = Keyring(None, env_secret="x" * 20)
        self.assertEqual([k["kid"] for k in kr.keys], ["env"])
        self.assertEqual(kr.active()["kid"], "env")

    def test_rotation_retire_grace_and_expiry(self):
        a, kr, clk = mk(self.tmp)
        t1 = a.mint()
        k1 = kr.active()["kid"]
        kr.rotate("HS256")
        k2 = kr.active()["kid"]
        self.assertNotEqual(k1, k2)
        self.assertEqual(kr.get(k1)["status"], "retired")
        self.assertIsNone(reason(a, t1))                    # retired key verifies during grace
        self.assertIsNone(reason(a, a.mint()))
        clk.t += kr.grace + 1
        self.assertEqual(reason(Authenticator(kr, ISS, "aud-1", clock=clk, leeway=10 ** 9), t1), "signing_key_retired_(grace_period_over)")

    def test_revoking_active_key_rolls_a_new_one(self):
        a, kr, _ = mk(self.tmp)
        t = a.mint()
        kid = kr.active()["kid"]
        kr.set_status(kid, "revoked")
        self.assertNotEqual(kr.active()["kid"], kid)
        self.assertEqual(reason(a, t), "signing_key_revoked")
        self.assertIsNone(reason(a, a.mint()))

    def test_second_process_changes_are_picked_up(self):
        a, kr, clk = mk(self.tmp)
        other = Keyring(os.path.join(self.tmp, "keys.json"), clock=clk)
        other.rotate("HS256")
        newtok = Authenticator(other, ISS, "aud-1", clock=clk).mint()
        self.assertIsNone(reason(a, newtok), "authenticator reloads keys.json when it changes")

    def test_rs256_end_to_end_with_rotation(self):
        a, kr, _ = mk(self.tmp)
        kr.rotate("RS256", 1024)
        tok = a.mint(subject="rsa-user")
        self.assertEqual(json.loads(b64url_decode(tok.split(".")[0]))["alg"], "RS256")
        claims = a.verify(tok, ["mcp"])
        self.assertEqual((claims["sub"], claims["_alg"]), ("rsa-user", "RS256"))
        bad = retoken(tok, sig=b64url_encode(b"\x01" * 128))
        self.assertEqual(reason(a, bad), "bad_signature")
        # tamper with a claim, keep the signature
        c = json.loads(b64url_decode(tok.split(".")[1]))
        c["scope"] = "auth:admin"
        self.assertEqual(reason(a, retoken(tok, claims=c)), "bad_signature")

    def test_verify_only_rsa_key_cannot_sign(self):
        from mcpauth import rsa
        a, kr, _ = mk(self.tmp)
        k = rsa.generate_key(1024)
        kr.add_rsa_public("ext-1", k["n"], k["e"])
        with self.assertRaises(ValueError):
            a.mint(kid="ext-1")
        h = {"alg": "RS256", "typ": "JWT", "kid": "ext-1"}
        now = int(a.clock())
        c = {"iss": ISS, "sub": "ext", "aud": "aud-1", "iat": now, "exp": now + 60, "jti": "j1", "scope": "mcp"}
        signing = b64url_encode(json.dumps(h).encode()) + "." + b64url_encode(json.dumps(c).encode())
        tok = signing + "." + b64url_encode(rsa.sign(signing.encode(), k["n"], k["d"]))
        self.assertIsNone(reason(a, tok), "token signed by an external RSA key whose public half was registered")


class ClaimTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.a, self.kr, self.clk = mk(self.tmp, leeway=30)

    def test_valid_token_and_scope_expansion(self):
        c = self.a.verify(self.a.mint(scopes=["mcp", "memory:admin", "tools:write"]), ["memory:read", "tools:read"])
        self.assertEqual(c["_granted"], ["mcp", "memory:admin", "tools:write"])
        self.assertTrue({"memory:read", "memory:write", "tools:read"} <= set(c["_scopes"]))
        self.assertEqual(expand_scopes({"tools:read"}), {"tools:read"})
        self.assertEqual(parse_scopes(["a", "b"]), {"a", "b"})
        self.assertEqual(parse_scopes(5), set())

    def test_missing_scope_is_insufficient_scope_403(self):
        with self.assertRaises(AuthError) as cx:
            self.a.verify(self.a.mint(scopes=["mcp"]), ["memory:write"])
        self.assertEqual((cx.exception.error, cx.exception.status), ("insufficient_scope", 403))

    def test_leeway_boundaries(self):
        t = self.a.mint(ttl=60)
        self.clk.t += 60 + 29
        self.assertIsNone(reason(self.a, t))
        self.clk.t += 2
        self.assertEqual(reason(self.a, t), "expired")
        fut = self.a.mint(not_before_offset=25)
        self.assertIsNone(reason(self.a, fut))
        self.assertEqual(reason(self.a, self.a.mint(not_before_offset=45)), "nbf_future")
        self.assertEqual(reason(self.a, self.a.mint(issued_at_offset=45)), "iat_future")

    def test_zero_leeway_is_strict(self):
        a, _, clk = mk(self.tmp + "x", leeway=0)
        t = a.mint(ttl=10)
        clk.t += 10
        self.assertEqual(reason(a, t), "expired")

    def test_rejections(self):
        a = self.a
        tok = a.mint()
        h, c, s = tok.split(".")
        claims = json.loads(b64url_decode(c))
        cases = {
            "wrong_issuer": a.mint(issuer="http://evil"), "wrong_audience": a.mint(audience="other"),
            "missing_kid": retoken(tok, header={"alg": "HS256", "typ": "JWT"}),
            "alg_not_allowed": retoken(tok, header={"alg": "none", "kid": json.loads(b64url_decode(h))["kid"]}),
            "alg_confusion": retoken(tok, header={"alg": "RS256", "kid": json.loads(b64url_decode(h))["kid"]}),
            "unknown_kid": retoken(tok, header={"alg": "HS256", "kid": "k-nope"}),
            "bad_kid": retoken(tok, header={"alg": "HS256", "kid": "a b"}),
            "bad_signature": tok[:-3] + ("AAA" if not tok.endswith("AAA") else "BBB"),
            "not_jws": "a.b", "missing_or_too_long": "x" * 9000, "bad_alphabet": "!!.!!.!!", "bad_encoding": "AAAA.AAAA.AAAA",
        }
        for want, t in cases.items():
            self.assertEqual(reason(a, t), want, want)
        for missing, want in (("sub", "missing_sub"), ("jti", "missing_jti"), ("exp", "missing_exp"), ("iat", "missing_iat")):
            c2 = {k: v for k, v in claims.items() if k != missing}
            # re-sign through the keyring so only the claim is wrong
            kid = json.loads(b64url_decode(h))["kid"]
            signing = (h + "." + b64url_encode(json.dumps(c2).encode())).encode()
            t = signing.decode() + "." + b64url_encode(self.kr.sign(signing, self.kr.get(kid)))
            self.assertEqual(reason(a, t), want, missing)

    def test_kidless_hs256_only_when_configured(self):
        import hashlib
        import hmac
        tok = self.a.mint()
        key = self.kr.active()
        h = {"alg": "HS256", "typ": "JWT"}
        claims = json.loads(b64url_decode(tok.split(".")[1]))
        signing = (b64url_encode(json.dumps(h).encode()) + "." + b64url_encode(json.dumps(claims).encode())).encode()
        kidless = signing.decode() + "." + b64url_encode(hmac.new(bytes.fromhex(key["secret"]), signing, hashlib.sha256).digest())
        self.assertEqual(reason(self.a, kidless), "missing_kid")
        lenient = Authenticator(self.kr, ISS, "aud-1", clock=self.clk, allow_kidless=True)
        self.assertIsNone(reason(lenient, kidless))
        bad = kidless[:-3] + ("AAA" if not kidless.endswith("AAA") else "BBB")
        self.assertEqual(reason(lenient, bad), "bad_signature")

    def test_b64url_is_canonical(self):
        for bad in ("a", "ab=", "a b", "AB\n"):
            with self.assertRaises(ValueError):
                b64url_decode(bad)
        with self.assertRaises(ValueError):
            b64url_decode("QR")  # non-canonical trailing bits
        self.assertEqual(b64url_decode(b64url_encode(b"\xff\xfe")), b"\xff\xfe")


class RevocationAndAudit(TempDirTestCase):
    def test_revocation_oracle_and_audit_chain(self):
        os.makedirs(self.tmp, exist_ok=True)
        clk = Clk()
        store = AuthStore(os.path.join(self.tmp, "auth.sqlite3"), clock=clk)
        audit = TokenAudit(os.path.join(self.tmp, "ta.log"), fsync=False)
        kr = Keyring(None, env_secret="s" * 24)
        a = Authenticator(kr, ISS, "aud-1", clock=clk, revocations=store, audit=audit)
        tok = a.mint(subject="u1", client_id="c1")
        claims = a.verify(tok, ["mcp"], source="test")
        self.assertTrue(a.still_valid(claims))
        store.revoke_jti(claims["jti"], claims["exp"], "test")
        self.assertEqual(reason(a, tok), "revoked:jti:test")
        self.assertFalse(a.still_valid(claims))
        self.assertEqual(reason(a, "bad.token.here"), "bad_encoding")
        res = audit.verify()
        self.assertTrue(res["ok"])
        with open(os.path.join(self.tmp, "ta.log")) as fh:
            events = [json.loads(json.loads(l)["payload"])["event"] for l in fh]
        self.assertEqual(events, ["issue", "validate", "reject", "reject"])
        with open(os.path.join(self.tmp, "ta.log")) as fh:
            text = fh.read()
        self.assertNotIn(tok, text)
        self.assertNotIn(tok.split(".")[2], text)
        # tamper
        path = os.path.join(self.tmp, "ta.log")
        with open(path) as fh:
            lines = fh.read().splitlines()
        rec = json.loads(lines[2])
        rec["payload"] = rec["payload"].replace("reject", "accept")
        lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        res = verify_file(path)
        self.assertFalse(res["ok"])
        self.assertEqual(res["line"], 3)


if __name__ == "__main__":
    unittest.main()
