#!/usr/bin/env python3
"""mcp-auth-hardened end-to-end demo: scopes, refresh rotation + reuse detection, introspection, key rotation (HS256/RS256), JWKS, leeway, lockout, token audit chain.

Everything runs against real subprocesses of `python3 -m mcpauth` (no mocks). Exit code 0 only if every step behaves as expected.
Uses only the standard library; no network beyond 127.0.0.1.
"""

import base64
import hashlib
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
PKG = "mcpauth"
STEPS = []


def say(msg=""):
    print(msg, flush=True)


def banner(title):
    say("\n" + "=" * 78 + "\n== " + title + "\n" + "=" * 78)


def must(cond, what):
    STEPS.append((what, bool(cond)))
    say("   [%s] %s" % ("ok" if cond else "FAIL", what))
    if not cond:
        raise SystemExit("demo failed at: " + what)


def env(**extra):
    e = dict(os.environ, PYTHONPATH=ROOT, PYTHONUNBUFFERED="1")
    e.pop("MCP_TOKEN", None)
    e.update(extra)
    return e


def cli(*args, **envx):
    say("$ python3 -m %s %s" % (PKG, " ".join(args)))
    return subprocess.run([PY, "-m", PKG, *args], capture_output=True, text=True, cwd=ROOT, env=env(**envx))


def short(obj, n=240):
    t = json.dumps(obj) if not isinstance(obj, str) else obj
    return t[:n] + (" ..." if len(t) > n else "")


class Stdio:
    """One `serve` subprocess speaking newline-delimited JSON-RPC; server notifications are collected in ``self.notes``."""

    def __init__(self, data_dir, issuer, token, extra=(), **envx):
        e = env(**envx)
        if token:
            e["MCP_TOKEN"] = token
        cmd = [PY, "-m", PKG, "serve", "--data-dir", data_dir, *(["--issuer", issuer] if issuer else []), *extra]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=ROOT, env=e)
        self.n = 0
        self.notes = []
        say("   (server process started, pid %d, transport=stdio)" % self.proc.pid)

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj).encode() + b"\n")
        self.proc.stdin.flush()

    def read(self):
        line = self.proc.stdout.readline()
        return json.loads(line) if line else None

    def call(self, method, params=None, quiet=False):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            msg["params"] = params
        if not quiet:
            say("-> " + short(msg, 200))
        self.send(msg)
        while True:
            out = self.read()
            if out is None:
                return None
            if "method" in out and "id" not in out:
                self.notes.append(out)
                say("<= (notification) " + short(out))
                continue
            if not quiet:
                say("<- " + short(out, 260))
            return out

    def next_note(self):
        """Read the next server notification line (blocks); used right after a response that must be followed by one."""
        out = self.read()
        say("<= (notification) " + short(out))
        return out

    def notify(self, method):
        say("-> " + json.dumps({"jsonrpc": "2.0", "method": method}) + "   (notification, no reply expected)")
        self.send({"jsonrpc": "2.0", "method": method})

    def tool(self, name, args, quiet=False):
        out = self.call("tools/call", {"name": name, "arguments": args}, quiet)
        return out

    def stop(self, kill=False):
        if kill:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait(10)
            self.proc.stdin.close()
            self.proc.stdout.close()
            say("   (server process pid %d killed with SIGKILL)" % self.proc.pid)
            return -9
        self.proc.stdin.close()
        code = self.proc.wait(10)
        self.proc.stdout.close()
        say("   (server process pid %d exited with code %s)" % (self.proc.pid, code))
        return code

    def handshake(self, version="2025-03-26"):
        res = self.call("initialize", {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "demo-client", "version": "1.0"}})
        if "result" in res:
            self.notify("notifications/initialized")
        return res


def text(res):
    return json.loads(res["result"]["content"][0]["text"])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Http:
    def __init__(self, port, token=None):
        self.port, self.token, self.sid = port, token, None
        self.c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)

    def req(self, method, path, body=None, headers=None, session=True):
        h = {}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        if self.sid and session:
            h["Mcp-Session-Id"] = self.sid
        h.update(headers or {})
        if body is not None and not isinstance(body, (str, bytes)):
            body = json.dumps(body)
        self.c.request(method, path, body=body, headers=h)
        r = self.c.getresponse()
        data = r.read().decode()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def rpc(self, method, params=None, mid=1, quiet=False):
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        if not quiet:
            say("POST /mcp -> " + short(msg, 200))
        st, hdr, data = self.req("POST", "/mcp", msg, {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
        if "mcp-session-id" in hdr and not self.sid:
            self.sid = hdr["mcp-session-id"]
        out = json.loads(data) if data else None
        if not quiet:
            say("<- HTTP %d %s" % (st, short(out, 240)))
        return st, out

    def notify(self, method):
        st, _, _ = self.req("POST", "/mcp", {"jsonrpc": "2.0", "method": method}, {"Content-Type": "application/json"})
        return st


def start_http(data, issuer, port, extra=(), **envx):
    p = subprocess.Popen([PY, "-m", PKG, "serve", "--transport", "http", "--port", str(port), *(["--issuer", issuer] if issuer else []),
                          "--data-dir", data, *extra], stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, cwd=ROOT, env=env(**envx), text=True)
    say("   " + p.stderr.readline().strip())
    return p


def stop_http(p):
    p.terminate()
    p.wait(5)
    p.stderr.close()


def init_params(version="2025-03-26"):
    return {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "demo", "version": "1"}}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def form(**kw):
    return urllib.parse.urlencode(kw)


def basic(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()}


def main():
    work = tempfile.mkdtemp(prefix="mcpauth-demo-")
    data = os.path.join(work, "data")
    port = free_port()
    issuer = "http://127.0.0.1:%d" % port
    say("mcp-auth-hardened demo  |  python %s  |  workdir %s" % (sys.version.split()[0], work))
    srv = None
    try:
        banner("1. Start the HTTP server; discovery document and JWKS (which must leak nothing secret)")
        r = cli("client-secret", "demo-client", "--data-dir", data)
        demo_secret = r.stdout.strip()
        admin_secret = cli("client-secret", "admin-client", "--data-dir", data).stdout.strip()
        srv = start_http(data, issuer, port, extra=("--client-lockout-threshold", "4"))
        h = Http(port)
        st, _, body = h.req("GET", "/.well-known/openid-configuration", session=False)
        doc = json.loads(body)
        must(st == 200 and doc["jwks_uri"].endswith("/.well-known/jwks.json") and "refresh_token" in doc["grant_types_supported"],
             "discovery doc advertises jwks_uri, introspection, revocation, refresh_token grant")
        st, _, jwks_body = h.req("GET", "/.well-known/jwks.json", session=False)
        keys_file = json.load(open(os.path.join(data, "keys.json")))
        secrets_ = [k["secret"] for k in keys_file["keys"] if "secret" in k]
        must(st == 200 and secrets_ and all(s not in jwks_body for s in secrets_), "JWKS does not contain the HS256 signing secret (%d secret(s) checked)" % len(secrets_))
        must('"d"' not in jwks_body and '"k"' not in jwks_body, "JWKS carries no private members (d / k)")
        must((os.stat(os.path.join(data, "keys.json")).st_mode & 0o777) == 0o600, "keys.json is mode 0600")

        banner("2. client_credentials grant with offline_access; use the access token over MCP")
        st, _, body = h.req("POST", "/oauth/token", form(grant_type="client_credentials", scope="mcp tools:read tools:write memory:read memory:write offline_access"),
                            dict(basic("demo-client", demo_secret), **{"Content-Type": "application/x-www-form-urlencoded"}), session=False)
        t1 = json.loads(body)
        must(st == 200 and t1["token_type"] == "Bearer" and t1.get("refresh_token"), "token endpoint issued an access token and a refresh token")
        hdr = json.loads(b64d(t1["access_token"].split(".")[0]))
        must(hdr["alg"] == "HS256" and hdr["kid"].startswith("k-"), "access token header carries alg=%s kid=%s" % (hdr["alg"], hdr["kid"]))
        m = Http(port, t1["access_token"])
        st, out = m.rpc("initialize", init_params())
        m.notify("notifications/initialized")
        st, out = m.rpc("tools/call", {"name": "memory_store", "arguments": {"content": "stored through a hardened token"}}, 2)
        must(st == 200 and "result" in out and not out["result"]["isError"], "authenticated tools/call works")

        banner("3. Per-method scope enforcement")
        st, _, body = h.req("POST", "/oauth/token", form(grant_type="client_credentials", scope="mcp tools:read"),
                            dict(basic("demo-client", demo_secret), **{"Content-Type": "application/x-www-form-urlencoded"}), session=False)
        ro = Http(port, json.loads(body)["access_token"])
        ro.rpc("initialize", init_params())
        ro.notify("notifications/initialized")
        st, out = ro.rpc("tools/list", None, 2)
        must("result" in out, "tools:read can list tools")
        st, out = ro.rpc("tools/call", {"name": "memory_recall", "arguments": {"query": "x"}}, 3)
        must(out["error"]["code"] == -32003, "tools:read cannot CALL tools -> -32003 (HTTP %d)" % st)
        must(out["error"].get("data"), "error data names what was missing: " + short(out["error"].get("data"), 120))

        banner("4. Refresh-token rotation and REUSE DETECTION (stolen refresh token replayed)")
        def refresh(rt, who=("demo-client", demo_secret)):
            st, _, body = h.req("POST", "/oauth/token", form(grant_type="refresh_token", refresh_token=rt),
                                dict(basic(*who), **{"Content-Type": "application/x-www-form-urlencoded"}), session=False)
            return st, json.loads(body)
        st, t2 = refresh(t1["refresh_token"])
        must(st == 200 and t2["refresh_token"] != t1["refresh_token"], "refresh rotates: a NEW refresh token is returned")
        st, bad = refresh(t1["refresh_token"])
        must(st == 400 and bad["error"] == "invalid_grant", "replaying the OLD refresh token fails: " + short(bad, 100))
        st, bad2 = refresh(t2["refresh_token"])
        must(st == 400 and bad2["error"] == "invalid_grant", "the legitimate NEW refresh token is now dead too: the whole family was revoked")
        c2 = Http(port, t2["access_token"])
        st, out = c2.rpc("initialize", init_params(), quiet=True)
        must(st == 401, "access token of the revoked family is rejected (HTTP 401)")
        r = cli("token-audit-verify", "--data-dir", data)
        must("reuse_detected" in open(os.path.join(data, "token_audit.log")).read() and r.returncode == 0, "token audit log records reuse_detected and its chain verifies")

        banner("5. Introspection (privileged clients only) and revocation by jti")
        st, _, body = h.req("POST", "/oauth/token", form(grant_type="client_credentials", scope="mcp tools:read"),
                            dict(basic("demo-client", demo_secret), **{"Content-Type": "application/x-www-form-urlencoded"}), session=False)
        t3 = json.loads(body)
        ct = {"Content-Type": "application/x-www-form-urlencoded"}
        st, _, body = h.req("POST", "/oauth/introspect", form(token=t3["access_token"]), dict(basic("admin-client", admin_secret), **ct), session=False)
        must(st == 200 and json.loads(body)["active"] is True and json.loads(body)["client_id"] == "demo-client", "admin-client introspection: active=true")
        st, _, body = h.req("POST", "/oauth/introspect", form(token=t3["access_token"]), dict(basic("demo-client", demo_secret), **ct), session=False)
        must(st in (401, 403), "an ordinary client may not introspect (HTTP %d)" % st)
        st, _, body = h.req("POST", "/oauth/revoke", form(token=t3["access_token"]), dict(basic("demo-client", demo_secret), **ct), session=False)
        must(st == 200, "revocation endpoint answers 200")
        st, _, body = h.req("POST", "/oauth/introspect", form(token=t3["access_token"]), dict(basic("admin-client", admin_secret), **ct), session=False)
        must(json.loads(body) == {"active": False}, "after revocation: introspection says active=false and nothing else (no oracle)")
        st, _, body = h.req("POST", "/oauth/revoke", form(token="garbage"), dict(basic("demo-client", demo_secret), **ct), session=False)
        must(st == 200, "revoking garbage also answers 200 (RFC 7009: no information leak)")

        banner("6. Key rotation: kid, grace period, RS256, verification by OpenSSL, revocation of a key")
        old_tok = cli("mint-token", "--data-dir", data, "--issuer", issuer, "--sub", "before-rotation").stdout.strip()
        old_kid = json.loads(b64d(old_tok.split(".")[0]))["kid"]
        r = cli("keys", "rotate", "--alg", "RS256", "--bits", "1024", "--data-dir", data)
        new_kid = json.loads(r.stdout)["rotated_to"]
        new_tok = cli("mint-token", "--data-dir", data, "--issuer", issuer, "--sub", "after-rotation").stdout.strip()
        must(json.loads(b64d(new_tok.split(".")[0])) == {"alg": "RS256", "kid": new_kid, "typ": "JWT"}, "new tokens are RS256 under the new kid %s" % new_kid)
        for tok, label in ((old_tok, "old HS256 token (retired key, grace period)"), (new_tok, "new RS256 token")):
            x = Http(port, tok)
            st, out = x.rpc("initialize", init_params(), quiet=True)
            must(st == 200, label + " is accepted by the running server")
        pem = cli("keys", "pubkey", new_kid, "--data-dir", data).stdout
        open(os.path.join(work, "pub.pem"), "w").write(pem)
        head, payload, sig = new_tok.split(".")
        open(os.path.join(work, "msg"), "wb").write((head + "." + payload).encode())
        open(os.path.join(work, "sig"), "wb").write(b64d(sig))
        v = subprocess.run(["openssl", "dgst", "-sha256", "-verify", os.path.join(work, "pub.pem"), "-signature", os.path.join(work, "sig"), os.path.join(work, "msg")], capture_output=True, text=True)
        must(v.returncode == 0 and "Verified OK" in v.stdout, "OpenSSL independently verifies the hand-written RS256 signature: " + v.stdout.strip())
        forged = head + "." + payload + "." + b64u(b"\x00" + b64d(sig)[1:])
        open(os.path.join(work, "sig"), "wb").write(b64d(forged.split(".")[2]))
        v = subprocess.run(["openssl", "dgst", "-sha256", "-verify", os.path.join(work, "pub.pem"), "-signature", os.path.join(work, "sig"), os.path.join(work, "msg")], capture_output=True, text=True)
        must(v.returncode != 0, "OpenSSL rejects a signature with a flipped byte (sanity check of the check)")
        st, _, jw = h.req("GET", "/.well-known/jwks.json", session=False)
        kinfo = [k for k in json.loads(jw)["keys"] if k["kid"] == new_kid][0]
        must(kinfo["kty"] == "RSA" and "d" not in kinfo and "p" not in kinfo, "JWKS now publishes the RS256 public key (n,e) only")
        x = Http(port, forged)
        st, out = x.rpc("initialize", init_params(), quiet=True)
        must(st == 401, "token with a corrupted RS256 signature -> 401")
        cli("keys", "revoke", old_kid, "--data-dir", data)
        x = Http(port, old_tok)
        st, out = x.rpc("initialize", init_params(), quiet=True)
        must(st == 401, "after `keys revoke %s` the old-key token is rejected immediately" % old_kid)

        banner("7. Algorithm confusion, alg=none, kid-less tokens, clock-skew leeway")
        claims = json.loads(b64d(new_tok.split(".")[1]))
        none_tok = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode()) + "." + b64u(json.dumps(claims).encode()) + "."
        hs_header = b64u(json.dumps({"alg": "HS256", "kid": new_kid, "typ": "JWT"}).encode())
        confusion = hs_header + "." + payload + "." + b64u(b"x" * 32)
        for tok, label in ((none_tok, "alg=none"), (confusion, "HS256 header on the RS256 kid (alg confusion)")):
            st, out = Http(port, tok).rpc("initialize", init_params(), quiet=True)
            must(st == 401, label + " -> 401")
        kidless = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + "." + payload + "." + b64u(b"y" * 32)
        st, out = Http(port, kidless).rpc("initialize", init_params(), quiet=True)
        must(st == 401, "token without kid -> 401 (kid is mandatory unless --allow-kidless)")
        for ttl, expect_ok, label in ((-10, True, "expired 10 s ago: inside the 30 s leeway -> accepted"), (-300, False, "expired 5 min ago: outside the leeway -> rejected")):
            t = cli("mint-token", "--data-dir", data, "--issuer", issuer, "--ttl=%d" % ttl).stdout.strip()
            st, out = Http(port, t).rpc("initialize", init_params(), quiet=True)
            must((st == 200) == expect_ok, label)

        banner("8. Brute-force protection: client lockout (429 + Retry-After), other clients unaffected")
        codes = []
        for i in range(6):
            st, hd, body = h.req("POST", "/oauth/token", form(grant_type="client_credentials"), dict(basic("demo-client", "wrong-%d" % i), **ct), session=False)
            codes.append(st)
        must(codes[:3] == [401, 401, 401] and 429 in codes, "wrong secrets: %s (lockout after the threshold)" % codes)
        st, hd, body = h.req("POST", "/oauth/token", form(grant_type="client_credentials", scope="mcp"), dict(basic("demo-client", demo_secret), **ct), session=False)
        must(st == 429 and "retry-after" in hd, "even the right secret is refused while locked out (Retry-After: %s)" % hd.get("retry-after"))
        st, hd, body = h.req("POST", "/oauth/token", form(grant_type="client_credentials", scope="mcp"), dict(basic("admin-client", admin_secret), **ct), session=False)
        must(st == 200, "another client (admin-client) is unaffected")

        banner("9. Hash-chained token audit log: verify, tamper, detect; no raw tokens inside")
        r = cli("token-audit-verify", "--data-dir", data)
        must(r.returncode == 0, "token_audit.log chain verifies: " + r.stdout.strip()[:100])
        log = open(os.path.join(data, "token_audit.log")).read()
        must("eyJ" not in log and "rt_" not in log, "the log contains no JWT and no refresh token")
        shutil.copytree(data, os.path.join(work, "tampered"))
        tp = os.path.join(work, "tampered", "token_audit.log")
        lines = open(tp).read().splitlines()
        rec = json.loads(lines[3])
        payload_ = json.loads(rec["payload"])
        payload_["sub"] = "someone-else"
        rec["payload"] = json.dumps(payload_, sort_keys=True, separators=(",", ":"))
        lines[3] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        open(tp, "w").write("\n".join(lines) + "\n")
        r = cli("token-audit-verify", "--data-dir", os.path.join(work, "tampered"))
        must(r.returncode == 1, "after editing entry #4 the verifier exits 1: " + (r.stdout + r.stderr).strip()[:100])

        stop_http(srv)
        srv = None
        banner("10. stdio: same hardened validation, revocation noticed mid-session")
        tok = cli("mint-token", "--data-dir", data, "--issuer", issuer, "--sub", "stdio-user").stdout.strip()
        s = Stdio(data, issuer, tok)
        s.handshake()
        must("result" in s.call("tools/list"), "stdio session works with a valid token")
        cli("token-revoke", "--data-dir", data, "--issuer", issuer, tok)
        out = s.call("tools/list")
        must(out["error"]["code"] == -32001, "after revocation the SAME live stdio session is refused (-32001)")
        s.stop()
        r = cli("audit-verify", "--data-dir", data)
        must(r.returncode == 0, "request audit log chain verifies")
        banner("DEMO OK - %d/%d steps passed" % (sum(1 for _, ok in STEPS if ok), len(STEPS)))
        return 0
    finally:
        if srv:
            stop_http(srv)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
