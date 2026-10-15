"""Command line interface:  python3 -m mcpauth <command> [options]

    serve              run the MCP server (stdio default, or --transport http)
    mint-token         print a signed JWT (HS256/RS256 per active key) - demos/tests
    verify-token       validate a token (signature, claims, revocation) and print its claims
    token-issue        issue an access token (+ refresh token with --offline) through the token service
    token-refresh      rotate a refresh token
    token-revoke       revoke an access token or a whole refresh family
    token-introspect   RFC 7662-style introspection
    keys               list | rotate | retire | revoke | pubkey
    client-secret      print the derived secret of a mock-issuer client
    audit-verify       verify the protocol audit chain      token-audit-verify   verify the JWT audit chain
    audit-tail         print last protocol audit entries     conformance          run the black-box suite
"""

import argparse
import json
import os
import signal
import sys
import threading

from . import __version__, rsa
from .audit import verify_file
from .auth import (ALL_SCOPES, DEFAULT_AUDIENCE, DEFAULT_ISSUER, Authenticator, AuthError, Keyring, b64url_decode)
from .llm import LlmClient
from .server import McpServer
from .tokens import AuthStore, Lockout, OidcIssuer, RateLimiter, TokenAudit, TokenService


def _add_common(p):
    p.add_argument("--data-dir", default=os.environ.get("MCP_FORGE_HOME", ".mcpauth"),
                   help="directory for memory.sqlite3, audit.log, token_audit.log, keys.json, auth.sqlite3 (default: $MCP_FORGE_HOME or ./.mcpauth)")
    p.add_argument("--issuer", default=os.environ.get("MCP_FORGE_ISSUER"),
                   help="expected/used token issuer (default: %s for stdio, the bound address for http)" % DEFAULT_ISSUER)
    p.add_argument("--audience", default=os.environ.get("MCP_FORGE_AUDIENCE", DEFAULT_AUDIENCE))
    p.add_argument("--leeway", type=int, default=int(os.environ.get("MCP_FORGE_LEEWAY", "30")), help="clock-skew leeway in seconds (default 30)")
    p.add_argument("--allow-kidless", action="store_true", default=os.environ.get("MCP_FORGE_ALLOW_KIDLESS") == "1",
                   help="ALSO accept HS256 tokens without a kid header (e.g. from mcp-base) if they verify under an HS256 key")


def build_parser():
    ap = argparse.ArgumentParser(prog="mcpauth", description="Stdlib-only MCP server with hardened simplified OIDC (not certified).")
    ap.add_argument("--version", action="version", version="mcp-auth-hardened " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the server")
    _add_common(s)
    s.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--no-auth", action="store_true", help="EXPLICITLY disable authentication (demo/dev only)")
    s.add_argument("--allow-origin", action="append", default=[])
    s.add_argument("--rate-limit", default=os.environ.get("MCP_FORGE_RATE", "200:400"), help="RATE:BURST requests/second per subject (default 200:400; 0 disables)")
    s.add_argument("--lockout-threshold", type=int, default=20, help="failed bearer tokens per address before lockout (HTTP)")
    s.add_argument("--lockout-duration", type=int, default=30)
    s.add_argument("--client-lockout-threshold", type=int, default=5, help="failed client authentications before a client is locked out")
    s.add_argument("--access-ttl", type=int, default=900)
    s.add_argument("--refresh-ttl", type=int, default=7 * 86400)

    m = sub.add_parser("mint-token", help="print a signed JWT")
    _add_common(m)
    m.add_argument("--sub", default="demo-user")
    m.add_argument("--scope", default=" ".join(ALL_SCOPES), help="space separated; default: all scopes")
    m.add_argument("--ttl", type=int, default=3600)
    m.add_argument("--aud", default=None)
    m.add_argument("--kid", default=None, help="sign with this key instead of the active one")
    m.add_argument("--show-claims", action="store_true")

    v = sub.add_parser("verify-token")
    _add_common(v)
    v.add_argument("token")
    v.add_argument("--require-scope", action="append", default=[])

    ti = sub.add_parser("token-issue", help="issue tokens via the token service (client_credentials semantics, no secret needed locally)")
    _add_common(ti)
    ti.add_argument("--client", default="demo-client")
    ti.add_argument("--scope", default=None)
    ti.add_argument("--offline", action="store_true", help="also issue a refresh token (new family)")

    tr = sub.add_parser("token-refresh")
    _add_common(tr)
    tr.add_argument("refresh_token")
    tr.add_argument("--client", default="demo-client")
    tr.add_argument("--scope", default=None)

    rv = sub.add_parser("token-revoke")
    _add_common(rv)
    rv.add_argument("token")

    it = sub.add_parser("token-introspect")
    _add_common(it)
    it.add_argument("token")

    k = sub.add_parser("keys", help="manage signing keys")
    _add_common(k)
    k.add_argument("action", choices=("list", "rotate", "retire", "revoke", "pubkey"))
    k.add_argument("kid", nargs="?")
    k.add_argument("--alg", choices=("HS256", "RS256"), default="HS256")
    k.add_argument("--bits", type=int, default=2048)

    c = sub.add_parser("client-secret")
    _add_common(c)
    c.add_argument("client_id")

    a = sub.add_parser("audit-verify")
    _add_common(a)
    a.add_argument("--expect-head")
    a.add_argument("--expect-count", type=int)
    a.add_argument("--file")

    ta = sub.add_parser("token-audit-verify")
    _add_common(ta)
    ta.add_argument("--expect-head")
    ta.add_argument("--expect-count", type=int)

    t = sub.add_parser("audit-tail")
    _add_common(t)
    t.add_argument("-n", type=int, default=10)

    cf = sub.add_parser("conformance")
    cf.add_argument("--transport", choices=("stdio", "http", "both"), default="both")
    cf.add_argument("--json", dest="json_path")
    cf.add_argument("--quiet", action="store_true")
    return ap


def _parse_rate(spec):
    if str(spec) == "0":
        return None
    rate, _, burst = str(spec).partition(":")
    return RateLimiter(float(rate), float(burst or float(rate) * 2))


def build_auth(args, default_issuer, fsync=True):
    """Keyring + audit + store + authenticator + token service from CLI args."""
    keyring = Keyring(os.path.join(args.data_dir, "keys.json"), env_secret=os.environ.get("MCP_FORGE_SECRET"))
    tokaudit = TokenAudit(os.path.join(args.data_dir, "token_audit.log"), fsync=fsync)
    store = AuthStore(os.path.join(args.data_dir, "auth.sqlite3"))
    auth = Authenticator(keyring, args.issuer or default_issuer, args.audience, leeway=args.leeway, allow_kidless=args.allow_kidless,
                         revocations=store, audit=tokaudit)
    service = TokenService(auth, store, access_ttl=getattr(args, "access_ttl", 900), refresh_ttl=getattr(args, "refresh_ttl", 7 * 86400), audit=tokaudit)
    return auth, service, tokaudit


def cmd_serve(args):
    llm = LlmClient.from_env()
    if args.no_auth:
        auth = service = tokaudit = None
    else:
        auth, service, tokaudit = build_auth(args, None if args.transport == "http" else DEFAULT_ISSUER)
    server = McpServer(args.data_dir, auth, llm, service=service, token_audit=tokaudit, limiter=_parse_rate(args.rate_limit))
    note = "auth DISABLED (--no-auth)" if auth is None else "auth enabled"
    if args.transport == "stdio":
        from .transport_stdio import serve_stdio
        print(json.dumps({"event": "ready", "transport": "stdio", "auth": note, "llm": bool(llm), "data_dir": os.path.abspath(args.data_dir)}),
              file=sys.stderr, flush=True)
        if auth is not None and not os.environ.get("MCP_TOKEN"):
            print("mcp-auth-hardened: warning: MCP_TOKEN not set; initialize will be rejected (use --no-auth for dev)", file=sys.stderr, flush=True)
        return serve_stdio(server, os.environ.get("MCP_TOKEN"))
    from .transport_http import HttpTransport
    http = HttpTransport(server, args.host, args.port, allowed_origins=args.allow_origin,
                         lockout=Lockout(args.lockout_threshold, 60, args.lockout_duration),
                         client_lockout=Lockout(args.client_lockout_threshold, 60, args.lockout_duration))
    print(json.dumps({"event": "ready", "transport": "http", "url": http.base_url + "/mcp", "port": http.port,
                      "issuer": auth.issuer if auth else None, "audience": auth.audience if auth else None, "auth": note,
                      "llm": bool(llm), "data_dir": os.path.abspath(args.data_dir)}), file=sys.stderr, flush=True)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=http.shutdown, daemon=True).start())
    try:
        http.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_mint(args):
    auth, _, _ = build_auth(args, DEFAULT_ISSUER)
    token = auth.mint(subject=args.sub, scopes=args.scope.split(), ttl=args.ttl, audience=args.aud, kid=args.kid)
    print(token)
    if args.show_claims:
        print(json.dumps(json.loads(b64url_decode(token.split(".")[1])), indent=2, sort_keys=True), file=sys.stderr)
    return 0


def cmd_verify_token(args):
    auth, _, _ = build_auth(args, DEFAULT_ISSUER)
    try:
        claims = auth.verify(args.token, args.require_scope, source="cli")
    except AuthError as exc:
        print(json.dumps({"valid": False, "error": exc.error, "description": exc.description}))
        return 1
    print(json.dumps({"valid": True, "claims": claims}, indent=2, sort_keys=True))
    return 0


def cmd_token_issue(args):
    auth, service, _ = build_auth(args, DEFAULT_ISSUER)
    issuer = OidcIssuer(auth, service, Lockout())
    allowed = issuer.clients.get(args.client)
    if allowed is None:
        raise ValueError("unknown client")
    scopes = args.scope.split() if args.scope else [s for s in allowed if s != "offline_access"]
    if any(s not in allowed for s in scopes):
        raise ValueError("scope not permitted for client")
    print(json.dumps(service.issue(args.client, args.client, scopes, offline=args.offline), indent=2))
    return 0


def cmd_token_refresh(args):
    from .tokens import GrantError
    auth, service, _ = build_auth(args, DEFAULT_ISSUER)
    try:
        print(json.dumps(service.refresh(args.refresh_token, args.client, args.scope.split() if args.scope else None), indent=2))
    except GrantError as exc:
        print(json.dumps({"error": exc.error, "error_description": exc.description}))
        return 1
    return 0


def cmd_token_revoke(args):
    _, service, _ = build_auth(args, DEFAULT_ISSUER)
    print(json.dumps({"result": service.revoke_token(args.token, "cli", True, "cli")}))
    return 0


def cmd_token_introspect(args):
    _, service, _ = build_auth(args, DEFAULT_ISSUER)
    print(json.dumps(service.introspect(args.token), indent=2))
    return 0


def cmd_keys(args):
    keyring = Keyring(os.path.join(args.data_dir, "keys.json"), env_secret=os.environ.get("MCP_FORGE_SECRET"))
    if args.action == "list":
        print(json.dumps(keyring.public_view(), indent=2))
    elif args.action == "rotate":
        k = keyring.rotate(args.alg, args.bits)
        print(json.dumps({"rotated_to": k["kid"], "alg": k["alg"]}))
    elif args.action in ("retire", "revoke"):
        if not args.kid:
            raise ValueError("kid required")
        k = keyring.set_status(args.kid, "retired" if args.action == "retire" else "revoked")
        print(json.dumps({"kid": k["kid"], "status": k["status"]}))
    else:
        k = keyring.get(args.kid or "")
        if not k or k["alg"] != "RS256":
            raise ValueError("pubkey needs the kid of an RS256 key")
        print(rsa.public_key_pem(int(k["rsa"]["n"], 16), int(k["rsa"]["e"], 16)), end="")
    return 0


def cmd_client_secret(args):
    auth, service, _ = build_auth(args, DEFAULT_ISSUER)
    from .auth import DEFAULT_CLIENTS
    if args.client_id not in DEFAULT_CLIENTS:
        raise ValueError("unknown client")
    print(OidcIssuer(auth, service, Lockout()).client_secret(args.client_id))
    return 0


def _verify_cmd(path, args, label="AUDIT"):
    res = verify_file(path, args.expect_head, args.expect_count)
    print(json.dumps(res, indent=2, sort_keys=True))
    print("%s CHAIN OK: %d entries, head %s" % (label, res["count"], res["head"]) if res["ok"]
          else "%s CHAIN BROKEN at line %s: %s" % (label, res["line"], res["error"]), file=sys.stderr)
    return 0 if res["ok"] else 1


def cmd_audit_verify(args):
    return _verify_cmd(args.file or os.path.join(args.data_dir, "audit.log"), args)


def cmd_token_audit_verify(args):
    return _verify_cmd(os.path.join(args.data_dir, "token_audit.log"), args, "TOKEN AUDIT")


def cmd_audit_tail(args):
    from .audit import AuditLog
    for e in AuditLog(os.path.join(args.data_dir, "audit.log")).tail(args.n):
        print(json.dumps(e, sort_keys=True))
    return 0


def cmd_conformance(args):
    from .conformance import run_cli
    return run_cli(args)


def main(argv=None):
    args = build_parser().parse_args(argv)
    handler = {"serve": cmd_serve, "mint-token": cmd_mint, "verify-token": cmd_verify_token, "token-issue": cmd_token_issue,
               "token-refresh": cmd_token_refresh, "token-revoke": cmd_token_revoke, "token-introspect": cmd_token_introspect,
               "keys": cmd_keys, "client-secret": cmd_client_secret, "audit-verify": cmd_audit_verify,
               "token-audit-verify": cmd_token_audit_verify, "audit-tail": cmd_audit_tail, "conformance": cmd_conformance}[args.cmd]
    try:
        return handler(args)
    except (ValueError, OSError) as exc:
        print("mcp-auth-hardened: error: %s" % exc, file=sys.stderr)
        return 2
