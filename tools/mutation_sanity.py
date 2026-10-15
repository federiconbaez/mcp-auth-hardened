#!/usr/bin/env python3
"""Mutation sanity check: prove the test-suite is not vacuous.

For each deliberate bug below, copy the repo to a temp dir, inject the bug, run the unit tests with
``-f`` (fail fast) and require that they FAIL. A mutant that survives is reported and makes the script exit 1.

    python3 tools/mutation_sanity.py [--jobs N]
"""

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = ["tests.test_schema", "tests.test_jsonrpc", "tests.test_auth", "tests.test_rsa", "tests.test_tokens",
           "tests.test_protocol", "tests.test_persistence_audit", "tests.test_http_e2e"]

A, T, S, H = "mcpauth/auth.py", "mcpauth/tokens.py", "mcpauth/server.py", "mcpauth/transport_http.py"
MUTANTS = [
    ("M01 ignore token expiry", A, 'if check_time and now >= claims["exp"] + self.leeway:', "if False:", {}),
    ("M02 ignore audience", A, "if self.audience not in auds:", "if False:", {}),
    ("M03 ignore issuer", A, 'if claims.get("iss") != self.issuer:', "if False:", {}),
    ("M04 HS256 signature always accepted", A, "return hmac.compare_digest(hmac.new(bytes.fromhex(key[\"secret\"]), signing_input, hashlib.sha256).digest(), signature)",
     "return True", {}),
    ("M05 no alg/kid algorithm pinning", A, 'if key["alg"] != alg:', "if False:", {}),
    ("M06 kid-less tokens always accepted", A, 'if not (self.allow_kidless and alg == "HS256"):', "if False:", {}),
    ("M07 revoked signing keys still verify", A, 'if key["status"] == "revoked":', "if False:", {}),
    ("M08 retired keys never expire", A, 'self.clock() >= key.get("retired_until", 0)', "False", {}),
    ("M09 iat-in-future not checked", A, 'if check_time and claims["iat"] > now + self.leeway:', "if False:", {}),
    ("M10 revocation list ignored", A, "if check_revocation and self.revocations is not None:", "if False:", {}),
    ("M11 scope implication memory:admin removed", A, '"memory:admin": ("memory:write", "memory:read"), ', "", {}),
    ("M12 JWKS publishes nothing about RSA modulus correctly (n omitted)", A, '"n": rsa.int_to_b64u(n), ', "", {}),
    ("M13 RS256 verify skips padding comparison", "mcpauth/rsa.py", "return hmac.compare_digest(em, expected)", "return True", {}),
    ("M14 refresh reuse not detected", T, 'if row["status"] == "used":', "if False:", {}),
    ("M15 refresh client binding not enforced", T, 'if fam["client"] != client_id:', "if False:", {}),
    ("M16 client lockout never triggers", T, "if len(recent) >= self.threshold and key not in self.locked:", "if False:", {}),
    ("M17 client secret not checked (only client id)", T, 'if not (hmac.compare_digest(expected.encode("utf-8"), secret.encode("utf-8")) and known):', "if not known:", {}),
    ("M18 no per-method scope enforcement", S, "missing = [s for s in scopes if not self._has_scope(s)]", "missing = []", {}),
    ("M25 refresh scope escalation allowed", T, "if not want <= granted:", "if False:", {}),
    ("M19 allow requests before initialize", S, "if method not in PRE_INIT_METHODS and not was_initialized:", "if False:", {}),
    ("M20 audit: ignore prev-link", "mcpauth/audit.py", 'if entry["prev"] != prev:', "if False:", {}),
    ("M21 audit: ignore entry hash", "mcpauth/audit.py", 'if entry_hash(entry) != entry["hash"]:', "if False:", {}),
    ("M22 booleans accepted as ids", "mcpauth/jsonrpc.py", "isinstance(value, int) and not isinstance(value, bool)", "isinstance(value, int)", {}),
    ("M23 HTTP session not bound to subject", H, "if app.auth and sub != (session.claims or {}).get(\"sub\"):", "if False:", {}),
    ("M24 schema ignores additionalProperties:false", "mcpauth/schema.py", "if ap is False:", "if False:", {}),
]


def run_one(m):
    name, rel, old, new, extra_env = m
    tmp = tempfile.mkdtemp(prefix="mutant-")
    try:
        dst = os.path.join(tmp, "repo")
        shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".mcpauth", "evidence"))
        path = os.path.join(dst, rel)
        with open(path) as fh:
            src = fh.read()
        if src.count(old) != 1:
            return name, "BAD-MUTANT", "pattern occurs %d times in %s" % (src.count(old), rel)
        with open(path, "w") as fh:
            fh.write(src.replace(old, new))
        env = dict(os.environ, PYTHONPATH=dst, **extra_env)
        r = subprocess.run([sys.executable, "-m", "unittest", "-f", *MODULES], cwd=dst, env=env,
                           capture_output=True, text=True, timeout=600)
        killed = r.returncode != 0
        first = next((l for l in r.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))), "")
        return name, "KILLED" if killed else "SURVIVED", first[:110]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
        results = list(ex.map(run_one, MUTANTS))
    for name, status, info in results:
        print("%-52s %-9s %s" % (name, status, info))
    killed = sum(1 for _, s, _ in results if s == "KILLED")
    print("\nmutants killed: %d/%d" % (killed, len(results)))
    return 0 if killed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
