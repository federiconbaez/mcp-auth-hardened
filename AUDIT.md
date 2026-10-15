# AUDIT.md - how a third party verifies mcp-auth-hardened, step by step

Offline, with only `python3` (>= 3.10; built on 3.13.5) and optionally `git`, `sha256sum`, `curl` and **`openssl`** (used for the
independent RS256 cross-check).

**What this kit can and cannot show.** It shows that the server enforces the behaviours below *as the author specified them*,
that automated tests, a black-box suite and a bounded model check exercise them, that an external tool (OpenSSL) agrees with the
hand-written RS256, and that the tests are not vacuous (mutation check). It is **not** a security audit and **not** OAuth/OIDC
conformance: no OAuth test-suite, third-party client or cryptographic review was involved.

## Step 0 - integrity

```bash
sha256sum -c mcp-auth-hardened.tar.gz.sha256
tar xzf mcp-auth-hardened.tar.gz && cd mcp-auth-hardened
python3 tools/make_manifest.py --check        # == sha256sum -c MANIFEST.sha256
python3 tools/check_doc_refs.py               # every file/test/check named in the docs exists
```

## Step 1 - stdlib-only / originality

```bash
python3 tools/check_stdlib_only.py            # AST-only; PASS/FAIL; line counts; git history
```

See ORIGINALITY.md for what it does not prove.

## Step 2 - unit tests (153) and black-box conformance (140)

```bash
python3 -m unittest discover -v
python3 -m mcpauth conformance --json /tmp/conf.json
```

`HRD-001..HRD-014` are the auth-specific checks; `AUT-*` are inherited and still pass. The suite starts real subprocesses.

## Step 3 - verify the hand-written RS256 with OpenSSL yourself

```bash
export MCP_FORGE_HOME=$(mktemp -d)
K=$(python3 -m mcpauth keys rotate --alg RS256 --bits 1024 | python3 -c 'import sys,json;print(json.load(sys.stdin)["rotated_to"])')
TOK=$(python3 -m mcpauth mint-token)
python3 -m mcpauth keys pubkey $K > pub.pem
python3 - "$TOK" <<'PY'
import base64, sys
h, p, s = sys.argv[1].split(".")
d = lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
open("msg", "wb").write((h + "." + p).encode()); open("sig", "wb").write(d(s))
PY
openssl dgst -sha256 -verify pub.pem -signature sig msg        # Verified OK
```

Flip a byte of `sig` and rerun: `Verification failure`. The reverse direction (our verifier accepts an OpenSSL signature) is in
`tests/test_rsa.py::test_our_verify_accepts_openssl_signature`.

## Step 4 - refresh rotation and reuse detection over HTTP, by hand

```bash
python3 -m mcpauth serve --transport http --port 8767 --issuer http://127.0.0.1:8767 &
S=$(python3 -m mcpauth client-secret demo-client)
T1=$(curl -s -u demo-client:$S -d grant_type=client_credentials -d 'scope=mcp tools:read offline_access' http://127.0.0.1:8767/oauth/token)
R1=$(echo "$T1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["refresh_token"])')
T2=$(curl -s -u demo-client:$S -d grant_type=refresh_token -d refresh_token=$R1 http://127.0.0.1:8767/oauth/token)   # new pair
curl -s -u demo-client:$S -d grant_type=refresh_token -d refresh_token=$R1 http://127.0.0.1:8767/oauth/token         # invalid_grant: REUSE
R2=$(echo "$T2" | python3 -c 'import sys,json;print(json.load(sys.stdin)["refresh_token"])')
curl -s -u demo-client:$S -d grant_type=refresh_token -d refresh_token=$R2 http://127.0.0.1:8767/oauth/token         # invalid_grant: family revoked
python3 -m mcpauth token-audit-verify                                                                                # chain ok; log contains reuse_detected
kill %1
```

## Step 5 - JWKS leaks nothing

```bash
curl -s http://127.0.0.1:8767/.well-known/jwks.json     # only kid/alg/kty (+ n,e for RSA); no "k", no "d", no secret
grep -c "$(python3 -c 'import json,os;print([k["secret"] for k in json.load(open(os.environ["MCP_FORGE_HOME"]+"/keys.json"))["keys"] if "secret" in k][0])')" <(curl -s http://127.0.0.1:8767/.well-known/jwks.json)   # 0
```

## Step 6 - model check, mutation check, evidence regeneration

```bash
python3 tools/refresh_check.py --depth 5      # every sequence of 7 refresh-token operations up to depth 5 vs. an invariant oracle
python3 tools/mutation_sanity.py              # 25 injected auth/protocol bugs; every one must be KILLED
tools/build_evidence.sh                       # regenerate evidence/
```

## Step 7 - formal-verification hooks (honest strength)

| Hook | Where | Strength |
|---|---|---|
| Runtime contracts (`AUTH-*` incl. AUTH-3 "refreshed scope is a subset of the grant") | `mcpauth/tokens.py`, `mcpauth/contracts.py` | assertions on real traffic |
| Bounded model check of refresh rotation (reuse revokes family, no escalation, one winner) | `mcpauth/refreshcheck.py`, `tools/refresh_check.py`, `evidence/refresh_check.txt` | exhaustive **up to the depth given** |
| Hash-chained token audit log + request audit log | `mcpauth/tokens.py`, `mcpauth/audit.py` | tamper-evident; tail truncation needs an anchor (`--expect-head`) |
| Independent oracle for RS256 (OpenSSL) | `tests/test_rsa.py::OpenSslInterop`, `demo.py` | external agreement on test vectors |

## Requirement -> evidence map

| Requirement | Implementation | Tests / checks |
|---|---|---|
| Multiple scopes + per-method enforcement | `mcpauth/server.py` | `tests/test_protocol.py::test_read_only_scope`, `tests/test_protocol.py::test_only_base_scope`, `tests/test_protocol.py::test_error_data_names_required_scope`, `check:HRD-003`, `check:HRD-005` |
| Scope implication | `mcpauth/auth.py` | `tests/test_auth.py::test_valid_token_and_scope_expansion`, `check:HRD-004` |
| Refresh rotation | `mcpauth/tokens.py` | `tests/test_tokens.py::test_rotation_issues_new_token_and_marks_old_used`, `check:HRD-010` |
| Reuse detection revokes the family | `mcpauth/tokens.py` | `tests/test_tokens.py::test_reuse_revokes_whole_family_including_newest_and_access_tokens`, `tests/test_tokens.py::test_other_family_unaffected`, `tests/test_tokens.py::test_client_credentials_refresh_reuse_over_http` |
| Concurrency-safe single winner | `mcpauth/tokens.py` | `tests/test_tokens.py::test_concurrent_presentation_of_same_token_exactly_one_wins` |
| No scope escalation, client binding | `mcpauth/tokens.py` | `tests/test_tokens.py::test_no_scope_escalation_and_downscope_allowed`, `tests/test_tokens.py::test_client_binding_expiry_malformed`, `check:HRD-011` |
| Refresh tokens stored only as hashes | `mcpauth/tokens.py` | `tests/test_tokens.py::test_refresh_tokens_stored_only_as_hashes` |
| Revocation list + introspection | `mcpauth/tokens.py` | `tests/test_tokens.py::test_introspection_and_revoke_token`, `tests/test_tokens.py::test_introspection_requires_admin_client`, `tests/test_tokens.py::test_revoke_endpoint`, `check:HRD-007`, `check:HRD-012` |
| Revocation enforced mid-session | `mcpauth/server.py`, `mcpauth/auth.py` | `check:HRD-007`, `tests/test_auth.py::test_revocation_oracle_and_audit_chain` |
| `kid`, key rotation, grace, revocation of keys | `mcpauth/auth.py` | `tests/test_auth.py::test_rotation_retire_grace_and_expiry`, `tests/test_auth.py::test_revoking_active_key_rolls_a_new_one`, `check:HRD-001`, `check:HRD-006` |
| Algorithm pinning (alg confusion, none) | `mcpauth/auth.py` | `tests/test_auth.py::test_rejections`, `check:HRD-002` |
| Kid-less tokens only when configured | `mcpauth/auth.py` | `tests/test_auth.py::test_kidless_hs256_only_when_configured` |
| RS256 by hand, verified by OpenSSL | `mcpauth/rsa.py` | `tests/test_rsa.py::test_openssl_verifies_our_signature_with_our_pem`, `tests/test_rsa.py::test_our_verify_accepts_openssl_signature`, `tests/test_rsa.py::test_forged_signature_with_garbage_padding_rejected`, `tests/test_auth.py::test_rs256_end_to_end_with_rotation` |
| Published RSA key suffices to verify | `mcpauth/auth.py` | `tests/test_auth.py::test_published_rsa_key_alone_is_enough_to_verify_signatures` |
| Clock-skew leeway | `mcpauth/auth.py` | `tests/test_auth.py::test_leeway_boundaries`, `tests/test_auth.py::test_zero_leeway_is_strict`, `check:HRD-008` |
| Discovery + JWKS without secrets | `mcpauth/tokens.py`, `mcpauth/auth.py` | `tests/test_tokens.py::test_jwks_and_discovery_do_not_leak_secrets`, `tests/test_tokens.py::test_revoked_keys_disappear_from_jwks`, `tests/test_auth.py::test_keys_file_is_0600_and_public_view_never_leaks_secrets`, `check:HRD-009` |
| Hash-chained token audit log, no raw tokens | `mcpauth/tokens.py` | `tests/test_tokens.py::test_audit_chain_and_events`, `check:HRD-014` |
| Rate limiting (-32005) | `mcpauth/tokens.py`, `mcpauth/server.py` | `tests/test_tokens.py::test_rate_limiter_bucket_refill_and_isolation`, `tests/test_protocol.py::test_burst_then_32005_with_retry_after_ping_exempt_and_per_subject` |
| Lockout (address and client) | `mcpauth/tokens.py`, `mcpauth/transport_http.py` | `tests/test_tokens.py::test_lockout_window_duration_success_reset`, `tests/test_tokens.py::test_client_lockout_after_repeated_failures`, `check:HRD-013` |
| Handler crash -> 500 JSON, not a dropped connection | `mcpauth/transport_http.py` | `tests/test_tokens.py::test_handler_crash_returns_500_not_dropped_connection` |
| Constant-time compares | `mcpauth/auth.py`, `mcpauth/tokens.py` | mutants M04, M13, M17 in `tools/mutation_sanity.py` (behavioural; timing itself is **not** measured) |
| Refresh model check detects injected bugs | `mcpauth/refreshcheck.py` | `tests/test_tokens.py::test_injected_bug_no_reuse_detection_is_caught`, `tests/test_tokens.py::test_injected_bug_scope_escalation_is_caught`, `tests/test_tokens.py::test_depth3_all_sequences_pass` |
| stdio and HTTP | `mcpauth/transport_stdio.py`, `mcpauth/transport_http.py` | `tests/test_stdio_e2e.py`, `tests/test_http_e2e.py`, `check:HTP-003` |
| stdlib only | `tools/check_stdlib_only.py` | `tests/test_llm_and_tools.py::test_stdlib_only_checker_catches_violations` |
