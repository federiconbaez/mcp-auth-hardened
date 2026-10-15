# SECURITY.md - mcp-auth-hardened

Inherits the threat model and controls of `mcp-base` (local/lab server, strict schemas, size limits, loopback-only HTTP with
Origin/Host checks, hash-chained request audit log). This file lists what the hardened auth layer adds and where it is weak.

## Controls

| Control | Detail |
|---|---|
| Algorithm pinning | only `HS256` and `RS256`; the header `alg` must equal the algorithm of the key named by `kid` (blocks `none` and HS/RS confusion) |
| Key identification | `kid` mandatory (format-checked); unknown kid rejected; kid-less HS256 accepted only with `--allow-kidless` (compat with mcp-base) |
| Key lifecycle | `active -> retired` (still verifies for a grace period, default 24 h; verify-only imported public keys get 10 years) `-> revoked` (rejected at once); revoking the only active key rolls a fresh HS256 key so the server can still sign |
| Claims | `iss`, `aud`, `sub`, `jti`, `exp`, `iat`, `nbf`, 30 s leeway (configurable, 0 allowed) |
| Token hygiene | strict base64url alphabet, 8 KiB cap, canonical encoding; raw tokens and refresh tokens never logged (audit stores fingerprints) |
| Refresh tokens | 256-bit random, stored as SHA-256, rotated on every use, reuse revokes the family, client-bound, scope can only shrink, `BEGIN IMMEDIATE` serialisation |
| Revocation | jti list + refresh-family list, checked on every request (also for long-lived stdio sessions) |
| Introspection | only `admin-client`; unknown/invalid tokens produce `{"active": false}` and nothing else |
| JWKS / discovery | RSA `n`,`e` only; HS256 secrets and RSA private exponent are never serialised into public views (tested) |
| Brute force | per-client lockout (429 + `Retry-After`), per-address bearer-failure lockout, per-subject token bucket (`-32005`) |
| Secrets at rest | `keys.json` and `oidc_secret` mode 0600; comparisons via `hmac.compare_digest` |
| Crash handling | an exception in an HTTP handler yields a JSON 500 `server_error`, never a dropped connection or a leaked traceback |

## Known weaknesses / not done

* **Hand-written RSA.** No blinding, Python big-int arithmetic is not constant-time, key generation uses `secrets` + Miller-Rabin
  with a fixed number of rounds. A timing attacker with many signing oracle queries could in principle recover information; tokens are
  signed only by the server on request of authenticated flows, but this has not been analysed. Do not reuse `mcpauth/rsa.py` elsewhere.
* **Constant-time claims are about API usage** (`hmac.compare_digest`); timing was never measured.
* **HS256 keys cannot be published**; anyone who can read `keys.json` can mint tokens. Rotation limits blast radius but is manual (`keys rotate`).
* **State is partly in memory**: lockout counters, rate-limit buckets and HTTP sessions are lost on restart (an attacker who can
  crash the server resets lockouts). Refresh families and revocations are persistent (`auth.sqlite3`).
* **Not an OP:** no authorization-code/PKCE, no user login, no dynamic client registration, no `id_token`s; built-in client secrets
  are derived from the server secret, not stored per client.
* Introspection oracle is limited to privileged clients, but `admin-client` is a built-in client whose secret is derivable by anyone who can run the CLI on the data dir.
* No TLS (plain `http.server`); tokens travel in clear text unless a TLS terminator is placed in front. No third-party review or pen test; Linux/CPython 3.13 only.
