# mcp-auth-hardened

> **ES:** Servidor MCP con capa de autenticación endurecida (simplificada) en Python 3 stdlib: scopes por método, rotación de refresh tokens con detección de reuso, revocación e introspección, rotación de claves por kid (HS256 y RS256 escrito a mano), rate limiting y log de tokens encadenado.
> Probar: `python3 -m unittest discover -s tests -t .`
>
> **EN:** MCP server with a hardened (still simplified) auth layer in Python 3 stdlib: per-method scopes, refresh-token rotation with reuse detection, revocation and introspection, kid-based key rotation (HS256 and hand-written RS256), rate limiting and a hash-chained token log.
> Test: `python3 -m unittest discover -s tests -t .`
>
> **Estado / Status:** 153 tests en verde en la box (Python 3.13.5, Linux 6.12, x86_64) el 2026-10-22; **no auditado** por un tercero / **not independently audited**. Implementación didáctica, no un IdP de producción / teaching implementation, not a production IdP. Licencia / License: Apache-2.0.


An **MCP server with a hardened (but still simplified) OIDC-style authentication layer**, pure Python 3, standard library only:
multi-scope tokens with per-method enforcement, refresh-token rotation with reuse detection, revocation + introspection,
`kid`-based key rotation (HS256 and a **hand-written RS256**), a hash-chained token audit log, rate limiting and lockout,
clock-skew leeway, a discovery document + JWKS that leak no secrets, constant-time comparisons, over stdio and HTTP.
Sibling of `mcp-base`, `mcp-memory-first`, `mcp-resource-heavy` and `mcp-crosscheck` in the *mcp-family*.

> Honest scope: this is **not** a certified OpenID Provider and not the MCP OAuth 2.1 profile. It is a reference implementation
> plus a self-consistent verification kit. RS256 is implemented by hand for the sake of "no dependencies" - which is itself a
> risk (see [SECURITY.md](SECURITY.md)). CPython 3.13.5 on Linux only.

## What is different from mcp-base

| Feature | Behaviour | Code |
|---|---|---|
| **Scopes, per-method** | `tools/list`->`tools:read`, `tools/call`->`tools:read` + the tool's own scopes, `resources/*`->`resources:read`, `prompts/*`->`prompts:read`; insufficient scope -> JSON-RPC `-32003` (HTTP 403) with `data.required/granted`; implication `memory:admin => memory:write => memory:read`, `tools:write => tools:read` | `mcpauth/server.py` (`METHOD_SCOPES`), `mcpauth/auth.py` (`IMPLIES`) |
| **Key ring, `kid`, rotation** | `keys.json` (0600): HS256 + RS256 keys, `active -> retired (grace) -> revoked`; every token carries `kid`; `alg` is pinned to the key's algorithm (alg confusion rejected); kid-less tokens refused unless `--allow-kidless` (needed to accept `mcp-base` tokens) | `mcpauth/auth.py` (`Keyring`) |
| **RS256 by hand** | big-int RSA, Miller-Rabin key generation, EMSA-PKCS1-v1_5/SHA-256, strict verification; cross-checked against `openssl` in both directions | `mcpauth/rsa.py`, `tests/test_rsa.py` |
| **Claims** | `iss aud sub exp iat nbf jti` validated; clock-skew **leeway** (default 30 s, `--leeway`) | `mcpauth/auth.py` |
| **Refresh rotation + reuse detection** | each refresh returns a new refresh token; presenting an already-used one revokes the **whole family** (refresh tokens and the access tokens minted from it); stored only as SHA-256; `BEGIN IMMEDIATE` makes concurrent presentations race-safe; no scope escalation | `mcpauth/tokens.py` |
| **Revocation + introspection** | `POST /oauth/revoke` (RFC 7009 style, always 200), `POST /oauth/introspect` (RFC 7662 style, privileged client only, `{"active":false}` and nothing else for bad tokens); CLI `token-revoke`, `token-introspect` | `mcpauth/tokens.py`, `mcpauth/transport_http.py` |
| **Discovery + JWKS** | `/.well-known/openid-configuration`, `/.well-known/jwks.json` publish RSA `n`,`e` only; HS256 secrets and RSA private parts never appear | `mcpauth/auth.py` (`public_view`), `mcpauth/tokens.py` |
| **Token audit log** | hash-chained `token_audit.log`: issue / validate / reject / revoke / refresh / reuse_detected / lockout; never contains a raw token (fingerprints only) | `mcpauth/tokens.py` (`TokenAudit`), `mcpauth/audit.py` |
| **Rate limiting + lockout** | per-subject token bucket (`-32005` + `Retry-After`, default 200 req/s burst 400, `ping` exempt); per-address bearer-failure lockout; per-client authentication lockout (429 + `Retry-After`) | `mcpauth/tokens.py`, `mcpauth/server.py`, `mcpauth/transport_http.py` |
| **Constant-time compares** | `hmac.compare_digest` for signatures, client secrets, refresh-token hashes | `mcpauth/auth.py`, `mcpauth/tokens.py` |
| **Formal-verification hooks** | contracts `AUTH-*`, bounded model check of refresh rotation (`mcpauth/refreshcheck.py`, `tools/refresh_check.py`), hash-chained logs, evidence generators | see [AUDIT.md](AUDIT.md) |

Tools (9): `memory_store`, `memory_recall`, `memory_list`, `memory_forget`, `memory_wipe` (admin), `whoami`, `token_introspect`
(`auth:admin`), `token_revoke` (`auth:admin`), `audit_verify`. Resources: `auth://whoami`, `memory://index`, `audit://chain`,
`auth://token-audit`, `auth://keys`, `auth://revocations`, `memory://entry/{id}` ... Default audience: `mcp-auth-hardened`.

Scopes: `mcp tools:read tools:write resources:read prompts:read memory:read memory:write memory:admin audit:read auth:admin`
(+ `offline_access` for refresh tokens). Built-in clients: `demo-client`, `readonly-client`, `admin-client` (secrets are derived
from the server secret: `python3 -m mcpauth client-secret <id>`).

## Quickstart

```bash
./demo.sh                           # 42-step demo: refresh reuse, key rotation, OpenSSL verification of our RS256, lockout, audit tamper ...
python3 -m unittest discover        # 153 tests
python3 -m mcpauth conformance      # 140 black-box checks (stdio + http); HRD-001..014 are auth specific
python3 tools/refresh_check.py --depth 5   # bounded model check of refresh rotation
python3 tools/check_stdlib_only.py  # AST proof: stdlib only
```

```bash
export MCP_FORGE_HOME=$PWD/.mcpauth
python3 -m mcpauth keys rotate --alg RS256 --bits 2048     # new active key; the old one stays valid during the grace period
export MCP_TOKEN=$(python3 -m mcpauth mint-token --scope "mcp tools:read tools:write memory:read memory:write")
python3 -m mcpauth serve                                    # stdio
python3 -m mcpauth serve --transport http --port 8767       # HTTP: /mcp, /oauth/token, /oauth/introspect, /oauth/revoke, /.well-known/*
python3 -m mcpauth token-issue --offline                    # access + refresh token from the local token service
python3 -m mcpauth token-audit-verify                       # verify the token audit chain
```

Accepting `mcp-base` tokens (they have no `kid`): `--allow-kidless` plus the **same secret and audience**; this is exactly what
`mcp-crosscheck` configures for its "configured" layer. By default they are rejected (different audience, no kid).

## Limitations

* Not a certified OP; no authorization-code/PKCE flow, no user authentication, no dynamic registration.
* Hand-written RSA: no blinding, not constant-time big-int arithmetic, key sizes >= 512 bits (multiple of 16; 2048 is the default, 1024 is used in tests); use a vetted library for anything real.
* HS256 keys cannot be published; relying parties must use introspection. Keys live in a file (0600), not an HSM.
* Lockout and rate-limit state is **in memory** (reset on restart; per process).
* HTTP is plain `http.server` without TLS. Sessions are in memory.
* The refresh model check is **bounded** (7 operations, depth 5); the claims are about those bounds only.
* Tests, suite and server share one author; no third-party client or OAuth test-suite has been run.

## Resumen en español

`mcp-auth-hardened` es un servidor MCP en Python puro (solo biblioteca estándar) con una capa de autenticación endurecida
(aunque simplificada y no certificada): permisos (*scopes*) por método, rotación de *refresh tokens* con detección de reutilización
(si se reutiliza uno ya usado, se revoca toda la familia), lista de revocación e introspección, `kid` y rotación de claves
(HS256 y RS256 escrito a mano, verificado contra `openssl`), registro de auditoría de tokens encadenado con hashes, límite de
tasa y bloqueo por fuerza bruta, tolerancia de reloj, documento de descubrimiento y JWKS sin filtrar secretos, comparaciones en
tiempo constante, por stdio y HTTP. Verificación: `./demo.sh`, `python3 -m unittest discover`, `python3 -m mcpauth conformance`.
Los pasos para un auditor externo están en `AUDIT.md`; la evidencia de originalidad y sus límites, en `ORIGINALITY.md`.
