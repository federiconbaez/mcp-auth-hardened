# ORIGINALITY.md - provenance of mcp-auth-hardened (and what the evidence cannot prove)

## What was done

* Written by an AI assistant (Grok Bot) for Federico N. Báez Rizzo. The repository starts from a **copy of the user's own `mcp-forge`**
  (commit "Import mcp-forge base", i.e. `mcp-base`) and adds the hardened authentication design on top.
* **Adapted from mcp-forge (stated plainly):** JSON-RPC engine (`mcpauth/jsonrpc.py`), schema validator (`mcpauth/schema.py`), audit log
  (`mcpauth/audit.py`), contracts registry (`mcpauth/contracts.py`), fuzzer (`mcpauth/fuzz.py`), LLM hook (`mcpauth/llm.py`), the SQLite
  memory store (`mcpauth/memory.py`, unchanged apart from the package name), most of the server core (`mcpauth/server.py`), the transports,
  parts of `mcpauth/catalog.py` and `mcpauth/cli.py`, and the conformance *harness* with its ~120 protocol checks. Per-file overlap with
  `mcp-base` is measured below (`tools/adaptation_report.py`).
* **New in this repo (not in mcp-forge):** `mcpauth/rsa.py` (hand-written RSA / RS256), `mcpauth/tokens.py` (refresh families, revocation,
  introspection, token audit, rate limiter, lockout, mock issuer), `mcpauth/refreshcheck.py` (bounded model check), the rewritten
  `mcpauth/auth.py` (key ring, `kid`, alg pinning, claims, leeway, implication), the scope table in `mcpauth/server.py`, the new tools and
  resources, CLI commands (`keys`, `token-*`), conformance checks `HRD-001..014`, and tests `tests/test_rsa.py`, `tests/test_tokens.py`,
  `tests/test_auth.py` (rewritten), plus `RateLimitProtocolTests`.
* The algorithms (RSASSA-PKCS1-v1_5, Miller-Rabin, JWT/JWS, refresh rotation, reuse detection) are **standard published techniques**
  implemented from the author's knowledge of RFC 7515/7518/7519/7662/7009/6749/8017/8725; they are not novel and similar code exists
  publicly. No code was copied from any SDK or library, no package was installed, and no web search/fetch was performed.
* Dependencies: **zero** (standard library). `openssl` is used only as an optional external test oracle by a test and the demo.

## What the evidence below can and cannot show

| Evidence | Shows | Does NOT show |
|---|---|---|
| `tools/check_stdlib_only.py` (AST) | no third-party import, no `exec/eval/__import__/importlib`, no dependency manifest or vendored dir | that the code is dissimilar to anyone else's |
| SDK-identifier scan | no `modelcontextprotocol`/`fastmcp`/`from mcp` in source | the same |
| Line-overlap report vs mcp-base | how much is inherited from the user's own earlier project | anything about third parties |
| git history | incremental construction; bug fixes found by the author's own tests (e.g. revoking the only active key left no signer; handler crashes dropped HTTP connections) | immutability (unsigned history) |
| Source sha256 manifest + `MANIFEST.sha256` | byte-identity with what was verified | authorship |
| OpenSSL interop tests | the RSA code agrees with a widely used implementation on the tested vectors | that it is free of side channels or edge-case bugs |
| Mutation check | tests catch 25 injected bugs | that they catch all |

**The evidence cannot prove dissimilarity to code you have not shown me.** Only a similarity tool run by a third party against the
corpus you care about can say something about that; none was run and no negative result is claimed. The claim is limited to *provenance*.

## Disclosure

Produced by an AI assistant. "Originality" means provenance and absence of third-party code, not novelty. Writing your own
cryptography is generally discouraged; this is a teaching/verification artifact (see SECURITY.md).

## Mechanical evidence (live at generation time)

<!-- GENERATED:BEGIN -->
<!-- GENERATED:END -->
