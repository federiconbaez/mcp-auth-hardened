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
### AST stdlib-only check (live run, exit code 0)

```
STDLIB-ONLY CHECK (ast-based; nothing was imported or executed)
python 3.13.5, 290 stdlib modules known to this interpreter

file                                 code  total  imports (stdlib/local)
demo.py                               339    402  base64,hashlib,http,json,os,shutil,signal,socket,subprocess,sys,tempfile,threading,time,urllib
mcpauth/__init__.py                     6     11  
mcpauth/__main__.py                     3      5  sys  | local: .cli
mcpauth/audit.py                      132    153  fcntl,hashlib,json,os,threading,time
mcpauth/auth.py                       385    453  base64,binascii,hashlib,hmac,json,math,os,re,secrets,time  | local: .
mcpauth/catalog.py                    275    314  json,re,sqlite3,urllib  | local: .,.llm,.memory
mcpauth/cli.py                        245    299  argparse,json,os,signal,sys,threading  | local: .,.audit,.auth,.conformance,.llm,.server,.tokens,.transport_http,.transport_stdio
mcpauth/conformance.py                963   1234  base64,hashlib,hmac,http,json,os,queue,re,shutil,socket,subprocess,sys,tempfile,threading,time,urllib  | local: .,.audit,.auth
mcpauth/contracts.py                   73    100  functools,os,threading
mcpauth/fuzz.py                       164    193  json,random
mcpauth/jsonrpc.py                    208    255  collections,json  | local: .
mcpauth/llm.py                         44     52  json,os,urllib
mcpauth/memory.py                     127    152  contextlib,json,os,re,sqlite3,time,unicodedata
mcpauth/refreshcheck.py               165    191  copy,os,shutil,tempfile  | local: .auth,.tokens
mcpauth/rsa.py                        110    140  base64,hashlib,hmac,secrets
mcpauth/schema.py                     204    241  re
mcpauth/server.py                     305    352  json,os,secrets,threading,time  | local: .,.audit,.auth,.catalog,.jsonrpc,.memory
mcpauth/tokens.py                     357    414  base64,binascii,contextlib,hashlib,hmac,json,os,secrets,sqlite3,threading,time  | local: .,.audit,.auth
mcpauth/transport_http.py             266    304  http,json,threading,time,urllib  | local: .,.auth,.jsonrpc,.tokens
mcpauth/transport_stdio.py             37     45  sys  | local: .jsonrpc
tests/__init__.py                       0      0  
tests/helpers.py                      103    137  json,os,shutil,subprocess,sys,tempfile,threading,unittest  | local: mcpauth.auth,mcpauth.server,mcpauth.tokens,mcpauth.transport_http
tests/test_auth.py                    224    260  base64,hashlib,hmac,json,os,unittest  | local: mcpauth,mcpauth.audit,mcpauth.auth,mcpauth.tokens,tests.helpers
tests/test_fuzz.py                     99    112  json,random,unittest  | local: mcpauth,mcpauth.auth,tests,tests.helpers
tests/test_http_e2e.py                217    248  base64,http,json,os,subprocess,sys,unittest,urllib  | local: tests,tests.helpers
tests/test_jsonrpc.py                 129    158  json,unittest  | local: mcpauth,mcpauth.jsonrpc,tests
tests/test_llm_and_tools.py           123    142  http,json,os,shutil,subprocess,sys,tempfile,threading,unittest  | local: mcpauth.llm,tests,tests.helpers
tests/test_persistence_audit.py       180    208  json,os,threading,unittest  | local: mcpauth.audit,mcpauth.memory,tests,tests.helpers
tests/test_protocol.py                308    356  itertools,json,os,unittest  | local: mcpauth.tokens,tests,tests.helpers
tests/test_rsa.py                      94    113  hashlib,os,shutil,subprocess,tempfile,unittest  | local: mcpauth
tests/test_schema.py                   83     98  tempfile,unittest  | local: mcpauth,mcpauth.catalog,mcpauth.memory,tests
tests/test_stdio_e2e.py                71     83  json,unittest  | local: tests,tests.helpers
tests/test_tokens.py                  254    297  base64,json,os,sqlite3,threading,unittest,urllib  | local: mcpauth,mcpauth.auth,mcpauth.tokens,tests,tests.helpers,tests.test_http_e2e
tools/adaptation_report.py             47     58  difflib,os,sys
tools/check_doc_refs.py                51     59  glob,os,re,sys
tools/check_stdlib_only.py            142    161  argparse,ast,json,os,subprocess,sys
tools/gen_originality.py               72     88  hashlib,os,re,subprocess,sys
tools/make_manifest.py                 60     73  argparse,hashlib,os,sys
tools/mutation_sanity.py               78     90  argparse,concurrent,os,shutil,subprocess,sys,tempfile
tools/refresh_check.py                 28     34  argparse,json,os,sys,time  | local: mcpauth

files: 40   lines: total=8085 code=6771 comment=102 blank=1212
stdlib modules used (35): argparse, ast, base64, binascii, collections, concurrent, contextlib, copy, difflib, fcntl, functools, glob, hashlib, hmac, http, itertools, json, math, os, queue, random, re, secrets, shutil, signal, socket, sqlite3, subprocess, sys, tempfile, threading, time, unicodedata, unittest, urllib

GIT HISTORY (oldest first):
e4606fc|Grok Bot (mcp-family build)|2026-10-15T02:47:10Z|Import mcp-forge base (adapted: package renamed, project-specific audience/paths); variant work follows

 34 files changed, 5745 insertions(+)
ad492d3|Grok Bot (mcp-family build)|2026-10-15T03:02:37Z|Auth-hardened: keyring (HS256+RS256 by hand), kid rotation, claims/leeway/revocation, refresh rotation with reuse detection, introspection, lockout, rate limit, token audit chain

 7 files changed, 1249 insertions(+), 263 deletions(-)
fb43424|Grok Bot (mcp-family build)|2026-10-15T03:11:24Z|Auth-hardened: HRD conformance checks, fix revoke-active-key and 500-on-handler-crash bugs, hardened test suites (rsa/openssl interop, keyring, claims, refresh, endpoints, rate limit, model check)

 15 files changed, 1222 insertions(+), 201 deletions(-)
671e4fd|Grok Bot (mcp-family build)|2026-10-15T03:38:32Z|Auth-hardened: end-to-end demo (42 steps incl. OpenSSL RS256 verification), tools: gen_originality, top-level manifest

 4 files changed, 394 insertions(+), 144 deletions(-)
f21031b|Grok Bot (mcp-family build)|2026-10-15T03:47:48Z|Auth-hardened: README/AUDIT/ORIGINALITY/SECURITY, mutation suite rewritten for auth (25 mutants), JWKS test, evidence tooling

 11 files changed, 460 insertions(+), 29 deletions(-)

RESULT: PASS - zero third-party imports, no dynamic imports/exec/eval, no dependency manifests
```

### Lines inherited from mcp-base / mcp-forge, per file (`evidence/adaptation_report.txt`)

```
file                                lines  inherited      %
mcpauth/__init__.py                     8          7    88%
mcpauth/__main__.py                     3          3   100%
mcpauth/audit.py                      132        132   100%
mcpauth/auth.py                       397         78    20%
mcpauth/catalog.py                    278        191    69%
mcpauth/cli.py                        245         80    33%
mcpauth/conformance.py               1000        799    80%
mcpauth/contracts.py                   73         73   100%
mcpauth/fuzz.py                       166        166   100%
mcpauth/jsonrpc.py                    211        211   100%
mcpauth/llm.py                         44         44   100%
mcpauth/memory.py                     129        129   100%
mcpauth/refreshcheck.py               166          0     0%
mcpauth/rsa.py                        112          0     0%
mcpauth/schema.py                     205        205   100%
mcpauth/server.py                     312        259    83%
mcpauth/tokens.py                     365          0     0%
mcpauth/transport_http.py             273        230    84%
mcpauth/transport_stdio.py             37         36    97%
TOTAL package code                   4156       2643    64%
```

### Git history (5 commits at generation time; later commits only touch docs/evidence)

```
e4606fc  Grok Bot (mcp-family build)  2026-10-15T02:47:10Z  Import mcp-forge base (adapted: package renamed, project-specific audience/paths); variant work follows
ad492d3  Grok Bot (mcp-family build)  2026-10-15T03:02:37Z  Auth-hardened: keyring (HS256+RS256 by hand), kid rotation, claims/leeway/revocation, refresh rotation with reuse detection, introspection, lockout, rate limit, token audit chain
fb43424  Grok Bot (mcp-family build)  2026-10-15T03:11:24Z  Auth-hardened: HRD conformance checks, fix revoke-active-key and 500-on-handler-crash bugs, hardened test suites (rsa/openssl interop, keyring, claims, refresh, endpoints, rate limit, model check)
671e4fd  Grok Bot (mcp-family build)  2026-10-15T03:38:32Z  Auth-hardened: end-to-end demo (42 steps incl. OpenSSL RS256 verification), tools: gen_originality, top-level manifest
f21031b  Grok Bot (mcp-family build)  2026-10-15T03:47:48Z  Auth-hardened: README/AUDIT/ORIGINALITY/SECURITY, mutation suite rewritten for auth (25 mutants), JWKS test, evidence tooling
```

### SDK-identifier scan of source files (`modelcontextprotocol|fastmcp|from mcp|import mcp`)

```
mcpauth/auth.py:1: """Hardened simplified-OIDC token validation (NEW code for mcp-auth-hardened; base64url helpers adap
mcpauth/cli.py:39: help="ALSO accept HS256 tokens without a kid header (e.g. from mcp-base) if they verify under an HS2
tools/adaptation_report.py:2: """Per-file report: how many lines of each variant file are inherited (unchanged) from mcp-base (= t
tools/gen_originality.py:51: parts.append("### Lines inherited from mcp-base / mcp-forge, per file (`evidence/adaptation_report.t
tools/gen_originality.py:55: pat = re.compile(r"modelcontextprotocol|fastmcp|from mcp\b|import mcp\b", re.I)
tools/gen_originality.py:61: parts.append("### SDK-identifier scan of source files (`modelcontextprotocol|fastmcp|from mcp|import
```

### Source sha256 manifest (42 files, 8118 lines incl. blanks/comments/tests)

```
fe4dd56858fc561b23382d4589510668adca62427b811f40d0fedba5a696dd8d  demo.py
a02448a1ef37ee611dcf004235001b521f703bdea08f06f3a826ac8cc8c4b58f  demo.sh
c6182ee6e1711dcf00b473c5b009cf252bd1d853148782e41028f5c09a8bedca  mcpauth/__init__.py
13a1a5b340cdcfc1902b62be90e508c7c71886000d5bf087e7854aadf09fb35e  mcpauth/__main__.py
63d10d1acb3d9fe1f8b55ecf5a1957d950bc10c1199352f350b890f5029bed7b  mcpauth/audit.py
08ca52442f9a48a40e458f0c05b8fb90294338642e45b88f224377dd1e93f858  mcpauth/auth.py
d3f5c62dfb434b7577aca06eed3a4f725e9852dcf07f7bb84a23d1ff9206c07c  mcpauth/catalog.py
cb46fbce2d5076441098390f2a55eb343e8a72ad55715d04953608734d4822ea  mcpauth/cli.py
fdb3e84204e2cd93bec73c1fc7a114a21de3cdbe7065be828ef005117d8ad6ee  mcpauth/conformance.py
9f072dbea531000f70687390911bee0af3a2b28fe27950eaf9a8c9a6fde1b7a3  mcpauth/contracts.py
87a0ea1907c1434ff9c6d64dc2f8b94da3ce4e641631f0b0820c351978e40995  mcpauth/fuzz.py
35352448a4ba83985f5f84ff18f1e0decc05096222f5ee506964ea305dc7873a  mcpauth/jsonrpc.py
030bdd0f0eed180c2248318ca4af571cb3154d376529014f703cf243ce4e51b2  mcpauth/llm.py
07328559e4e01eebddbbbc558ff90003efc06bc2c140ab00bbf3ac4737401f1d  mcpauth/memory.py
bb20cdd63701af209105705314af470bec864f548002275627f11300d3b8dbc9  mcpauth/refreshcheck.py
7f7b40f3bc7eef013dc8830b7a422d2c29fed1e287a1cea3219fcbd49b514fe0  mcpauth/rsa.py
6522db8460cbd73973d0eeb6e71fa96908606bff53000bd99dd3850f37d6fd8a  mcpauth/schema.py
763651fb31d9ccde5c39f280e6ae8b2a4eb3318dcccaa2bcaa0ce56d4ddb49a4  mcpauth/server.py
ffa3d2ec2cb8ff96c122b6fbe42a3aef421c6ecf2177a3c4e4f974063b6e9e3f  mcpauth/tokens.py
050457830155691728026db41d5af77b2a7e5868cfa2d509dae561716e97e9f3  mcpauth/transport_http.py
9e40098b83d9b5b9781de710dbcf0cc7240450786ad7971257f5f5d530275362  mcpauth/transport_stdio.py
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  tests/__init__.py
6a942c5c470c816a48c7e3f463d3d09e7de6a954fadd2ed75872bdd965d12501  tests/helpers.py
097a6e345dd3405364e3f74d256ecbdd59c03479aaaabb3f04337883d18fea2f  tests/test_auth.py
e0293218ef86c80b27745933ed7a4081a94e17e6a0145aa1282ac279eee5a25b  tests/test_fuzz.py
ea99aaabbcfbbe261aeb666c7c63a90f535abde253b5abfc27e387765f92fff9  tests/test_http_e2e.py
94bcaecd86f7d0c04a270c1682cdae08672ee6625bdacc22d5829abdc18028d8  tests/test_jsonrpc.py
c7f0bb7ecab6e56cca0c0ed7e76af6ede322f756ddd1d9402e9b452374561e97  tests/test_llm_and_tools.py
e1e56c2bc1113434b84f683949fad5895bdfe7a419dcde6900027519316cc059  tests/test_persistence_audit.py
036831e7cd9b2e2cdae754ab9840dea318d18a4a0a66abdb2d2417c35f6bbf96  tests/test_protocol.py
a042982caf3db58f9b80fe5aee054ad3a6048b57a4a0e2a36a8723966b17e468  tests/test_rsa.py
405ee5e23a2c009af57834a3c79b9d18be24a2d0aec66cd284d4ef74caf143d1  tests/test_schema.py
04d43bfb12d2a35203e7f26298e9c5392c42fdc4014a10484509bd10a771bf17  tests/test_stdio_e2e.py
748d17302271c30bfdda1437dfd8b018ad8e992a883726519849b14699699773  tests/test_tokens.py
89e8b7dd57c23907d7fab1305e2eedcf3056ed2dc30ab767912d04d1a644751c  tools/adaptation_report.py
75893272f7e5d76f045e25554c6c8bb4392beb3a118f7113f40d568f1afeeb8a  tools/build_evidence.sh
b2d2145aae29a6f08cc2f3ac1ab3bfd6ba0485b560c8033d93480e26f91e81cb  tools/check_doc_refs.py
83fac84d53732d658ca33d855610e2b9c0aacf4b28be49be724f8a9662f34341  tools/check_stdlib_only.py
65074c2678b2e041b9cc1e426dcb0549c95b4e42cca1c43b198b40f8efd2fc7d  tools/gen_originality.py
edc0d78fc71b717d0351ceb306355fc099b8dce9c3d7a4f2658ac92ff9dfac4e  tools/make_manifest.py
5759ae9d8996a5254eb1ec0fb8098740e3345ccae2816cfaa63ef029782f1e14  tools/mutation_sanity.py
bae25d465c780e9eaea14a2fceefe1c6648350723cde0b342dbcc3f3443be35f  tools/refresh_check.py
```

<!-- GENERATED:END -->
