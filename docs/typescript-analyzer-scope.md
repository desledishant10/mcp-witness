# Scope: a TypeScript analyzer for mcp-witness

**Status:** **Phases 1–2 implemented (2026-09-26)** — `analyzer/ts/` ships the tree-sitter front-end plus S-006, S-007 (Phase 1) and S-011, S-014 (Phase 2); see the Phasing section. Phase 3 (S-013, S-012) remains. **Why:** the static analyzer was Python-only (AST-based), but a large share of published MCP servers are TypeScript/Node. A TS analyzer roughly doubles the tool's real-world reach.

## The key insight: most of the work is already done

The analyzer runs three rule registries. Crucially, **8 of the 15 rules read only the captured `tools/list` JSON** (name, description, `inputSchema`) and are therefore **language-agnostic** — a TypeScript server captured with `mcp-witness-capture` (which just speaks MCP over stdio) already feeds them unchanged today. One more is file/regex based and already language-agnostic. Only **6 rules parse Python source** and need a TypeScript front-end.

| Category | Rules | TS status |
|---|---|---|
| **A — tool-definition (captured JSON)** | S-001, S-002, S-003, S-004, S-005, S-008, S-009, S-015 | **Already work** on TS servers via `mcp-witness-capture` + `analyze <file>.json`. Zero new code. |
| **C — repo/file (regex)** | S-010 (secrets) | Already scans `.ts`/`.js` if those extensions are in `_SECRET_SCAN_EXTS` (verify list). |
| **B — Python-source AST** | S-006, S-007, S-011, S-012, S-013, S-014 | **The actual work.** Need a TS/JS AST equivalent + TS tool discovery. |

So the TS analyzer is not "reimplement the analyzer." It is: **(1) a TS tool-discovery front-end, and (2) TS-source implementations of 6 handler/transport rules.** The definition-based rules come along for free the moment a TS server is captured.

## Parser decision: tree-sitter (pure Python, proven)

**Chosen: `tree-sitter` + `tree-sitter-language-pack`.** Both are pip-installable with prebuilt wheels; no Node runtime, no build step. `tree_sitter` 0.26 is already in the dev env, and `tree-sitter-language-pack` ships the `typescript`, `tsx`, and `javascript` grammars.

**Feasibility was verified end to end** (2026-09-26): parsing a real TS MCP snippet, the query found `server.tool(...)` registrations, extracted the tool names, and walked each handler body to flag dangerous callees:

```
tool='fetch_url'  handler-danger=['fetch(']        # SSRF surface
tool='read_file'  handler-danger=['readFileSync']  # path-traversal surface
```

That is the core mechanism of every B-rule (find a registration, walk its handler, match sink call-shapes), so the highest-risk unknown is retired.

**Rejected alternatives:**
- *Node + the TypeScript compiler API / `@babel/parser`* — the most semantically precise, but forces a Node runtime and an IPC/JSON-AST bridge on a pip-installed Python tool. Keep it as a possible Phase-3 precision upgrade, not the baseline.
- *Regex only* — insufficient for the handler-body/taint rules (S-006/007/011/013); fine only for the definition rules, which we already get for free.

Trade-off to accept: tree-sitter gives a syntax tree, **not** types or import resolution. That matches the existing Python analyzer, which already resolves callables by simple/attribute name only (`_callable_simple_name`) with no real import resolution — so TS rules can likewise match on syntactic call-shape (`child_process.execSync`, `fs.readFileSync`) rather than resolving module bindings.

## How it slots into the existing analyzer

Keep the shared core and add a language front-end. Nothing about `Finding` or the dispatch loop changes.

- **Shared, unchanged:** `analyzer/types.py` (`Finding`), the `RULES`/`SERVER_RULES` registries for the A-rules, and the captured-JSON path in `analyze.py`.
- **`DiscoveredTool` gains a neutral handler handle.** Today it carries `function_node` (a Python `ast` node). Add an optional `handler_ts` (a tree-sitter node) + `source_bytes` so a tool can be described by either front-end. The A-rules ignore it; the B-rules pick the front-end that matches.
- **New TS front-end** (`analyzer/ts/`):
  - `discover.py` — `discover_tools_in_ts(source_bytes, path)`: tree-sitter query for tool registrations → `DiscoveredTool` with `handler_ts` set.
  - `rules.py` — TS implementations of the 6 B-rules (`check_path_traversal_ts`, …), each operating on `handler_ts`. Reuse the Finding rule_ids/severities so a TS S-007 and a Python S-007 are the same finding class.
  - `treesitter_utils.py` — the shared primitives the map identified as needed (below).
- **CLI dispatch:** extend `analyze_path()` suffix routing — `.ts`/`.tsx`/`.js`/`.mjs`, or a directory containing `package.json`/`tsconfig.json`, routes to the TS front-end; `.py` and `.json` behave as today. One command, `mcp-witness-analyze`, stays the entry point.

This is parallel TS rule functions rather than abstracting the 6 Python rules over a language-neutral node interface. The abstraction is cleaner long-term but a large refactor of working, tested code; parallel functions are the pragmatic v1 and can be unified later.

## Tool (and prompt) discovery in TypeScript

The Python discovery keys on the FastMCP decorator `@mcp.tool`. The TS SDK registers by **call**, not decorator. Detect these shapes (pin exact names against the installed `@modelcontextprotocol/sdk` version in Phase 0):

- High-level: `server.tool("name", "desc"?, schemaShape, handler)` and the newer `server.registerTool("name", { description, inputSchema }, handler)`.
- Prompts (for S-013): `server.prompt(...)` / `server.registerPrompt(...)`.
- Low-level: `server.setRequestHandler(ListToolsRequestSchema, …)` + `CallToolRequestSchema` — the handler is one big switch; discovery here is best-effort (v2).

`inputSchema` on the TS side is usually a **Zod** shape, which is harder to read statically than JSON Schema. This mostly does not matter: the schema-reading rules are all category A and get the real schema from **runtime capture**, not source. Source-side Zod extraction is a nice-to-have for source-only analysis (v2+).

## Per-rule port table (the 6 B-rules)

Each TS rule matches syntactic call-shapes inside the discovered handler body; taint is the lightweight, param-name/line-based approach the Python rules already use.

| Rule | Python sinks/shape | TypeScript sinks/shape to detect |
|---|---|---|
| **S-006 path traversal** | `open()`, `Path(p).read_text/…`, `glob`; taint from path-named param; guards `resolve/realpath/is_relative_to/startswith` | `fs.readFileSync/readFile/createReadStream/promises.readFile`, `fs.openSync`; `path.join(base, userParam)` flowing to an fs read; taint from a path-named handler param; guards: `path.resolve` + a `startsWith(base)` / `path.relative` containment check |
| **S-007 command injection** | `subprocess.*(shell=True)`, `os.system`, `os.popen` | `child_process.exec(...)` / `execSync(...)` (**shell by default** — flag when an arg is or interpolates a handler param), `spawn/execFile(..., { shell: true })`, and a template literal / `+` concatenation of a param into any of these |
| **S-011 sensitive logging** | `print`, `logging.*`, `sys.std{out,err}.write`; sensitive = param, `os.environ`, `.headers`; debug-gated suppressed | `console.log/info/warn/error/debug`, `process.stdout.write`/`process.stderr.write`, common loggers (`logger.*`, `pino`, `winston`); sensitive = handler param, `process.env[...]`, `req.headers`/`.headers`; suppress inside `if (debug|verbose|process.env.DEBUG)` blocks |
| **S-012 roots declared but unused** | `RootsCapability` referenced but `list_roots()` never called | Server declares the roots capability (`capabilities: { roots: … }` or a `roots` option) but never calls `server.listRoots()`. Niche in TS; low priority — confirm the SDK API first |
| **S-013 prompt interpolation** | `@prompt` handler; message ctor / dict with role system\|assistant; f-string/`.format`/`%`/`+` interpolation of a param | `server.prompt(...)` handler returning `messages: [{ role: "system"\|"assistant", content: … }]`; a template literal / `+` / `.replace` putting a prompt argument into that content |
| **S-014 HTTP bind / origin** | `uvicorn.run`/`app.run`/`web.TCPSite` on a rebindable host w/o Origin/Host read; CORS `*`+credentials | `StreamableHTTPServerTransport` / `SSEServerTransport` mounted without `enableDnsRebindingProtection` / `allowedHosts` / `allowedOrigins`; Express/`http.createServer().listen(port, "0.0.0.0")` with no Origin-checking middleware; `cors({ origin: "*", credentials: true })`. **Confirm the SDK's exact DNS-rebinding option names in Phase 0** |

## Shared TS primitives to build (`treesitter_utils.py`)

The map shows the Python helpers live inline; the TS front-end needs analogs of the reusable ones:

- `node_text(node, src)` — the `_safe_unparse` analog (a byte-slice, truncated for evidence).
- `walk(node)` / a small tree-sitter **query** layer — replace `ast.walk`.
- `collect_string_bindings(tree)` — `const HOST = "0.0.0.0"` and function/default params → literal map (the S-014 `_collect_string_bindings` analog); include `process.env.X ?? "default"` (the `_extract_env_default` analog).
- `call_shape(node)` — collapse `a.b.c(...)` to `a.b.c` for sink matching (the `_callable_simple_name` analog).
- `param_names(handler)` — destructured handler params (`async ({ url, path }) => …`) for taint roots.
- `references_param(node, params)` and `line_of(node)` — the line-based taint/guard-suppression the Python rules use.

## Dependencies

Add an **optional extra** so the core install stays lean:

```toml
[project.optional-dependencies]
ts = ["tree-sitter>=0.25", "tree-sitter-language-pack>=1.19"]
```

The TS front-end imports lazily and, if the extra is missing, `mcp-witness-analyze` on a `.ts` path prints a one-line "install mcp-witness[ts]" message and exits cleanly (mirror the existing graceful-degradation patterns).

## Testing strategy

Mirror the existing three-shape fixture approach:

- **A-rules:** already covered by captured JSON; add one captured-`tools/list` JSON from a real TS server to the corpus to prove they fire cross-language.
- **B-rules:** a deliberately-vulnerable `analyzer/tests/fixtures/example_server.ts` (the analog of `example_server.py`) with one `server.tool(...)` per bug class, plus per-rule TS **source-string** fixtures for the negative/guarded cases. Assert by tool name and rule_id exactly as the Python suite does.
- Keep the same bar: every rule ships with positive + guarded-negative tests; no false positive on a safe handler.

## Phasing and rough effort

- **Phase 0 — pin the SDK surface (0.5 day).** Read the installed `@modelcontextprotocol/sdk`: exact registration APIs (`tool`/`registerTool`/`setRequestHandler`), prompt API, roots API, and the StreamableHTTP DNS-rebinding option names. Lock the tree-sitter queries against real SDK code.
- **Phase 1 — front-end + highest-value rules (2–3 days).** `analyzer/ts/` scaffolding, `discover_tools_in_ts`, `treesitter_utils`, CLI dispatch, the `ts` extra, and the two rules with the best signal: **S-007 (command injection)** and **S-006 (path traversal)**. Prove an A-rule fires on a TS-captured JSON. Full tests.
- **Phase 2 — transport + logging (2 days).** **S-014 (HTTP bind/origin)** — the DNS-rebinding class, which is exactly the disclosure story, now cross-language — and **S-011 (sensitive logging)**.
- **Phase 3 — the long tail (1–2 days).** **S-013 (prompt interpolation)** and **S-012 (roots)**; optionally a Node/TS-compiler precision backend if tree-sitter proves too coarse anywhere.

Total ≈ **6–9 focused days** for parity on the 6 source rules, with a usable, shippable tool at the end of Phase 1.

## Risks / unknowns to resolve in Phase 0

- **SDK API variance** — `tool` vs `registerTool` vs low-level `setRequestHandler`; multiple SDK major versions in the wild. Mitigation: detect all high-level shapes; treat low-level switch handlers as best-effort v2.
- **Zod schema extraction** from source is fiddly; deferred by relying on runtime capture for the definition rules.
- **tree-sitter coarseness** — no types/imports. Accept syntactic matching (matches the Python analyzer's own precision); escalate a specific rule to the Node/TS-compiler backend only if it proves too noisy.
- **TSX/JSX and plain JS** — the language-pack has `tsx`/`javascript` grammars; pick the grammar by extension.
