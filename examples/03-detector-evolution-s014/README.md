# Example 03 — Detector evolution: how W1–W4 caught what v0.1 missed

A more advanced example. The story of how MCP-S-014 evolved from the original v0.1 implementation through four patches (W1–W4), each motivated by a real-world DNS-rebind target the v0.1 detector silently missed. This example doesn't run a fresh scan — instead it walks through four small Python fixtures that demonstrate what each patch is for.

## Background

MCP-S-014 detects DNS rebinding via missing Origin/Host validation on HTTP-transport MCP servers. The v0.1 implementation handled the obvious case:

```python
# Obvious — string literal host. v0.1 catches.
uvicorn.run(app, host="0.0.0.0", port=3000)
```

But real packages don't write it that way. The four DNS-rebind targets from the [survey](../../findings/2026-05-12-dns-rebinding-survey.md) each used a slightly different bind shape, and the v0.1 detector slipped past all four. Four patches later (W1–W4), each one demonstrates a different real-world pattern.

## Fixtures

The four files in this directory each contain a *vulnerable* bind pattern modeled on one of the four surveyed packages. The v0.1 detector misses them all; the v0.3 detector with W1–W4 catches them all.

| Fixture | Modeled on | Patch needed |
|---|---|---|
| `w1_host_variable.py` | `mcp-streamablehttp-proxy`, `fastmcp-http` | W1 — function-default → variable resolution |
| `w2_origin_in_comment.py` | (regression test for the W2 tightening) | W2 — AST-based Origin check |
| `w3_aiohttp_tcpsite.py` | `mcp-server-fetch-sse` | W3 — aiohttp `web.TCPSite` bind shape |
| `w4_env_var_default.py` | `mcp-fetch-streamablehttp-server` | W4 — `os.getenv(..., default)` resolution |

## Run the analyzer over each fixture

```bash
mcpsentry-analyze w1_host_variable.py
mcpsentry-analyze w2_origin_in_comment.py
mcpsentry-analyze w3_aiohttp_tcpsite.py
mcpsentry-analyze w4_env_var_default.py
```

Each should fire `MCP-S-014` (HIGH). On the v0.1 detector, none of them would have fired.

## Why these patches were needed

### W1 — Host variable resolution

v0.1 only resolved string-literal `host` arguments. Patterns like `uvicorn.run(app, host=host, port=...)` where `host` was set earlier — via module-level assignment or as a function-parameter default — slipped through silently.

Fix: a pre-pass `_collect_string_bindings(tree)` walks the file and produces a `{name: literal_string}` map from `ast.Assign` and `FunctionDef.args.defaults`. The bind-shape rule then threads that map and resolves `ast.Name` arguments.

### W2 — AST-based Origin suppression

v0.1 silenced the rule when a substring `origin` appeared *anywhere* in the file. Comments, response-header literals, and even LLM-prompt strings containing `origin` all qualified for suppression.

Fix: `_file_validates_origin(tree)` walks the AST for actual *request-header reads*: `request.headers["Origin"]` (subscript) or `request.headers.get("Origin", ...)` (method call). Comments and string literals no longer suppress.

### W3 — aiohttp bind shapes

v0.1 only knew about `uvicorn.run` and `app.run`. aiohttp's `web.run_app` (keyword-host) and `web.TCPSite` (positional-host) bind shapes weren't recognized.

Fix: extended `_SERVER_BIND_METHODS` to include both.

### W4 — Env-var default resolution

`host = os.getenv("HOST", "0.0.0.0")` is a common production-shaped pattern — the env-var fallback **is** the deployed bind. v0.1's binding pre-pass only resolved literal string assignments, not function-call results.

Fix: `_extract_env_default(call)` recognizes `os.getenv(name, default)` and `os.environ.get(name, default)` and resolves the literal second-arg default. `_collect_string_bindings` calls it for `Assign` nodes whose value is a `Call`.

## The lesson

The detector evolved with the survey. Each W-patch is a piece of detector logic that the survey work itself surfaced. Listing them honestly — including "the v0.1 detector missed 4 of 4 surveyed packages" — is more useful than pretending the rule was right from the start. Anyone else writing a similar rule should expect their detector to be insufficient until real-world targets teach it what it needs to know.

Full detector-evolution narrative: [docs/static-rules.md §MCP-S-014 → Detector evolution: W1–W4 patches](../../docs/static-rules.md#detector-evolution-w1w4-patches).
