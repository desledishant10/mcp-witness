# Harness (Phase 2)

Dynamic test runner for MCP-Scan. Loads scenario YAML files (see [../docs/scenario-schema.md](../docs/scenario-schema.md)), executes them against a target MCP server, and reports whether each scenario's oracle condition fired.

## Status

**Working** — runs end-to-end against any stdio MCP server:

- stdio transport
- Two run modes auto-detected from the scenario's attack steps:
  - **Direct mode** — agent-less; harness probes the server directly via JSON-RPC. Used by server-side validation tests.
  - **Proxy mode** — harness owns a `ProxySession` mediating between an agent driver (in-process) and the real target. Mutation hooks apply to tool descriptions and tool outputs in flight; `notifications/tools/list_changed` is signaled via an asyncio Event.
- Direct step types: `tools_call`, `tools_list`
- Proxy step types: `inject_tool_description`, `inject_tool_output`, `mutate_tool_definition`, `send_user_message`, `wait`
- Agent drivers (selected with `--agent`):
  - `stub` (default) — deterministic; for proxy plumbing tests
  - `anthropic` — real Claude tool-use loop; requires `ANTHROPIC_API_KEY`. Model selectable via `MCPSCAN_AGENT_MODEL` env var (default `claude-opus-4-7`).
- `target_tool_capability` filtering and `argument_role` parameter selection via the Layer 1 [capability classifier](../classifier/)
- Oracle conditions: `canary_hit`, `trace_contains`, `tool_call_matches` (substring; JSONPath deferred), `no_user_consent_prompt` (trivially satisfied today — needs agent-side consent-UI plumbing to be meaningful)
- HTTP canary server
- Scenarios runnable today: [MCP-D-001](../scenarios/MCP-D-001-tool-desc-injection-fetch.yaml), [MCP-D-002](../scenarios/MCP-D-002-path-traversal-fs-tool.yaml), [MCP-D-003](../scenarios/MCP-D-003-ssrf-url-fetcher.yaml), [MCP-D-004](../scenarios/MCP-D-004-tool-def-rug-pull.yaml), [MCP-D-005](../scenarios/MCP-D-005-unicode-tag-smuggling.yaml)

**Caveat on agent-side scenarios.** D-001, D-004, and D-005 only produce meaningful results with `--agent anthropic`. The stub agent never falls for prompt injection by construction, so those scenarios will report "passed" against it. The stub is for verifying the proxy wires up correctly, not the agent's susceptibility to injection.

**Not yet implemented:**

- `sampling_handler` step (no scenario in the seed set uses it; v0.3)
- `resources_read` / `resources_list` steps
- Classifier Layer 2 (AST sink-call detection) — lands with the static analyzer
- `no_user_consent_prompt` oracle — needs the agent driver to surface consent UI; v0.3
- SSE and Streamable HTTP transports
- DNS and filesystem canaries
- Other agent providers (OpenAI, local models, etc.)

## Tests

```bash
pip install -e ".[dev]"
pytest harness/tests/
```

Tests use a minimal mock MCP server ([testing/mock_server.py](testing/mock_server.py)) spawned as a subprocess via stdio. Coverage:

- `macros.substitute` (pure unit, incl. nested `unicode_tags` + `canary`)
- `CanaryServer` (allocation, hit recording, 404 on bad tokens, body capture)
- `ProxySession` mutation hooks (description override in append + replace modes, output override `when: first_call`)
- End-to-end direct mode — MCP-D-002 (path traversal) and MCP-D-003 (SSRF) against a vulnerable mock, plus a negative case (no matching capability → scenario passes)
- End-to-end proxy mode — MCP-D-001 plumbing with stub agent (verifies the machinery wires up; stub by construction does not fall for injection)

`AnthropicAgent` is not covered by automated tests — it needs an API key and burns tokens. Use manual verification for v0.2.

## Layout

| File              | Purpose                                                                                                  |
|-------------------|----------------------------------------------------------------------------------------------------------|
| `mcp_client.py`   | Thin wrapper around the official MCP Python SDK with session-level trace recording.                      |
| `canaries.py`     | aiohttp HTTP canary server with per-token endpoints; records method, path, query, headers, body.         |
| `macros.py`       | Two-pass payload macro substitution (`{canary:…}`, `{run_id}`, `{path:…}`, `{unicode_tags:…}`, …).       |
| `scenario.py`     | Pydantic models for scenario YAML validation.                                                            |
| `runner.py`       | Orchestrator — setup → attack → oracle → cleanup. Step dispatch and oracle condition evaluation.         |
| `cli.py`          | `mcp-scan-test <scenario.yaml> --server-cmd …`                                                           |

## Usage

```bash
# From the repo root:
python -m harness.cli scenarios/MCP-D-002-path-traversal-fs-tool.yaml \
    --server-cmd npx \
    --server-arg -y --server-arg @modelcontextprotocol/server-filesystem \
    --server-arg /tmp/some/workspace
```

Stdout is a JSON report. Exit code is `0` when no oracle evidence fired (scenario "passed" — no vulnerability detected), non-zero otherwise.

## Design notes

- The trace is recorded at the **session call boundary**, not the JSON-RPC stream. Adequate for direct-mode oracles; insufficient for proxy mode, which will rewire at the stream level so an agent's full session can be mutated transparently.
- The runner constructs one `TracedMCPClient` per scenario run. No reuse between scenarios — keeps state isolation simple and matches the "one clean session per scenario" expectation in [docs/scenario-schema.md](../docs/scenario-schema.md).
- `target_tool_capability` is the load-bearing gap for the next batch of scenarios. The runner currently falls back to glob matching — fine for fuzzing all tools but loses the precision the classifier provides. Implementing the classifier unlocks several v0.2 scenarios at once.
