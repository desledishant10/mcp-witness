# Analyzer (Phase 1)

Static analyzer for MCP servers. Spec: [../docs/static-rules.md](../docs/static-rules.md).

## Status

**Implemented (Layer 1 — Python AST + captured JSON):**

- Tool discovery via FastMCP-style decorator pattern (`@something.tool` / `@something.tool()`) over `.py` files
- Tool discovery from captured `tools/list` JSON (`mcp-scan-analyze captured.json`)
- 6 of 14 v0.1 rules:
  - **MCP-S-001** — Imperative instructions in tool description (heuristic; calibration-tuned against real `mcp-server-fetch`)
  - **MCP-S-002** — Cross-tool reference in tool description (naming-based poisoning; server-level rule)
  - **MCP-S-003** — Hidden instructions in schema sub-fields (parameter descriptions, titles, `$comment`; catches real `mcp-server-time` pattern)
  - **MCP-S-005** — Overbroad capability surface (server-level; wraps classifier's `overbroad_combinations`)
  - **MCP-S-006** — Path traversal in file-handling tool (intra-procedural AST inspection)
  - **MCP-S-007** — Shell command injection in tool handler (subprocess with `shell=True`, `os.system`, `os.popen`)
- `mcp-scan-analyze <path>` CLI with text and JSON output, severity filtering, and CI-friendly exit codes (`--fail-on`)
- Scenario YAML linter — `mcp-scan-lint-scenarios scenarios/` — catches the null-byte-smuggling class of bug + parse errors + schema violations

**Not yet implemented:**

- The other 11 rules in the v0.1 spec (S-002 through S-014, excluding S-001/006/007)
- TypeScript support — requires tree-sitter, planned for v0.2
- Low-level `Server.list_tools()` discovery pattern (only FastMCP decorators today)
- Inter-procedural taint tracking — current S-006 only follows direct calls inside the tool function

## Layout

| File                | Purpose                                                                                      |
|---------------------|----------------------------------------------------------------------------------------------|
| `discover.py`       | Walks a path, parses Python files with `ast`, finds `@.tool` decorated functions             |
| `rules.py`          | The three detection rules, plus the rule registry                                            |
| `analyze.py`        | `analyze_path()` — orchestrator: discover then run all rules                                 |
| `types.py`          | `Finding`, `DiscoveredTool` dataclasses                                                      |
| `__main__.py`       | CLI                                                                                          |
| `lint_scenarios.py` | YAML lint tool (separate CLI: `mcp-scan-lint-scenarios`)                                     |
| `tests/`            | Rule fixtures (vulnerable + safe examples) + tests; scenario-lint tests                      |

## Usage

```bash
# Analyze an MCP server source tree:
mcp-scan-analyze /path/to/some-mcp-server

# JSON output, gate at high severity:
mcp-scan-analyze --format json --fail-on critical ./src

# Lint scenario files:
mcp-scan-lint-scenarios scenarios/
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest analyzer/tests/
```

## False-positive expectations

Layer 1 is heuristic. Expected v0.1 precision (vibes-tuned, not corpus-tuned):

- **S-001**: medium-high precision on imperative-pattern hits; the URL-in-description sub-rule is more permissive and tagged `medium` for that reason.
- **S-006**: high precision when path-typed parameters exist; the `_PATH_GUARD_ATTRS` list captures the common patterns (`is_relative_to`, `resolve`, `realpath`, `commonpath`, `startswith`). Helpers in separate functions are not yet followed (inter-procedural is v0.2).
- **S-007**: high precision on direct `shell=True` / `os.system` / `os.popen` usage. Does not yet trace taint from tool params; flags any usage in a tool function body.
