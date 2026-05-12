# Classifier

Shared capability classifier used by [harness/](../harness/) (Phase 2) and the planned static analyzer (Phase 1). Spec: [../docs/capability-classifier.md](../docs/capability-classifier.md).

## v0.1 status

**Implemented — Layer 1 (lexical / heuristic):**

- `classify_tool(tool: dict) -> ToolClassification` — per-tool capability tags + parameter roles + confidence + evidence
- `classify_server(tools: list) -> ServerClassification` — aggregate + overbroad-combination detection
- `python -m classifier <file.json>` — CLI for ad-hoc classification
- 11 smoke tests in `tests/`

**Not yet implemented:**

- Layer 2 (AST sink-call detection on Python / TypeScript handler source) — lands with the static analyzer
- Layer 3 (LLM fallback for low-confidence cases) — opt-in via flag
- Calibration corpus + lexicon tuning (see [spec §Calibration plan](../docs/capability-classifier.md#calibration-plan))

## Layout

| File              | Purpose                                                                                |
|-------------------|----------------------------------------------------------------------------------------|
| `classify.py`     | `classify_tool`, `classify_server`, parameter classifier, scoring logic                |
| `lexicons.py`     | Hand-curated keyword and pattern tables; versioned with the spec                       |
| `types.py`        | Dataclasses for output (`ToolClassification`, `CapabilityFinding`, `ParameterRole`, …) |
| `__main__.py`     | CLI entry                                                                              |
| `tests/`          | Smoke tests covering the obvious capability and role detection paths                   |

## Confidence model

- Two or more distinct signal kinds firing → `high` (independent agreement)
- One strong signal (`name_combo` or `desc_pattern`) → `medium`
- Single weak signal only (`name_token`, partial param-name match) → `low`
- Layer 3 LLM outputs would map to `inferred`

Consumers pick their threshold. Today:
- Harness `target_tool_capability` filter: `high` + `medium`
- Static rule MCP-S-005 (overbroad surface): `high` only
- Audit reports: include all, label confidence visibly

## Usage

```bash
# Classify a single tool definition over stdin:
echo '{"name":"read_file","description":"Reads a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}' \
    | python -m classifier

# Classify a server's tools/list output:
python -m classifier server_tools.json
```

## Running the tests

```bash
pip install -e ".[dev]"      # quote for zsh; bash also accepts unquoted
pytest classifier/tests/
```
