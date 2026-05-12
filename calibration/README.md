# Calibration corpus

Real-server evaluation harness for the [classifier](../classifier/) and [analyzer](../analyzer/). Goal: turn lexicon and rule tuning from gut-feel into measurable precision and recall against hand-labeled ground truth, per the calibration plan in [docs/capability-classifier.md](../docs/capability-classifier.md#calibration-plan).

## Workflow

The fastest way to add a new target — three commands plus one round of hand-labeling:

```bash
# 1. Capture the server's tools/list:
mcp-scan-capture --server-cmd python --server-arg -m --server-arg some_server \
    -o /tmp/captured.json

# 2. Scaffold a ground-truth skeleton:
mcp-scan-scaffold-gt /tmp/captured.json --name some_server --language python \
    --source https://github.com/.../some_server \
    -o ground_truth/some_server.yaml

# 3. Hand-edit ground_truth/some_server.yaml — populate `capabilities`,
#    `parameter_roles`, and `known_vulns` for each tool. Names,
#    descriptions, and input schemas are already filled in by step 2.

# 4. Run the eval:
mcp-scan-eval-calibration some_server
# Or against the whole corpus:
mcp-scan-eval-calibration --all
```

The judgment calls — what capability each tool has, what role each parameter plays, which static rules should fire — stay with the human auditor. The scaffolder removes the rote transcription work.

For targets you cannot run locally (transport mismatch, missing credentials, paid service), transcribe the `tools/list` shape into a JSON file manually and skip step 1.

## Aggregation, tuning, and "stable" promotion

5. **Aggregate.** Once 3+ targets are labeled, run `mcp-scan-eval-calibration --all` for cross-target precision/recall. The per-tool diffs list the actionable gaps.
6. **Tune.** Where the report shows gaps, edit [classifier/lexicons.py](../classifier/lexicons.py) (or the analyzer rules) and re-run. Commit the updated JSON report under `reports/` alongside the lexicon change so the diff is reviewable.

## Hand-labeling rubric

For each tool, fill in:

- `capabilities` — capability tags the tool genuinely has (auditor judgment, not implementation behavior). A tool whose description says "deletes records from a table" is `db_write` regardless of how its body is coded.
- `parameter_roles` — semantic role of each *interesting* parameter (`path`, `url`, `command`, `query`, `host`, `content`). Skip params that fall into the catch-all `text` / `id` buckets unless documenting one matters.
- `known_vulns` — static-rule IDs that *should* fire on this tool (e.g. `[MCP-S-006]` if it has a known path-traversal bug). Used by the upcoming analyzer-side eval.

## Ground-truth schema

```yaml
target_name: <slug>                 # must match the filename basename
source: <URL or filesystem path>
language: python | typescript | rust | other
mcp_spec_version: "2025-06-18"
notes: <free text>

tools:
  - name: <tool_name>
    description: <description as a user/auditor sees it>
    input_schema:
      type: object
      properties:
        <param>: { type: string, ... }
    capabilities: [<tag>, ...]      # auditor's labels
    parameter_roles:
      <param>: <role>
    known_vulns: [<rule_id>, ...]   # e.g. [MCP-S-006]
```

A tool may have zero capabilities — that's a meaningful label (the auditor saw nothing dangerous). Empty `parameter_roles` is also fine if every parameter is uninteresting.

## Acceptance criteria for "v0.1 stable"

Before any classifier rule or analyzer rule promotes from experimental to stable:

- ≥10 targets in `labeled` status (mix of Python and TypeScript)
- Per-tag precision ≥0.9 on `high`-confidence classifier outputs
- Overall capability recall ≥0.75 across the corpus
- Aggregated report committed under `reports/`

The included [example_server](ground_truth/example_server.yaml) is the analyzer's own fixture — useful for verifying the workflow but not sufficient on its own.

## Layout

| Path                 | Purpose                                                       |
|----------------------|---------------------------------------------------------------|
| `targets.yaml`       | Planned corpus, each with a status                            |
| `ground_truth/*.yaml`| Hand-labeled tool definitions, one file per target            |
| `reports/*.json`     | Eval output, committed for diff-tracking lexicon changes      |
| `eval.py`            | The evaluation script and CLI                                 |
| `tests/`             | Smoke tests against the example_server target                 |

## Reading a report

```text
Target: example_server  (9 tools)

Per-tag capability metrics:
  Tag                    TP   FP   FN    Prec    Recl
  exec                    4    0    0    1.00    1.00
  fs_read                 3    0    1    1.00    0.75

Parameter role accuracy: 8/9 (88.89%)

Per-tool diffs (predicted vs ground truth):
  vulnerable_desc_injection:
    missing:  ['fs_read']
```

- **TP / FP / FN** count tool-tag pairs (a tool labeled `[fs_read, net_egress]` contributes to two tags).
- **Precision** answers "when I predict X, how often am I right?" — `MCP-S-005` (overbroad surface) acts on `high`-confidence only, so this is the most important number for that rule.
- **Recall** answers "of all the X tools, how many did I catch?" — matters for audit completeness.
- **Per-tool diffs** are what you actually act on: each `missing` line suggests a lexicon improvement, each `spurious` line suggests a tightening.
