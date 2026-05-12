# Capability Classifier (v0.1)

## Purpose

Both the static analyzer (Phase 1) and the dynamic harness (Phase 2) need to label MCP tools with **capability tags** ("what dangerous thing does this tool let you do?") and **parameter roles** ("what kind of value does each parameter take?"). The classifier is the shared component that produces these labels. It is the load-bearing dependency for:

- Static rule `MCP-S-005` (Overbroad capability surface) and several others
- Dynamic scenarios using `target_tool_capability` (MCP-D-002, D-003, D-005, and most planned v0.2 scenarios)
- Dynamic scenarios using `argument_role` (same set)
- Audit-phase reporting (per-server capability heatmap)

A bug in the classifier propagates into every consumer. Calibration matters more than novelty here.

## Capability tag vocabulary (v0.1)

Closed set. Adding a new tag is a versioned change to this document.

| Tag             | Meaning                                                                                                            | Indicative names                                                  |
|-----------------|--------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| `exec`          | Executes arbitrary code, shell commands, or scripts on the host or in a sandbox.                                   | `run_command`, `python_eval`, `shell_exec`, `bash`                |
| `fs_read`       | Reads files or directory listings from the host filesystem.                                                        | `read_file`, `list_files`, `cat`, `grep`, `glob`                  |
| `fs_write`      | Creates, modifies, or deletes files or directories.                                                                | `write_file`, `delete`, `rename`, `chmod`, `mkdir`                |
| `net_egress`    | Makes outbound network requests (HTTP, raw TCP, DNS, etc.). Includes webhooks, scraping, third-party API calls.    | `fetch_url`, `http_request`, `send_webhook`, `download`           |
| `net_ingress`   | Opens a listening socket or accepts inbound connections. Rare in tool surface; relevant for transport surface.     | n/a for tools; the SSE/HTTP transport itself                      |
| `secret_access` | Reads sensitive material: env vars (sensitive keys), credential files, OS keychain, secret managers, `.env`.       | `get_env`, `read_credential`, `keychain_lookup`                   |
| `db_query`      | Reads from a database (SQL `SELECT` or NoSQL equivalent).                                                          | `pg_query`, `mongo_find`, `redis_get`                             |
| `db_write`      | Modifies a database (INSERT/UPDATE/DELETE/DDL or equivalent).                                                      | `pg_execute`, `mongo_insert`, `redis_set`                         |

Tags are not exclusive. A single tool may carry several — e.g. a `code_review` tool can be `fs_read` + `net_egress` simultaneously, and that combination is itself a finding (see [Aggregation rules](#aggregation-rules)).

## Parameter role vocabulary (v0.1)

| Role      | Meaning                                                       | Used by scenarios for             |
|-----------|---------------------------------------------------------------|-----------------------------------|
| `path`    | Filesystem path (absolute or relative).                       | Path-traversal probes (MCP-D-002) |
| `url`     | URL (any scheme).                                             | SSRF probes (MCP-D-003)           |
| `command` | Shell command or argv array.                                  | Command-injection probes          |
| `query`   | SQL or other query-language string.                           | SQLi probes                       |
| `host`    | Hostname or IP without scheme.                                | Host-based probes                 |
| `content` | Free-form payload body (file contents, message body, etc.).   | Content-injection scenarios       |
| `text`    | Generic text with no security-sensitive role inference.       | Catch-all for low-interest params |
| `id`      | Opaque identifier (numeric ID, UUID, slug).                   | Catch-all                         |

`text` and `id` are the "uninteresting" bucket; every other role is a probe target for at least one scenario class.

## Input modes

**Mode A — Tool definition only.** What `tools/list` returns: `name`, `description`, `inputSchema` (including all nested string fields). This is the only thing the dynamic harness has against a black-box target.

**Mode B — Tool definition plus implementation source.** The static analyzer additionally passes the AST of the handler function. Enables higher-confidence labels because real sink calls (`subprocess.run`, `requests.get`, etc.) are observable.

Output schema is identical between modes — only the confidence levels and evidence fields differ.

## Detection layers

The classifier runs as a pipeline. Each layer may add tags, raise confidence, or demote prior outputs.

### Layer 1 — Lexical / heuristic (always on)

Operates over `name`, `description`, parameter names, parameter descriptions, and schema annotations. No source required.

- **Name tokenization.** Split `snake_case` and `camelCase`, lowercase. (Optional lemmatization is a v0.2 nice-to-have; not required for v0.1.) Match tokens against per-tag lexicons.
- **Description keyword scan.** Search descriptions for capability-indicative phrases. Per-tag lexicons are versioned alongside this doc in `classifier/lexicons/`.
- **Parameter-name → role map.** Dictionary lookup: `path | file | filename | filepath | dir → path`; `url | uri | link | endpoint → url`; `cmd | command | argv → command`; `query | sql | filter → query`; `host | hostname | server → host`; `body | content | data | payload → content`.
- **Schema-format signals.** `format: uri` → `url`; `format: hostname` → `host`; `format: ipv4`/`ipv6` → `host`; etc.

Default output confidence: `medium`. Promoted to `high` only when **multiple independent signals agree** (e.g. name `read_file` AND param `path` AND description mentions "reads the file at the given path").

### Layer 2 — AST / source-aware (static analyzer only)

When the handler AST is available, look for **sink calls** within it:

| Sink (Python / TypeScript)                                                            | Implies capability  |
|---------------------------------------------------------------------------------------|---------------------|
| `open()`, `pathlib.Path(...).read_*`, `fs.readFile`, `fs.createReadStream`            | `fs_read`           |
| `open(..., 'w')`, `fs.writeFile`, `fs.unlink`, `shutil.rmtree`                        | `fs_write`          |
| `requests.*`, `httpx.*`, `urllib.request.urlopen`, `aiohttp.*`, `fetch`, `axios.*`    | `net_egress`        |
| `subprocess.*`, `os.system`, `os.popen`, `child_process.exec/execFile/spawn`          | `exec`              |
| `os.environ[...]`, `process.env.*` (sensitive-key allowlist), keyring/keychain SDKs   | `secret_access`     |
| `cursor.execute(SELECT...)`, `conn.query`, `db.collection(...).find`                  | `db_query`          |
| `cursor.execute(INSERT/UPDATE/DELETE/DDL)`, ORM `.save()`/`.delete()`, raw write APIs | `db_write`          |

Promotion rule: a Layer 1 tag confirmed by Layer 2 evidence → confidence `high`. A Layer 1 tag with no corresponding sink → confidence demoted to `low` plus a `weak_signal` warning. Tags Layer 1 missed but Layer 2 found are added with confidence `medium` (the AST is strong evidence, but Layer 1 disagreement is a yellow flag).

Layer 2 is intra-procedural in v0.1 — it does not follow calls into local helpers. Inter-procedural taint is a v0.2 goal.

### Layer 3 — LLM classifier (opt-in)

Behind `--llm-classifier`. Sends the tool definition (and, in Mode B, the handler source) to a model with a structured-output prompt. Used only when:

- Layer 1 produced `low` confidence, AND
- Either Mode A is in effect, or Layer 2 also produced `low`

Cost is bounded: at most one LLM call per tool per scan, results cached by content hash. Output is normalized to `inferred` confidence regardless of the model's self-reported confidence — we do not trust LLM calibration.

## Confidence levels

| Level      | Meaning                                                                                                              |
|------------|----------------------------------------------------------------------------------------------------------------------|
| `high`     | Multiple independent signals agree, or AST evidence directly observed.                                               |
| `medium`   | Single strong signal (e.g. param name `path` + description mentions reading files), no contradicting evidence.       |
| `low`      | Inferred from weak signals only, or signals partially conflict. Reported but most downstream rules skip these.       |
| `inferred` | LLM classifier produced this label. Treated as `medium` for filtering but tagged separately in reports.              |

Downstream consumers choose which levels to act on:
- `MCP-S-005` (overbroad surface): `high` only — false positives here are user-hostile.
- Dynamic harness `target_tool_capability` matcher: `high` and `medium` by default. CLI flag `--include-low` extends to `low`.
- Audit reports: include all levels with confidence visibly tagged.

## Output format

Per tool:

```json
{
  "tool_name": "read_file",
  "capabilities": [
    {
      "tag": "fs_read",
      "confidence": "high",
      "evidence": [
        "name_token:read",
        "name_token:file",
        "param:path:role=path:confidence=high",
        "ast_sink:open()@src/tools/files.py:23"
      ]
    }
  ],
  "parameter_roles": {
    "path":     { "role": "path", "confidence": "high",   "evidence": ["param_name:path"] },
    "encoding": { "role": "text", "confidence": "medium", "evidence": ["param_name:encoding"] }
  },
  "classification_mode": "B"
}
```

Per server, an aggregate object adds:

```json
{
  "server_capability_set": ["fs_read", "fs_write", "net_egress"],
  "overbroad_combinations": [
    {
      "tags": ["fs_read", "net_egress"],
      "tools": ["read_file", "fetch_url"],
      "rationale": "exfil_pair"
    }
  ]
}
```

`overbroad_combinations` is what drives `MCP-S-005` findings.

## Aggregation rules

Combinations flagged at the server level:

| Combination                                        | Risk pattern                                |
|----------------------------------------------------|---------------------------------------------|
| `fs_read` + `net_egress`                           | Data exfil via file upload                  |
| `secret_access` + `net_egress`                     | Credential exfil                            |
| `db_query` + `net_egress`                          | Database exfil                              |
| `fs_write` + `exec`                                | Write-then-execute RCE                      |
| `fs_write` + `net_egress` over writable code paths | Self-modifying agent persistence            |
| `db_query` + `db_write` on the same DB             | Full DB compromise on injection             |

Combinations table is versioned with the doc and may grow.

## Calibration plan

Before any rule or scenario depending on the classifier promotes to `stable`:

1. Assemble a corpus of ≥30 real MCP server implementations (target mix: 15 popular open-source servers, 10 SDK / reference examples, 5 known-vulnerable cases from prior research such as Invariant Labs).
2. Hand-label the ground-truth capability set and parameter roles for each tool.
3. Measure per-tag precision and recall at each layer (1 alone, 1+2, 1+2+3).
4. Tune lexicons until: per-tag precision ≥90% on `high`-confidence outputs, overall recall ≥75% across the corpus.
5. Publish results and the corpus list in `docs/classifier-eval.md`.

The same corpus serves as the broader analyzer's FP/FN baseline (see [static-rules.md](static-rules.md) §Rule lifecycle).

## Extension points

- **New capability tag.** Requires: vocabulary entry, Layer 1 lexicon updates, Layer 2 sink list (if applicable), aggregation-table update (if combinations apply), corpus relabel for any affected tools.
- **New parameter role.** Requires: vocabulary entry, parameter-name dictionary update, schema-format signal list update, scenario authors opt-in.
- **Per-language Layer 2 backend.** Adding Go / Rust MCP server analysis means a new AST visitor and a sink-call table for that language. Output schema does not change.

## Out of scope for v0.1

- Inter-procedural taint tracking in Layer 2.
- Cross-server combination analysis (only flagged within one server). Cross-server confused-deputy lives in the harness, not the classifier.
- Active learning / confidence calibration via labeled disagreement. The corpus-and-tune approach is intentionally simple.
- Capability inference from runtime behavior (e.g. observe what the tool actually does on a probe call). Possible v0.2 idea, but introduces ethical questions for the audit phase.
