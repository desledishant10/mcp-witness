# MCP-Scan

[![tests](https://github.com/desledishant10/mcp-scan/actions/workflows/tests.yml/badge.svg)](https://github.com/desledishant10/mcp-scan/actions/workflows/tests.yml)
[![license: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![python: 3.11+](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![findings: 8](https://img.shields.io/badge/findings-8-orange)](findings/)
[![corpus: 10 targets](https://img.shields.io/badge/corpus-10_targets_stable-green)](calibration/ground_truth/)

> Security scanner for Model Context Protocol servers and AI agents.

Finds vulnerabilities in MCP server implementations and tests AI agents against documented attack patterns. Static analyzer + dynamic harness + calibration corpus, all driven by a shared capability classifier.

**Status:** alpha. 88 tests passing, 6 analyzer rules implemented, 5 calibration targets at 100% precision/recall, and a small but growing [findings/](findings/) corpus of real-world results — including one environment-dependent SSRF finding in an Anthropic reference server.

## Real findings to date

Eight documented audit observations against seven PyPI-published servers, captured in [findings/](findings/):

| Date | Target | Test | Outcome |
|---|---|---|---|
| 2026-05-11 | `mcp-server-fetch` | [D-003 (direct SSRF probe)](findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md) | **Vulnerability** — env-dependent SSRF, **demonstrated on EC2 2026-05-12** (real IAM credentials retrieved); **disclosure filed 2026-05-12 as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143)** (embargo 2026-08-10) |
| 2026-05-11 | `mcp-server-http-request` | [D-003 (direct SSRF probe)](findings/2026-05-11-MCP-D-003-http-request-direct-environment-dependent-ssrf.md) | **Vulnerability** — second instance of same SSRF class, different vendor |
| 2026-05-11 | `mcp-server-fetch` | [D-001 against Claude Opus 4.7](findings/2026-05-11-MCP-D-001-fetch-opus47-defense.md) | Defense |
| 2026-05-11 | `mcp-server-fetch` | [D-006 against Claude Opus 4.7](findings/2026-05-11-MCP-D-006-fetch-opus47-defense.md) | Defense |
| 2026-05-11 | `mcp-server-time` | [S-003 static, 3 hits](findings/2026-05-11-MCP-S-003-time-static-param-injection-pattern.md) | Info (pattern present; benign in this deployment) |
| 2026-05-11 | `mcp-server-git` | [D-002 (direct path-traversal)](findings/2026-05-11-MCP-D-002-git-direct-defense.md) | Defense (defense-in-depth example) |
| 2026-05-11 | `mcp-server-aidd` | [D-002 (direct path-traversal)](findings/2026-05-11-MCP-D-002-aidd-direct-defense.md) | Defense (allowed-directory containment working) |
| 2026-05-11 | `mcp-server-aidd` | [S-001 + S-002 + S-005 (static, multi-hit)](findings/2026-05-11-aidd-three-rule-multi-hit.md) | Info (3 simultaneous rules — pattern stress test) |

Each entry includes reproduction commands, the raw trace, an interpretation, caveats, and a disclosure recommendation. **The fetch + http-request pair is the most actionable result** — two PyPI-published Python MCP servers, different vendors, same SSRF class. Disclosure-suitable.

## Quickstart — reproduce a real finding in three commands

```bash
# Install (editable):
git clone <repo> && cd mcp-scan
pip install -e ".[dev]"

# Capture the official Anthropic mcp-server-fetch:
pip install mcp-server-fetch
mcp-scan-capture --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch \
    -o captured.json

# Run static analysis:
mcp-scan-analyze captured.json
```

Output:

```
[HIGH] MCP-S-001  <captured>:0  fetch
    Tool description contains instruction-like phrasing directed at the model.
    | ou internet access. Now you can fetch the most up-to-date information and let the user know

1 finding.
```

That's the project's first real-world catch — the shipped tool description of `mcp-server-fetch` contains agent-directed phrasing that an attacker could use to override prior model alignment.

## What's inside

### CLIs

| Command | Purpose |
|---------|---------|
| `mcp-scan-capture` | Connect to any stdio MCP server, dump `tools/list` as JSON |
| `mcp-scan-scaffold-gt` | Generate a calibration ground-truth skeleton from a capture |
| `mcp-scan-analyze` | Static analysis — Python source or captured JSON |
| `mcp-scan-classify` | Run the capability classifier on a tool definition |
| `mcp-scan-eval-calibration` | Compare classifier predictions to hand-labeled ground truth |
| `mcp-scan-lint-scenarios` | YAML lint for scenario files (catches null-byte smuggling, parse errors, schema violations) |
| `mcp-scan-test` | Run a dynamic scenario against a real MCP server, optionally with a real LLM agent |

### Static analyzer rules (7 of 14 v0.1 rules implemented)

| ID | What it catches | Mode |
|----|---|---|
| `MCP-S-001` | Imperative phrasing in tool description (you-must, now-you-can, grants-you, were-advised) | per-tool, heuristic |
| `MCP-S-002` | One tool's description references another tool by name (poisoning vector) | server-level, heuristic |
| `MCP-S-003` | Hidden instructions in schema sub-fields (parameter descriptions, titles, `$comment`) | per-tool, heuristic |
| `MCP-S-005` | Overbroad capability surface (e.g. `fs_read` + `net_egress` = exfil pair) | server-level, classifier-driven |
| `MCP-S-006` | Path traversal in file-handling tool | per-tool, AST + taint |
| `MCP-S-007` | Shell command injection (`subprocess(shell=True)`, `os.system`, `os.popen`) | per-tool, AST |
| `MCP-S-009` | URL-fetching tool with no scheme/host allowlist (catches the SSRF class flagged dynamically by D-003) | per-tool, heuristic on tools/list |

Every rule's lexicon decisions are commented with the calibration evidence that drove them. Spec for all 14 rules: [docs/static-rules.md](docs/static-rules.md).

### Dynamic scenarios (7 in the seed set)

Scenario YAML format: [docs/scenario-schema.md](docs/scenario-schema.md). The seed set lives in [scenarios/](scenarios/) and is described in [scenarios/README.md](scenarios/README.md). Highlights:

- `MCP-D-002` — path traversal in filesystem-read tools (direct probe, no LLM needed)
- `MCP-D-003` — SSRF in URL-fetching tools (direct probe; produces the cloud-metadata finding)
- `MCP-D-001` / `MCP-D-006` — tool-description injection at two phrasing tiers (obvious vs subtle)
- `MCP-D-004` — tool-definition rug pull (mutate after first approval)
- `MCP-D-005` — invisible Unicode-tag-character injection via tool output
- `MCP-D-007` — cloud metadata-service exfiltration via URL-fetcher (strict oracle — only fires on actual metadata response content, designed for EC2/GCP/Azure audit verification)

### Capability classifier

Layer 1 (lexical) classifier shared by analyzer rules and harness scenario filtering. 8 capability tags, 8 parameter roles, three-tier confidence (`high` / `medium` / `low`). Per the [spec](docs/capability-classifier.md), promotion to "stable" requires ≥10-target corpus + ≥90% precision on `high`-confidence outputs.

**Current calibration corpus state:** 10 labeled targets, 81 tools, **100% precision and 100% recall on all four exercised capability tags** (`exec`, `fs_read`, `fs_write`, `net_egress`). Verified by direct capture against 8 of 10 targets. Hit the spec's ≥10-target / ≥0.9-precision / ≥0.75-recall "stable" threshold this session. See [calibration/README.md](calibration/README.md).

### Dynamic harness

Two modes auto-selected per scenario:
- **Direct mode** — agent-less, harness as MCP client. Used for server-side validation tests (path traversal, SSRF).
- **Proxy mode** — harness mediates between an agent under test and the real target, applying mutations to tool descriptions and outputs in flight. Used for agent-side scenarios (description injection, rug pull, output injection).

Two agent driver implementations: `stub` (deterministic, plumbing tests) and `anthropic` (real Claude tool-use loop). See [harness/README.md](harness/README.md).

## Architecture

```
mcp-scan/
  analyzer/      Static analysis: Python AST + captured-JSON modes, 6 rules
  classifier/    Capability tagger: 8 tags, 8 param roles, Layer 1 (lexical)
  harness/       Dynamic test runner: direct + proxy modes, stub + Claude agents
  scenarios/     Attack-scenario YAML library (6 in v0.1 seed set)
  calibration/   Ground-truth corpus + eval driver + capture/scaffold tools
  findings/      Audit-trail record (5 entries; append-only)
  docs/          Specs: rules, scenarios, classifier, threat model
```

## Roadmap and current state

| Phase | Planned window | Status |
|---|---|---|
| 1 — Static analyzer | weeks 1–6 | 7/14 rules implemented (S-001, S-002, S-003, S-005, S-006, S-007, S-009); Python AST + captured-JSON modes; CLI with severity filtering and CI-friendly exit codes |
| 2 — Dynamic harness | weeks 7–14 | Substantially complete: direct + proxy modes, two agent drivers, 6 scenarios runnable end-to-end against real servers |
| 3 — Real-world audit | weeks 15–20 | **Started.** 5 documented findings against 3 real Python servers from PyPI. Cloud reproduction of the SSRF finding is the next priority. |
| 4 — Polish + publish | weeks 21–26 | Not started. README and reference docs complete; blog/whitepaper and conference submission pending audit volume. |

## Scope and non-goals

In scope for v1:
- Static and dynamic vuln discovery in MCP server implementations
- Agent-level attack scenarios against spec-conformant servers
- Python servers (analyzer); any-language servers via captured `tools/list` JSON
- stdio transport (harness)
- MCP spec version `2025-06-18`

Not yet implemented (planned):
- TypeScript analyzer support (tree-sitter; would unlock 5 queued TS calibration targets)
- SSE / Streamable HTTP transports in the harness
- The other 8 analyzer rules from the v0.1 spec
- DNS / filesystem canaries (HTTP only today)

Out of scope for v1 (intentional — these are good follow-ups, not features):
- Runtime "agent firewall" / behavioral detection / EDR-for-agents
- Non-MCP agent frameworks (LangChain, AutoGPT, custom orchestrators)
- Production WAF-style protection
- Host-side hardening recommendations beyond what the scanner emits

## Project metrics

| | |
|---|---|
| Tests passing | **94 / 94** |
| Analyzer rules | 7 of 14 (S-001, S-002, S-003, S-005, S-006, S-007, S-009) |
| Dynamic scenarios | 7 (5 from v0.1 seed set + D-006 subtle-injection + D-007 cloud-metadata-exfil) |
| Calibration corpus | **10 labeled targets, 81 tools, 100/100 precision-recall** (8 verified by direct capture) — hit the spec's "stable" threshold |
| Real-world finding entries | 5 (1 vulnerability, 3 defense, 1 informational) |
| Packages | 5 (`analyzer`, `classifier`, `harness`, `calibration` + `scenarios` as YAML) |
| Console scripts | 7 |

## Running the test suite

```bash
pip install -e ".[dev]"
pytest
```

For dynamic scenarios that exercise a real LLM, install the optional Anthropic agent and set an API key:

```bash
pip install "mcp-scan[anthropic]"
export ANTHROPIC_API_KEY=sk-ant-...
mcp-scan-test scenarios/MCP-D-001-tool-desc-injection-fetch.yaml \
    --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch \
    --agent anthropic
```

## Methodology and threat model

Attack surface enumerated by MCP primitive (tools, resources, prompts, sampling, roots) plus transport and cross-cutting agent-level attacks. Every detection rule and every scenario carries a `category` field mapped back to this taxonomy. The categories and tag/role vocabularies live in:

- [docs/static-rules.md](docs/static-rules.md) — detection rules and lexicon decisions
- [docs/scenario-schema.md](docs/scenario-schema.md) — dynamic scenario YAML schema and step types
- [docs/capability-classifier.md](docs/capability-classifier.md) — capability tag and parameter role vocabularies, calibration plan

## Responsible disclosure

Findings against third-party servers follow coordinated disclosure: maintainers receive 90 days from notification before public release, extended if a fix is in active development. Reporters using MCP-Scan are expected to follow the same practice. See each finding entry's `## Disclosure` section for case-specific details.

A formal `SECURITY.md` with policy + contact will land before any disclosure is filed.

## Contributing

Issue discussion and ruleset/scenario proposals are welcome. Highest-leverage places to contribute right now:

1. **Label more calibration targets.** The corpus needs ≥10 labeled servers for the classifier to promote to `stable`. The workflow is press-button (`capture` → `scaffold-gt` → hand-label → `eval-calibration`). See [calibration/README.md](calibration/README.md).
2. **Propose new analyzer rules** following [docs/static-rules.md](docs/static-rules.md) §Rule lifecycle. Real-world evidence (from a captured server) is the bar for inclusion.
3. **Propose new dynamic scenarios** following [docs/scenario-schema.md](docs/scenario-schema.md). Same evidence bar.

## License

To be selected before first public release. Likely Apache 2.0.
