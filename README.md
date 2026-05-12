# MCP-Scan

[![tests](https://github.com/desledishant10/mcp-scan/actions/workflows/tests.yml/badge.svg)](https://github.com/desledishant10/mcp-scan/actions/workflows/tests.yml)
[![license: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![python: 3.11+](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![findings: 11](https://img.shields.io/badge/findings-11-orange)](findings/)
[![corpus: 10 targets](https://img.shields.io/badge/corpus-10_targets_stable-green)](calibration/ground_truth/)

> Security scanner for Model Context Protocol servers and AI agents.

Finds vulnerabilities in MCP server implementations and tests AI agents against documented attack patterns. Static analyzer + dynamic harness + calibration corpus, all driven by a shared capability classifier.

**Status:** alpha. **151 tests passing, all 14 v0.1 static-analyzer rules shipped**, 10-target calibration corpus at 100% precision/recall (stable per spec), and a growing [findings/](findings/) corpus of real-world results — including two confirmed SSRF disclosures (one in an Anthropic reference server, demonstrated end-to-end on EC2 with real IAM credentials retrieved).

## Real findings to date

Eleven documented audit observations against ten PyPI-published servers, captured in [findings/](findings/), plus a [DNS-rebinding survey](findings/2026-05-12-dns-rebinding-survey.md) that frames three of them as one class:

| Date | Target | Test | Outcome |
|---|---|---|---|
| 2026-05-11 | `mcp-server-fetch` | [D-003 (direct SSRF probe)](findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md) | **Vulnerability** — env-dependent SSRF, **demonstrated on EC2 2026-05-12** (real IAM credentials retrieved); **disclosure filed 2026-05-12 as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143)** (embargo 2026-08-10) |
| 2026-05-11 | `mcp-server-http-request` | [D-003 (direct SSRF probe)](findings/2026-05-11-MCP-D-003-http-request-direct-environment-dependent-ssrf.md) | **Vulnerability** — second instance of same SSRF class, different vendor; **disclosure email-filed 2026-05-12** to maintainers ([record](disclosures/2026-05-12-mcp-fetch-http-request-ssrf.md)) (embargo 2026-08-10) |
| 2026-05-12 | `mcp-streamablehttp-proxy` v0.2.0 | [S-014 (static, DNS rebinding)](findings/2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md) | **Vulnerability** — 127.0.0.1 + no Origin/Host check; universal escalation against whatever stdio MCP it proxies; coordinated disclosure [drafted](disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md) (embargo 2026-08-10) |
| 2026-05-12 | `mcp-fetch-streamablehttp-server` v0.2.0 | [S-014 (static, DNS rebinding + 0.0.0.0 + recursive SSRF)](findings/2026-05-12-MCP-S-014-fetch-streamablehttp-server-dns-rebinding.md) | **Vulnerability** — 0.0.0.0 (`# noqa: S104`) + wildcard CORS + inherited fetch SSRF; co-disclosed with proxy finding (embargo 2026-08-10) |
| 2026-05-12 | `fastmcp-http` v0.1.4 | [S-014 (static, DNS rebinding)](findings/2026-05-12-MCP-S-014-fastmcp-http-dns-rebinding.md) | **Vulnerability** — Flask dev server on 0.0.0.0, no middleware anywhere; disclosure pending GHSA-availability check (embargo 2026-08-10) |
| 2026-05-11 | `mcp-server-fetch` | [D-001 against Claude Opus 4.7](findings/2026-05-11-MCP-D-001-fetch-opus47-defense.md) | Defense |
| 2026-05-11 | `mcp-server-fetch` | [D-006 against Claude Opus 4.7](findings/2026-05-11-MCP-D-006-fetch-opus47-defense.md) | Defense |
| 2026-05-11 | `mcp-server-time` | [S-003 static, 3 hits](findings/2026-05-11-MCP-S-003-time-static-param-injection-pattern.md) | Info (pattern present; benign in this deployment) |
| 2026-05-11 | `mcp-server-git` | [D-002 (direct path-traversal)](findings/2026-05-11-MCP-D-002-git-direct-defense.md) | Defense (defense-in-depth example) |
| 2026-05-11 | `mcp-server-aidd` | [D-002 (direct path-traversal)](findings/2026-05-11-MCP-D-002-aidd-direct-defense.md) | Defense (allowed-directory containment working) |
| 2026-05-11 | `mcp-server-aidd` | [S-001 + S-002 + S-005 (static, multi-hit)](findings/2026-05-11-aidd-three-rule-multi-hit.md) | Info (3 simultaneous rules — pattern stress test) |

Each entry includes reproduction commands, the raw trace, an interpretation, caveats, and a disclosure recommendation. **Two CVE-track classes are now in flight: SSRF in stdio fetch servers (2 packages, disclosed) and DNS rebinding in HTTP-transport servers (3 packages, drafted).** Together they cover both ends of the MCP transport boundary — server reaching out, browser reaching in.

## Quickstart — audit any pip-installable MCP server in one command

```bash
git clone https://github.com/desledishant10/mcp-scan && cd mcp-scan
pip install -e ".[dev]"
mcp-scan-audit mcp-server-fetch
```

That single command pip-installs `mcp-server-fetch` (or any other PyPI MCP server), captures its `tools/list` over stdio, runs the static analyzer rules, runs the capability classifier, and prints a human-readable report. Sample output against the official Anthropic reference server:

```
=== mcp-server-fetch ===
Launched: /usr/bin/python3 -m mcp_server_fetch
Tools:    1
  fetch
Capability tags: net_egress

2 analyzer findings:
  [HIGH    ] MCP-S-001  fetch
      Tool description contains instruction-like phrasing directed at the model.
  [HIGH    ] MCP-S-009  fetch
      Tool has URL parameter(s) ['url'] with no schema-level constraint
      and no validation keywords in the description.

Capture saved to: calibration/reports/captured-mcp-server-fetch.json
```

Two real findings on the official Anthropic reference server, surfaced from one `mcp-scan-audit` command — one at the description level (S-001 catches agent-directed instructions in the tool's docstring), one at the schema level (S-009 catches the missing SSRF allowlist). Both have been disclosed; the SSRF one was [demonstrated end-to-end on EC2](findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md) with real IAM credentials retrieved.

## What's inside

### CLIs

| Command | Purpose |
|---------|---------|
| `mcp-scan-audit` | **One-shot:** install + capture + analyze + classify + report against any pip-installable MCP server |
| `mcp-scan-capture` | Connect to any stdio MCP server, dump `tools/list` as JSON |
| `mcp-scan-scaffold-gt` | Generate a calibration ground-truth skeleton from a capture |
| `mcp-scan-analyze` | Static analysis — Python source or captured JSON |
| `mcp-scan-classify` | Run the capability classifier on a tool definition |
| `mcp-scan-eval-calibration` | Compare classifier predictions to hand-labeled ground truth |
| `mcp-scan-lint-scenarios` | YAML lint for scenario files (catches null-byte smuggling, parse errors, schema violations) |
| `mcp-scan-test` | Run a dynamic scenario against a real MCP server, optionally with a real LLM agent |

### Static analyzer rules (14 of 14 v0.1 rules implemented)

| ID | What it catches | Mode |
|----|---|---|
| `MCP-S-001` | Imperative phrasing in tool description (you-must, now-you-can, grants-you, were-advised) | per-tool, heuristic |
| `MCP-S-002` | One tool's description references another tool by name (poisoning vector) | server-level, heuristic |
| `MCP-S-003` | Hidden instructions in schema sub-fields (parameter descriptions, titles, `$comment`) | per-tool, heuristic |
| `MCP-S-004` | Tool annotation declares read-only / non-destructive but name/description indicates the opposite | per-tool, heuristic |
| `MCP-S-005` | Overbroad capability surface (e.g. `fs_read` + `net_egress` = exfil pair) | server-level, classifier-driven |
| `MCP-S-006` | Path traversal in file-handling tool | per-tool, AST + taint |
| `MCP-S-007` | Shell command injection (`subprocess(shell=True)`, `os.system`, `os.popen`) | per-tool, AST |
| `MCP-S-008` | Database-query tool with no apparent input constraint (no parameterized-query mention, no schema pattern) | per-tool, heuristic on tools/list |
| `MCP-S-009` | URL-fetching tool with no scheme/host allowlist (catches the SSRF class flagged dynamically by D-003) | per-tool, heuristic on tools/list |
| `MCP-S-010` | Hardcoded API keys / tokens / PEM private keys / JWTs / `.env` files committed in source | repo-level, regex + filename |
| `MCP-S-011` | Tool handler logs parameters, request data, headers, or env-derived secrets to stderr/stdout (debug-gated calls suppressed) | per-tool, AST |
| `MCP-S-012` | `RootsCapability` referenced but `list_roots()` never called — declared containment guarantee not enforced | repo-level, AST |
| `MCP-S-013` | Prompt template interpolates handler parameters into `system`/`assistant`-role messages without sanitization | repo-level, AST + light taint |
| `MCP-S-014` | HTTP transport binds to loopback / `0.0.0.0` without Origin/Host validation (DNS rebinding); CORS `allow_origins=['*']` + `allow_credentials=True` antipattern | repo-level, AST |

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
  analyzer/      Static analysis: Python AST + captured-JSON modes, 14 rules
  classifier/    Capability tagger: 8 tags, 8 param roles, Layer 1 (lexical)
  harness/       Dynamic test runner: direct + proxy modes, stub + Claude agents
  scenarios/     Attack-scenario YAML library (7 scenarios)
  calibration/   Ground-truth corpus + eval driver + capture/scaffold tools
  findings/      Audit-trail record (11 entries + 1 class survey; append-only)
  disclosures/   Append-only log of outgoing coordinated-disclosure communications
  docs/          Specs: rules, scenarios, classifier, threat model
```

## Roadmap and current state

| Phase | Planned window | Status |
|---|---|---|
| 1 — Static analyzer | weeks 1–6 | **Complete.** All 14 v0.1 rules implemented (S-001..S-014); Python AST + captured-JSON modes + repo-level scanning; CLI with severity filtering and CI-friendly exit codes |
| 2 — Dynamic harness | weeks 7–14 | Substantially complete: direct + proxy modes, two agent drivers, 7 scenarios runnable end-to-end against real servers |
| 3 — Real-world audit | weeks 15–20 | **In flight.** 11 documented findings against 10 PyPI-published servers, plus a [DNS-rebinding class survey](findings/2026-05-12-dns-rebinding-survey.md). Two CVE-track classes: SSRF in fetch-family servers (2 packages, **disclosure filed 2026-05-12** — embargo 2026-08-10, cloud reproduction completed on EC2 with real IAM creds) and DNS rebinding in HTTP-transport servers (3 packages, [disclosure drafted](disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md), embargo target 2026-08-10). |
| 4 — Polish + publish | weeks 21–26 | Embargo-day blog draft and EC2 audit runbook in [docs/](docs/). PyPI release + conference submission pending. |

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
- DNS / filesystem canaries (HTTP only today)

Out of scope for v1 (intentional — these are good follow-ups, not features):
- Runtime "agent firewall" / behavioral detection / EDR-for-agents
- Non-MCP agent frameworks (LangChain, AutoGPT, custom orchestrators)
- Production WAF-style protection
- Host-side hardening recommendations beyond what the scanner emits

## Project metrics

| | |
|---|---|
| Tests passing | **151 / 151** |
| Analyzer rules | **14 of 14** (S-001..S-014) — v0.1 spec complete |
| Dynamic scenarios | 7 (5 from v0.1 seed set + D-006 subtle-injection + D-007 cloud-metadata-exfil) |
| Calibration corpus | **10 labeled targets, 81 tools, 100/100 precision-recall** (8 verified by direct capture) — hit the spec's "stable" threshold |
| Real-world finding entries | **11 + 1 class survey** (5 vulnerabilities across 2 disclosure-track classes — SSRF + DNS rebinding; 4 defense; 2 informational) |
| Packages | 5 (`analyzer`, `classifier`, `harness`, `calibration` + `scenarios` as YAML) |
| Console scripts | 8 (added `mcp-scan-audit` — single-command audit) |

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

Policy + contact: [SECURITY.md](SECURITY.md).

## Contributing

Issue discussion and ruleset/scenario proposals are welcome. Highest-leverage places to contribute right now:

1. **Label more calibration targets.** The corpus needs ≥10 labeled servers for the classifier to promote to `stable`. The workflow is press-button (`capture` → `scaffold-gt` → hand-label → `eval-calibration`). See [calibration/README.md](calibration/README.md).
2. **Propose new analyzer rules** following [docs/static-rules.md](docs/static-rules.md) §Rule lifecycle. Real-world evidence (from a captured server) is the bar for inclusion.
3. **Propose new dynamic scenarios** following [docs/scenario-schema.md](docs/scenario-schema.md). Same evidence bar.

## License

Apache 2.0 — see [LICENSE](LICENSE).
