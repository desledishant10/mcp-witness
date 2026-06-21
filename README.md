# mcp-witness

[![PyPI version](https://img.shields.io/pypi/v/mcp-witness.svg)](https://pypi.org/project/mcp-witness/)
[![tests](https://github.com/desledishant10/mcp-witness/actions/workflows/tests.yml/badge.svg)](https://github.com/desledishant10/mcp-witness/actions/workflows/tests.yml)
[![ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![license: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![python: 3.11+](https://img.shields.io/badge/python-3.11+-blue)](pyproject.toml)
[![findings: 12](https://img.shields.io/badge/findings-12-orange)](findings/)
[![CVE-track classes: 2](https://img.shields.io/badge/CVE--track_classes-2-red)](findings/)

> Coordinated-disclosure track for Model Context Protocol server security — and the scanner that finds the filings.

## Six coordinated security disclosures against PyPI-published MCP servers

**One community-authored fix PR open + branch-verified (still awaiting maintainer merge 30 days later).** **One maintainer-confirmed-unmaintained outcome.** **Four filings in flight under coordinated embargo through 2026-08-10.**

mcp-witness is built around the disclosure track at [`disclosures/`](disclosures/). The scanner — 14 static rules + 7 dynamic scenarios + a capability classifier — is the engine that surfaces filings. The disclosure records and their outcomes are the durable artifacts:

- **`mcp-server-fetch` v2025.4.7** — SSRF demonstrated on EC2 with real AWS IAM credentials retrieved (`AccessKeyId` / `SecretAccessKey` / `Token` triplet). Coordinated disclosure filed as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) on 2026-05-12. Community contributor `@kgarg2468` opened fix PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) on 2026-05-22 with scheme allowlist + RFC-reserved-range denylist + per-redirect validation. ✅ **Branch verified 2026-05-22 (EC2 demo) and re-verified 2026-06-20 (containerized `poc/ssrf/` harness)** — both reproductions refuse the IMDS URL with *"Fetching private or non-public IP addresses is not allowed"* when run against the PR branch. ⚠️ **PR still open + unmerged 30 days after open; latest PyPI release `mcp-server-fetch==2026.6.4` (uploaded 2026-06-04) still vulnerable** to the exact same probe.
- **`mcp-server-http-request` v0.1.0** (statespace) — same SSRF class. Filed via email 2026-05-12, silent through day +30, then maintainer-confirmed unmaintained via LinkedIn DM on 2026-06-11 ("not an actively maintained package"). Yank request pending.
- **4× DNS rebinding** in HTTP-transport servers — `mcp-streamablehttp-proxy`, `mcp-fetch-streamablehttp-server`, `fastmcp-http`, `mcp-server-fetch-sse`. All under coordinated disclosure with 2026-08-10 embargo. Reproducible end-to-end via the containerized harness at [`poc/dns-rebind/`](poc/dns-rebind/) (`make demo`).

Two CVE-track vulnerability classes covering both ends of the MCP transport boundary — server reaching out (SSRF), browser reaching in (DNS rebind). The detectors that found them are static rules `MCP-S-009` (SSRF) + `MCP-S-014` v0.3 (DNS rebind, four-patch W1–W4 series developed from the survey itself) + dynamic scenario `MCP-D-003` (SSRF). Detector evolution is itself part of the audit trail — every patch is documented against the finding that motivated it.

**Full disclosure track:** [`disclosures/`](disclosures/) — status table, methodology notes, channel-decision audit trails.
**Per-finding evidence:** [`findings/`](findings/) — reproduction + raw output + interpretation, one file per observation.

## Findings ledger

Twelve documented audit observations against eleven PyPI-published servers, captured in [findings/](findings/) (status-table index at [findings/README.md](findings/README.md)), plus a [DNS-rebinding class survey](findings/2026-05-12-dns-rebinding-survey.md) that frames four of them as one class:

| Date | Target | Test | Outcome |
|---|---|---|---|
| 2026-05-11 | `mcp-server-fetch` | [D-003 (direct SSRF probe)](findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md) | **Vulnerability** — env-dependent SSRF, demonstrated on EC2 2026-05-12 (real IAM credentials retrieved); disclosure [#4143](https://github.com/modelcontextprotocol/servers/issues/4143); **fix PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) independently verified 2026-05-22** |
| 2026-05-11 | `mcp-server-http-request` | [D-003 (direct SSRF probe)](findings/2026-05-11-MCP-D-003-http-request-direct-environment-dependent-ssrf.md) | **Vulnerability** — second instance of same SSRF class; **disclosure email-filed 2026-05-12** (embargo 2026-08-10) |
| 2026-05-12 | `mcp-streamablehttp-proxy` v0.2.0 | [S-014 (static, DNS rebinding)](findings/2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md) | **Vulnerability** — 127.0.0.1 + no Origin/Host check; universal escalation against whatever stdio MCP it proxies; **disclosure filed 2026-05-12** (embargo 2026-08-10) |
| 2026-05-12 | `mcp-fetch-streamablehttp-server` v0.2.0 | [S-014 (static, DNS rebinding + 0.0.0.0 + recursive SSRF)](findings/2026-05-12-MCP-S-014-fetch-streamablehttp-server-dns-rebinding.md) | **Vulnerability** — 0.0.0.0 + wildcard CORS + inherited fetch SSRF; co-disclosed with proxy finding (embargo 2026-08-10) |
| 2026-05-12 | `fastmcp-http` v0.1.4 | [S-014 (static, DNS rebinding)](findings/2026-05-12-MCP-S-014-fastmcp-http-dns-rebinding.md) | **Vulnerability** — Flask dev server on 0.0.0.0, no middleware anywhere; **public-issue disclosure filed 2026-06-02** (embargo 2026-08-10) |
| 2026-06-02 | `mcp-server-fetch-sse` v0.1.1 | [S-014 (static, W1+W3 — aiohttp TCPSite)](findings/2026-06-02-MCP-S-014-mcp-server-fetch-sse-dns-rebinding.md) | **Vulnerability** — DNS rebind + inherited pre-PR-#4226 SSRF; **maintainer + Anthropic Security notified 2026-06-02** (embargo 2026-08-10) |
| 2026-05-11 | `mcp-server-fetch` | [D-001 against Claude Opus 4.7](findings/2026-05-11-MCP-D-001-fetch-opus47-defense.md) | Defense |
| 2026-05-11 | `mcp-server-fetch` | [D-006 against Claude Opus 4.7](findings/2026-05-11-MCP-D-006-fetch-opus47-defense.md) | Defense |
| 2026-05-11 | `mcp-server-time` | [S-003 static, 3 hits](findings/2026-05-11-MCP-S-003-time-static-param-injection-pattern.md) | Info (pattern present; benign in this deployment) |
| 2026-05-11 | `mcp-server-git` | [D-002 (direct path-traversal)](findings/2026-05-11-MCP-D-002-git-direct-defense.md) | Defense (defense-in-depth example) |
| 2026-05-11 | `mcp-server-aidd` | [D-002 (direct path-traversal)](findings/2026-05-11-MCP-D-002-aidd-direct-defense.md) | Defense (allowed-directory containment working) |
| 2026-05-11 | `mcp-server-aidd` | [S-001 + S-002 + S-005 (static, multi-hit)](findings/2026-05-11-aidd-three-rule-multi-hit.md) | Info (3 simultaneous rules — pattern stress test) |

Each entry includes reproduction commands, the raw trace, an interpretation, caveats, and a disclosure recommendation. **Two CVE-track classes are now in flight: SSRF in stdio fetch servers (2 packages, disclosed; 1 fix verified, 1 maintainer-confirmed unmaintained) and DNS rebinding in HTTP-transport servers (4 packages, all disclosed).**

## Quickstart — audit any pip-installable MCP server in one command

```bash
pip install mcp-witness
mcp-witness-audit mcp-server-fetch
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

Two real findings on the official Anthropic reference server, surfaced from one `mcp-witness-audit` command — one at the description level (S-001 catches agent-directed instructions in the tool's docstring), one at the schema level (S-009 catches the missing SSRF allowlist). The SSRF one was [demonstrated end-to-end on EC2](findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md) with real IAM credentials retrieved, disclosed via #4143, and fixed by PR #4226 (verified).

## What's inside

### CLIs

| Command | Purpose |
|---------|---------|
| `mcp-witness-audit` | **One-shot:** install + capture + analyze + classify + report against any pip-installable MCP server |
| `mcp-witness-capture` | Connect to any stdio MCP server, dump `tools/list` as JSON |
| `mcp-witness-scaffold-gt` | Generate a calibration ground-truth skeleton from a capture |
| `mcp-witness-analyze` | Static analysis — Python source or captured JSON |
| `mcp-witness-classify` | Run the capability classifier on a tool definition |
| `mcp-witness-eval-calibration` | Compare classifier predictions to hand-labeled ground truth |
| `mcp-witness-lint-scenarios` | YAML lint for scenario files (catches null-byte smuggling, parse errors, schema violations) |
| `mcp-witness-test` | Run a dynamic scenario against a real MCP server, optionally with a real LLM agent |
| `mcp-witness-disclose` | **Coordinated-disclosure helper.** Scaffold new disclosure records, track day-count milestones (`status`), render day-appropriate follow-up bodies (`ping`) |

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
| `MCP-S-014` | HTTP transport binds to loopback / `0.0.0.0` without Origin/Host validation (DNS rebinding); CORS `allow_origins=['*']` + `allow_credentials=True` antipattern. v0.3 adds W1 (host-variable resolution), W2 (AST-based Origin validation check), W3 (aiohttp.web bind shapes), W4 (`os.getenv` default resolution). | repo-level, AST |

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

**Current calibration corpus state:** 11 labeled targets, 87 tools, **100% precision and 100% recall on all six exercised capability tags** (`db_query`, `db_write`, `exec`, `fs_read`, `fs_write`, `net_egress`). Verified by direct capture against 8 of 11 targets. Hit the spec's ≥10-target / ≥0.9-precision / ≥0.75-recall "stable" threshold. **CI-protected against regression:** [calibration/tests/test_corpus_regression.py](calibration/tests/test_corpus_regression.py) runs the full eval on every PR and fails if precision drops below 0.90, recall below 0.75, target count below 10, parameter-role accuracy below 0.80, or any of the original four v0.1 tags disappears from the corpus. See [calibration/README.md](calibration/README.md).

### Dynamic harness

Two modes auto-selected per scenario:
- **Direct mode** — agent-less, harness as MCP client. Used for server-side validation tests (path traversal, SSRF).
- **Proxy mode** — harness mediates between an agent under test and the real target, applying mutations to tool descriptions and outputs in flight. Used for agent-side scenarios (description injection, rug pull, output injection).

Two agent driver implementations: `stub` (deterministic, plumbing tests) and `anthropic` (real Claude tool-use loop). See [harness/README.md](harness/README.md).

## Architecture

```
mcp-witness/
  analyzer/      Static analysis: Python AST + captured-JSON modes, 14 rules
  classifier/    Capability tagger: 8 tags, 8 param roles, Layer 1 (lexical)
  harness/       Dynamic test runner: direct + proxy modes, stub + Claude agents
  scenarios/     Attack-scenario YAML library (7 scenarios)
  calibration/   Ground-truth corpus + eval driver + capture/scaffold tools
  findings/      Audit-trail record (12 entries + 1 class survey; append-only)
  disclosures/   Append-only log of outgoing coordinated-disclosure communications
  docs/          Specs: rules, scenarios, classifier, threat model
```

## Roadmap and current state

| Phase | Planned window | Status |
|---|---|---|
| 1 — Static analyzer | weeks 1–6 | **Complete.** All 14 v0.1 rules implemented (S-001..S-014); v0.3 patches W1–W4 closed the DNS-rebind detector gap surfaced by the survey. Python AST + captured-JSON modes + repo-level scanning; CLI with severity filtering and CI-friendly exit codes. |
| 2 — Dynamic harness | weeks 7–14 | Substantially complete: direct + proxy modes, two agent drivers, 7 scenarios runnable end-to-end against real servers. |
| 3 — Real-world audit | weeks 15–20 | **Substantially complete.** 12 documented findings against 11 PyPI-published servers, plus a [DNS-rebinding class survey](findings/2026-05-12-dns-rebinding-survey.md). Two CVE-track classes: SSRF in fetch-family servers (2 packages disclosed; 1 community-authored fix PR open + branch-verified, maintainer merge pending 30 days; 1 maintainer-confirmed unmaintained 2026-06-11) and DNS rebinding in HTTP-transport servers (4 packages, all under coordinated disclosure with 2026-08-10 embargo). |
| 4 — Polish + publish | weeks 21–26 | **In flight.** Embargo-day blog draft in [drafts/](drafts/) (excluded from Pages indexing pre-embargo); EC2 audit runbook in [docs/](docs/). PyPI release + conference submission queued. |

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
| Tests passing | **191 / 191** |
| Analyzer rules | **14 of 14** (S-001..S-014) — v0.1 spec complete + v0.3 W1–W4 patches |
| Dynamic scenarios | 7 (5 from v0.1 seed set + D-006 subtle-injection + D-007 cloud-metadata-exfil) |
| Calibration corpus | **11 labeled targets, 87 tools, 100/100 precision-recall** (8 verified by direct capture) — hit the spec's "stable" threshold; CI-protected via [test_corpus_regression.py](calibration/tests/test_corpus_regression.py) |
| Real-world finding entries | **12 + 1 class survey** (6 vulnerabilities across 2 disclosure-track classes — SSRF + DNS rebinding; 4 defense; 2 informational) |
| Coordinated disclosures filed | **6** (1 community-authored fix PR open + branch-verified; 1 maintainer-confirmed unmaintained; 4 awaiting maintainer response with 2026-08-10 embargo) |
| Packages | 5 (`analyzer`, `classifier`, `harness`, `calibration` + `scenarios` as YAML) |
| Console scripts | 8 |

## Running the test suite

```bash
pip install -e ".[dev]"
pytest
```

With coverage:

```bash
pytest --cov=analyzer --cov=classifier --cov=harness --cov=calibration --cov-report=term-missing
```

Lint + format:

```bash
ruff check .
ruff format --check .
```

Optional pre-commit hooks (one-time setup):

```bash
pip install pre-commit
pre-commit install
```

After install, every `git commit` runs ruff + a fast tests subset on push.

For dynamic scenarios that exercise a real LLM, install the optional Anthropic agent and set an API key:

```bash
pip install "mcp-witness[anthropic]"
export ANTHROPIC_API_KEY=sk-ant-...
mcp-witness-test scenarios/MCP-D-001-tool-desc-injection-fetch.yaml \
    --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch \
    --agent anthropic
```

## Methodology and threat model

Attack surface enumerated by MCP primitive (tools, resources, prompts, sampling, roots) plus transport and cross-cutting agent-level attacks. Every detection rule and every scenario carries a `category` field mapped back to this taxonomy. The categories and tag/role vocabularies live in:

- [docs/static-rules.md](docs/static-rules.md) — detection rules and lexicon decisions
- [docs/scenario-schema.md](docs/scenario-schema.md) — dynamic scenario YAML schema and step types
- [docs/capability-classifier.md](docs/capability-classifier.md) — capability tag and parameter role vocabularies, calibration plan
- [docs/detector-evolution-s014.md](docs/detector-evolution-s014.md) — worked example of how MCP-S-014 went from one of five to four of four across the W1–W4 patch series; methodology notes for static-rule evolution
- [docs/methodology-soft-escalation.md](docs/methodology-soft-escalation.md) — the LinkedIn escape valve pattern: how a polite "if this is unmaintained, that's fine, just let me know" surfaced a verified maintainer reply on day +30 after 30 days of email silence

## Responsible disclosure

Findings against third-party servers follow coordinated disclosure: maintainers receive 90 days from notification before public release, extended if a fix is in active development. Reporters using mcp-witness are expected to follow the same practice. The [disclosures/](disclosures/) directory documents every outgoing coordinated-disclosure communication, including channel-decision audit trails — when a public issue was the channel of last resort ([ARadRareness/mcp-registry#3](https://github.com/ARadRareness/mcp-registry/issues/3)), when an intake automation deflected (HackerOne triage interstitial + `disclosure@anthropic.com` auto-responder, both documented as substantive disclosure outcomes), when a LinkedIn DM with a polite escape-valve surfaced an unmaintained-confirmation after 30 days of email silence.

The disclosure track is the project's load-bearing artifact. See [disclosures/README.md](disclosures/README.md) for the full status table and methodology notes.

Policy + contact: [SECURITY.md](SECURITY.md).

## Contributing

Issue discussion and ruleset/scenario proposals are welcome. Highest-leverage places to contribute right now:

1. **Label more calibration targets.** The corpus needs more labeled servers for the classifier to grow beyond the current `stable` threshold. The workflow is press-button (`capture` → `scaffold-gt` → hand-label → `eval-calibration`). See [calibration/README.md](calibration/README.md).
2. **Propose new analyzer rules** following [docs/static-rules.md](docs/static-rules.md) §Rule lifecycle. Real-world evidence (from a captured server) is the bar for inclusion.
3. **Propose new dynamic scenarios** following [docs/scenario-schema.md](docs/scenario-schema.md). Same evidence bar.

## License

Apache 2.0 — see [LICENSE](LICENSE).
