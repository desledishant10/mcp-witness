# Disclosures

Outgoing coordinated-disclosure communications from mcp-witness to the maintainers of MCP servers where the [analyzer](../analyzer/) or [dynamic harness](../harness/) surfaced a security finding. Companion to [`findings/`](../findings/) — findings document what the scanner observed; this directory documents what was sent to maintainers, when, through which channel, and with what outcome.

**This directory is the project's load-bearing artifact.** The scanner finds the bugs; the disclosures and their outcomes are what makes the work durable. Every disclosure here can be walked: who was contacted, when, what channels were tried, what they said back, when (and where) it became public.

## Status — all disclosures closed or past embargo

Six coordinated disclosures filed. Outcomes as of 2026-09-11: **one vendor-declined** (branch-verified community fix left unmerged, issue closed "not planned"), **one maintainer-confirmed-unmaintained**, **four silent through embargo with no fix**. All six embargoes (2026-08-10) have expired and all six are publicly disclosed; CVE requests filed for all six on 2026-09-11.

| Filed | Target | Channel(s) | Maintainer status | Disclosure record |
|---|---|---|---|---|
| 2026-05-12 | `mcp-server-fetch` v2025.4.7 | Public GitHub issue [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) | 🔴 **Closed by maintainer as "not planned" (2026-07-30); PR #4226 unmerged; latest release still vulnerable** — community contributor `@kgarg2468` opened fix PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) on 2026-05-22 (scheme allowlist + RFC-reserved-range denylist + per-redirect validation). Branch verified against the EC2 demo (2026-05-22) and the containerized [`poc/ssrf/`](../poc/ssrf/) harness (2026-06-20); CI green (16/16); external technical audit by `@LuuOW`. **Issue closed as "not planned" by Anthropic contributor `@localden` 2026-07-30 and consolidated to the older umbrella issue [#3741](https://github.com/modelcontextprotocol/servers/issues/3741) (opened 2026-03-27; dormant, no substantive activity since opening beyond the consolidation event). PR #4226 remains open + unmerged despite CI green + external review + independent reproduction. Three releases shipped since disclosure (v2026.6.4, v2026.7.10, v2026.8.18); current latest v2026.8.18 (2026-08-18) still vulnerable, runtime-verified via the `poc/ssrf/` harness on 2026-09-10.** | (issue thread + [finding entry](../findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md)) |
| 2026-05-12 | `mcp-server-http-request` v0.1.0 | Email to `esteban@statespace.com` + `gavin@statespace.com` → day +21 ping → day +30 LinkedIn DMs | 🟡 **Maintainer confirmed unmaintained on 2026-06-11.** Cofounder Gavin Chan replied via LinkedIn after the day +30 escalation: *"not an actively maintained package."* Yank + deprecation-notice request pending | [2026-05-12-mcp-fetch-http-request-ssrf.md](2026-05-12-mcp-fetch-http-request-ssrf.md) |
| 2026-05-12 | `mcp-streamablehttp-proxy` v0.2.0 + `mcp-fetch-streamablehttp-server` v0.2.0 (joint filing) | Email to `atrawog@gmail.com` → day +21 ping → day +30 third email | 🔴 **Silent through embargo; no fix.** No reply at any point (filing 2026-05-12, day +21 2026-06-02, day +30 third email). Embargo expired 2026-08-10; both packages unchanged on PyPI (v0.2.0) and still vulnerable as of 2026-09-10. Publicly disclosed. | [2026-05-12-mcp-oauth-gateway-dns-rebinding.md](2026-05-12-mcp-oauth-gateway-dns-rebinding.md) |
| 2026-06-02 | `fastmcp-http` v0.1.4 | Public-issue channel of last resort: [ARadRareness/mcp-registry#3](https://github.com/ARadRareness/mcp-registry/issues/3) | 🔴 **Issue closed "completed" 2026-06-21 with no comment, no commit, no fix.** GHSA disabled, maintainer profile contact-less, PyPI email is GitHub-noreply, so the public issue was the only channel. Embargo expired 2026-08-10; v0.1.4 unchanged on PyPI and still vulnerable as of 2026-09-10. | [2026-06-02-fastmcp-http-dns-rebinding.md](2026-06-02-fastmcp-http-dns-rebinding.md) |
| 2026-06-02 | `mcp-server-fetch-sse` v0.1.1 (primary) | Email to `jadamson@anthropic.com` (PyPI-listed maintainer-of-record) | 🔴 **Silent through embargo; no fix.** No maintainer reply; the parallel Anthropic-intake notice was auto-deflected (row below). Embargo expired 2026-08-10; v0.1.1 unchanged on PyPI and still vulnerable as of 2026-09-10. | [2026-06-02-mcp-server-fetch-sse-dns-rebinding.md](2026-06-02-mcp-server-fetch-sse-dns-rebinding.md) |
| 2026-06-02 | `mcp-server-fetch-sse` v0.1.1 (parallel courtesy notice, brand-attribution flag) | Email to `disclosure@anthropic.com` (after HackerOne triage interstitial halted the attempt) | 🔴 **No-reply auto-responder.** disclosure@ returned routing-to-other-channels boilerplate; no human review reached. Documented in the disclosure record as channel-deflection per the published Anthropic intake | (above) |

**All embargoes (2026-08-10) have expired.** Post-embargo verification 2026-09-10: every still-open package is unchanged on PyPI and remains vulnerable; zero fixes shipped across the six, except the community fix PR for `mcp-server-fetch` that remains unmerged. CVE requests filed for all six on 2026-09-11 (see [`docs/cve-requests.md`](../docs/cve-requests.md)). Full technical writeups: [`drafts/blog-mcp-server-fetch-ssrf.md`](../drafts/blog-mcp-server-fetch-ssrf.md) and [`drafts/blog-mcp-dns-rebind-class.md`](../drafts/blog-mcp-dns-rebind-class.md).

## What "one of one" looks like in this directory

The disclosure track here is what no other MCP security project ships. Specifically:

- **1 branch-verified community fix the vendor declined to merge** ([#4143 → #4226](https://github.com/modelcontextprotocol/servers/pull/4226); verified against the EC2 IAM-credential demo and the containerized harness, then the issue was closed "not planned" and the PR left unmerged) — the distinct "a fix exists but never shipped" outcome
- **1 maintainer-confirmed-unmaintained outcome** (statespace, 2026-06-11) — a distinct disclosure outcome category from "fixed" or "silent"
- **Documented channel-deflection records** for two intake-automation outcomes (HackerOne triage interstitial; `disclosure@anthropic.com` no-reply auto-responder) — useful methodology data for anyone running similar coordinated disclosure
- **Public-issue channel-of-last-resort precedent** with the channel-decision audit (`gh api`-verified that GHSA was disabled + maintainer contactless + PyPI noreply) so anyone reading can see why a public issue was the right call rather than a default

The PoC harness for the DNS-rebinding class lives at [`poc/dns-rebind/`](../poc/dns-rebind/) and reproduces the vulnerability end-to-end with a single `make demo`. The reproduction round-trip — disclosure record → finding entry → runnable PoC — is itself unusual; most coordinated-disclosure records stop at the technical narrative.

## Helper CLI

The day +14 / +21 / +30 / +45 / +60 / +90 cadence used to run this disclosure track is codified in [`mcp-witness-disclose`](../disclose/):

```bash
mcp-witness-disclose status --today 2026-06-11
#   today: 2026-06-11  (4 disclosures on disk)
#
#     SLUG                                           FILED       DAY   NEXT ACTION
#     ---------------------------------------------  ----------  ----  -----------------------------------------
#     2026-05-12-mcp-fetch-http-request-ssrf         2026-05-12  + 30  day +45 pointer issue in 15d (2026-06-26)
#     2026-05-12-mcp-oauth-gateway-dns-rebinding     2026-05-12  + 30  day +45 pointer issue in 15d (2026-06-26)
#     2026-06-02-fastmcp-http-dns-rebinding          2026-06-02  +  9  day +14 ping in 5d (2026-06-16)
#     2026-06-02-mcp-server-fetch-sse-dns-rebinding  2026-06-02  +  9  day +14 ping in 5d (2026-06-16)
#
#   summary: 4 open / 0 closed; 0 due today; 0 overdue

mcp-witness-disclose ping mcp-fetch-http-request --to "Esteban" --today 2026-06-11
# renders the day +30 escalation body (auto-selected from the day-count),
# with affected packages + embargo + slug auto-populated from the file

mcp-witness-disclose new mcp-server-foo --class ssrf \
    --filed-to maintainer@example.invalid \
    --affected "\`mcp-server-foo\` v0.1.0"
# scaffolds disclosures/2026-06-11-mcp-server-foo-ssrf.md with standard frontmatter
```

Pass `--today YYYY-MM-DD` to any subcommand for deterministic output (used in tests + for previewing future milestone bodies via `ping --day 60`).

## How this directory is organized

```
disclosures/
├── README.md                                                  (this file)
├── 2026-05-12-mcp-fetch-http-request-ssrf.md                  (statespace SSRF)
├── 2026-05-12-mcp-oauth-gateway-dns-rebinding.md              (atrawog DNS rebind, joint)
├── 2026-06-02-fastmcp-http-dns-rebinding.md                   (ARadRareness)
├── 2026-06-02-mcp-server-fetch-sse-dns-rebinding.md           (jadamson + disclosure@)
└── 2026-06-11-day-plus-30-escalation-templates.md             (escalation playbook + templates)
```

Each disclosure file is **append-only**. The body of the report at the top is the verbatim text that was sent (or, for public-issue filings, the verbatim body of the issue). The `## Updates` section below tracks every subsequent event — follow-up pings, channel pivots, maintainer responses, outcome confirmations — in reverse-chronological order (newest first).

The original mcp-server-fetch disclosure (#4143) does not have a file here because it was filed as a public GitHub issue directly. The full record lives in the issue thread + the [corresponding finding entry](../findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md).

## How to read a disclosure file

Each file follows a consistent template:

```markdown
# <Short title>

**Filed:** YYYY-MM-DD
**Filed to:** <recipient(s) + channel>
**Affected:** <package(s) + version(s)>
**Embargo:** 2026-08-10
**Status:** <drafted | filed | acknowledged | maintainer-confirmed-unmaintained | fix-shipped | publicly-disclosed>

## <Channel justification, if non-obvious>

## <Body of the filed report — verbatim sent text>

## Updates

### YYYY-MM-DD — <event>
### YYYY-MM-DD — <event>
...
```

The `Updates` section is where the disclosure's life happens. Anyone re-reading a disclosure six months from now should be able to reconstruct the full timeline from the Updates entries alone.

## Methodology notes worth banking

Three patterns from this disclosure round that other coordinated-disclosure work could lift:

### LinkedIn-DM as a soft escalation channel for small-team unmaintained projects

When a small startup's maintainer email goes silent, the most likely explanation is "the project is dead and the maintainer doesn't want to admit it." A LinkedIn DM that **explicitly offers that as a polite escape valve** — *"if statespace as a company has wound down and the package is unmaintained, that's fine, just let me know and I'll include that in the public writeup"* — surfaced a verified-cofounder reply within hours on 2026-06-11 after 30 days of email silence. The escape-valve framing made it psychologically easy to confirm rather than feel cornered. Repeating this pattern in future disclosures.

**Full writeup with the four-case taxonomy, verbatim messages, and the parallel atrawog case:** [docs/methodology-soft-escalation.md](../docs/methodology-soft-escalation.md).

### Channel-deflection-documentation as a substantive disclosure outcome

The mcp-server-fetch-sse parallel notice to Anthropic went through **two corporate intake systems** (HackerOne + `disclosure@`) that both deflected without human review. Documenting the verbatim deflection texts in the disclosure record turned what would have been "couldn't reach Anthropic" into evidence about how disclosure-channel pathologies actually look in 2026. That's useful research-track material on its own, separate from the underlying vulnerability.

### Public-issue channel-of-last-resort precedent

When no private channel exists (GHSA disabled + maintainer profile contact-less + PyPI noreply), opening a public issue with **intentionally non-exploitative content** is the responsible-disclosure-norm answer. The fastmcp-http filing precedent here ([ARadRareness/mcp-registry#3](https://github.com/ARadRareness/mcp-registry/issues/3)) shows what the threshold looks like in practice: names the vulnerability class, suggests the fix shape, asks for a private channel — without source-line references or PoC payloads.

## Policy

- **Embargo:** 90 days from notification before public disclosure; extended if a fix is in active development.
- **No exploit code published until embargo expires.** Reproduction *runbooks* are public from the start (they're also defense documentation); concrete payloads, exfiltrated values, etc. are redacted in this directory until the maintainer is satisfied.
- **Append-only updates.** Original report text is preserved verbatim. Subsequent events go under `## Updates` in reverse-chronological order.
- **One file per disclosure**, named `YYYY-MM-DD-<short-slug>.md`.

## Why this directory is public

Open auditing means the disclosure timeline is part of the record. Anyone reading can see: what was reported, when, how, and what happened after. That's the difference between security work and security theater — and it's why the disclosure track is the project's load-bearing artifact, not the scanner.
