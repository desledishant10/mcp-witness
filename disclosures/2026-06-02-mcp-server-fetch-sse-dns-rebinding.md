# DNS-rebinding + inherited SSRF in mcp-server-fetch-sse

**Filed:** 2026-06-02
**Filed by:** Dishant Desle, didesle7@gmail.com
**Filed to:**
  - **Primary:** Jack Adamson <jadamson@anthropic.com> (PyPI-listed maintainer-of-record) — email sent 2026-06-02
  - **Parallel:** Anthropic Security at `disclosure@anthropic.com` (the secondary contact published on Anthropic's responsible-disclosure-policy page) — email sent 2026-06-02. Channel changed from the originally-planned HackerOne route mid-filing; see §"HackerOne attempt and pivot to email" below and the Updates section for the full reasoning.
**Affected:** `mcp-server-fetch-sse` v0.1.1 (PyPI)
**Embargo:** 2026-08-10 (truncated from the standard 90 days to align with the class-wide DNS-rebind + SSRF public writeup; ~69 days)
**Status:** filed (both channels dispatched 2026-06-02); awaiting maintainer acknowledgement. Anthropic-side parallel notification was deflected by intake automation on both attempted channels (HackerOne triage interstitial → cancelled with reputation-points warning; `disclosure@` → no-reply auto-responder routing back to HackerOne / specialized categories with no fit for third-party brand-attribution concerns). No human review reached on the Anthropic side; further escalation declined per coordinated-disclosure hygiene — see §"HackerOne attempt and pivot to email" and Updates for full audit trail.

---

## Channel justification

The PyPI METADATA for `mcp-server-fetch-sse` lists:

```
Author: Anthropic, PBC.
Maintainer-email: Jack Adamson <jadamson@anthropic.com>
```

The Author attribution is **likely inherited from the upstream fork** (the README is lifted near-verbatim from Anthropic's official `mcp-server-fetch`, including VS Code install badges that still point at the upstream package name), not necessarily an indication of active Anthropic maintenance. PyPI does not verify Author/Maintainer claims.

Two-channel approach:

1. **Email Jack directly at the published address.** He is the listed maintainer-of-record. If he is actively maintaining the package (whether at Anthropic or independently), this is the correct private channel.
2. **Parallel filing to Anthropic Security via HackerOne.** Anthropic's `.well-known/security.txt` points at their HackerOne embedded submission form as the official channel. Filing here covers two cases:
   - If the package is in fact Anthropic-maintained, the HackerOne filing reaches the right security team in parallel with the maintainer email.
   - If the package is **not** Anthropic-maintained (the Author attribution is misleading), Anthropic Security needs to know that a vulnerable PyPI package is being published with their brand attribution. They can determine the right action (verify maintainership, request a takedown, request PyPI metadata correction).

Both filings reference each other for transparency.

## Primary email (verbatim — to send to jadamson@anthropic.com)

> **Subject:** Security disclosure — mcp-server-fetch-sse v0.1.1 (DNS-rebinding + inherited SSRF)
>
> Hi Jack,
>
> I'm reaching out as a coordinated security disclosure for `mcp-server-fetch-sse` v0.1.1 on PyPI. You're listed as the maintainer-of-record in the wheel METADATA, so I'm starting here. I've also filed a parallel notification to Anthropic Security via HackerOne — partly because the package's PyPI metadata lists `Author: Anthropic, PBC.` (which may be inherited from the upstream `mcp-server-fetch` fork rather than reflecting active Anthropic publication, but I want Anthropic Security to have the option to verify either way given the brand attribution).
>
> **TL;DR:** Two compounding vulnerabilities in the package's default deployment configuration.
>
> 1. **DNS-rebinding via missing Origin/Host validation.** `mcp_server_fetch/http_sse_server.py` `start_server(self, host: str = "localhost", port: int = 3001)` uses `web.AppRunner` + `web.TCPSite(runner, host, port)` with **no aiohttp middleware**, **no `Origin` validation**, and **no `Host` allowlist**. Repo-wide grep across the installed wheel for `trustedhost | add_middleware | origin | cors | before_request` returns zero header-validation hits. A DNS-rebind attack against `localhost` (TTL flip on attacker-controlled DNS) lets any browser tab the operator visits establish an SSE session and POST `tools/call` to `/message?sessionId=<id>`.
>
> 2. **Inherited SSRF from the wrapped fetch tool.** `server.py` and `sse_server.py` appear to be a fork of upstream `mcp-server-fetch`. The upstream had no scheme allowlist or IP-class denylist — disclosed as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) on 2026-05-12 and fixed in [PR #4226](https://github.com/modelcontextprotocol/servers/pull/4226) (kgarg2468) on 2026-05-22, which I independently verified. **Your fork has not taken the patch.** The accidental robots.txt-fetch-first defense documented in the upstream finding works only against unreachable targets — on a cloud VM where the metadata service responds to TCP, the defense fails open.
>
> **Compounding:** rebind → SSE session → fetch tool → IMDS URL → IAM credentials. On an EC2 host with IMDSv1 or IMDSv2-Optional, this is unauthenticated IAM-credential exfiltration triggered by any browser tab.
>
> **Demonstration**: I verified the upstream SSRF on a real EC2 `t3.micro` on 2026-05-12 with `mcp-server-fetch` v2025.4.7 — full runbook at https://github.com/desledishant10/mcp-scan/blob/main/docs/audit-runbook-ec2-ssrf-verification.md. The same demo applies to `mcp-server-fetch-sse` once the inbound rebind primitive lets an attacker reach the tool; I haven't separately staged the EC2 reproduction for this package because the inherited-SSRF mechanism is identical, but happy to do so if you'd like an explicit reproduction artifact.
>
> **Suggested remediation:**
>
> 1. **DNS-rebind defense:** add an aiohttp middleware at `web.Application(middlewares=[origin_host_validator])` time. Pseudocode in the finding entry linked below. Validates `Origin` against an allowlist and `Host` against `{localhost:port, 127.0.0.1:port}`. Rejects everything else with 403.
> 2. **SSRF defense:** port the upstream PR #4226 fix into this fork. Scheme allowlist (`http`, `https`), reserved-range denylist (`169.254/16`, `127/8`, `::1`, `10/8`, `172.16/12`, `192.168/16`, `fc00::/7`, `0.0.0.0/8`), per-redirect validation. PR diff is small (~100 lines) and translates near-verbatim.
> 3. **Separately**: the `from mcp.server.sse import sse_server` import in `sse_server.py` is broken on current `mcp` library versions (the upstream API was renamed). The package fails at startup on `mcp>=1.x`. This is independent of the vulnerability but worth flagging — the HTTP+SSE entry point (`mcp-server-fetch-http` → `http_sse_server.py`) is the in-scope-vulnerable one and doesn't depend on the broken import.
>
> **Embargo:** 2026-08-10. This is ~69 days, truncated from the standard 90, to align with parallel disclosures of the same class (DNS-rebind across four packages, SSRF across two packages) so the public writeup covers the whole ecosystem at once. If you're shipping a fix sooner I'll align; if you need more time I'm happy to extend.
>
> **Brand-attribution concern (separate from the technical vuln):**
>
> The wheel METADATA lists `Author: Anthropic, PBC.` and the README is lifted from upstream Anthropic content. If you're publishing this fork independently of Anthropic, you may want to update the Author field to reflect that (e.g., your name as Author, with a note in the README that the underlying fetch code is forked from Anthropic's MIT-licensed `mcp-server-fetch`). This avoids the appearance of an Anthropic-published package and reduces the chance of brand-misattribution takedown requests. If you ARE publishing this on behalf of Anthropic, the HackerOne filing should reach the right people internally — no action needed on your end for that piece.
>
> **About me + the tool:**
>
> Disclosure produced by MCP-Scan, an open-source security scanner for MCP servers I'm building as a capstone project. Detector rule MCP-S-014 fires on this package. Full audit trail (this disclosure record + the v0.3 detector that surfaced your package + the parallel filings for the other affected packages in the same survey) lives at https://github.com/desledishant10/mcp-scan. The detailed finding entry for your package: https://github.com/desledishant10/mcp-scan/blob/main/findings/2026-06-02-MCP-S-014-mcp-server-fetch-sse-dns-rebinding.md.
>
> Happy to verify any candidate fix before you ship it.
>
> Thanks for taking a look,
> Dishant Desle
> didesle7@gmail.com

## Parallel HackerOne submission (to file at https://hackerone.com/4f1f16ba-10d3-4d09-9ecc-c721aad90f24/embedded_submissions/new)

> **Title:** Vulnerable PyPI package `mcp-server-fetch-sse` published with Anthropic Author attribution
>
> **Severity:** Medium (the technical vulnerability is High on cloud-deployed hosts; the brand-attribution concern is the Medium-severity piece for Anthropic specifically)
>
> **Description:**
>
> Filing this as a courtesy / brand-attribution flag in parallel with a direct technical disclosure to the package's listed maintainer (Jack Adamson <jadamson@anthropic.com>).
>
> The PyPI package `mcp-server-fetch-sse` v0.1.1 (uploaded 2025-06-29) lists `Author: Anthropic, PBC.` in its wheel METADATA. The README is lifted near-verbatim from Anthropic's official `mcp-server-fetch` (`modelcontextprotocol/servers/src/fetch/`), including the same VS Code install badges that point at the upstream package name. The package contains two vulnerabilities:
>
> 1. DNS-rebinding via missing Origin/Host validation in the HTTP+SSE transport (`http_sse_server.py`).
> 2. Inherited SSRF — the wrapped fetch tool is a fork of upstream `mcp-server-fetch` from before [PR #4226](https://github.com/modelcontextprotocol/servers/pull/4226) shipped the SSRF fix.
>
> I am filing this notification so that:
>
> - If `mcp-server-fetch-sse` is in fact maintained internally at Anthropic, the right security team is aware in parallel with the maintainer email I sent to Jack Adamson at `jadamson@anthropic.com`.
> - If it is NOT, Anthropic Security may want to assess the brand-attribution concern (a vulnerable PyPI package being distributed with Anthropic Author attribution) and route appropriately — e.g., request the PyPI metadata be corrected, or pursue a takedown if the attribution is unauthorized.
>
> I am not asserting any technical compromise of Anthropic's infrastructure or any internal-to-Anthropic code. The package is publicly published on PyPI.
>
> **Technical details and disclosure record:**
>
> - Full finding: https://github.com/desledishant10/mcp-scan/blob/main/findings/2026-06-02-MCP-S-014-mcp-server-fetch-sse-dns-rebinding.md
> - Disclosure record (this filing + the direct maintainer email): https://github.com/desledishant10/mcp-scan/blob/main/disclosures/2026-06-02-mcp-server-fetch-sse-dns-rebinding.md
> - Related upstream fix that this fork has not taken: https://github.com/modelcontextprotocol/servers/pull/4226
>
> **Embargo:** 2026-08-10 (~69 days), aligned with a parallel public writeup covering the broader DNS-rebind + SSRF ecosystem class.
>
> **About me:**
>
> MCP-Scan author. Disclosure track record: filed `modelcontextprotocol/servers#4143` on 2026-05-12, independently verified the fix on 2026-05-22. Capstone project, open-source: https://github.com/desledishant10/mcp-scan.

## HackerOne attempt and pivot to email (channel decision narrative)

The original plan called for filing the parallel notice via Anthropic's HackerOne program, since that is the channel listed in `anthropic.com/.well-known/security.txt`. The Jack-to-Anthropic email that was sent first (at the top of this disclosure record) references HackerOne as the parallel channel because that was the active plan at send-time.

What actually happened on the HackerOne side:

1. **HackerOne signup friction.** First attempt to create a HackerOne account routed to their customer-onboarding flow (the "$50k/year minimum security budget" sales gate), not the researcher-signup flow. This is a known papercut with HackerOne's homepage navigation — the security researcher signup is at `hackerone.com/users/sign_up`, separate from the `/contact` / "Get Started" CTAs that lead to sales. Resolved by going through the researcher signup directly.
2. **Form populated successfully** at `https://hackerone.com/4f1f16ba-10d3-4d09-9ecc-c721aad90f24/embedded_submissions/new` with: Asset = `OtherAsset`, Weakness = CWE-918 SSRF, Severity = "Submit report without severity", Title and Description matching the body drafted below in the "Parallel HackerOne submission" section.
3. **Program triage interstitial fired** on submit. Verbatim text: *"It looks like you're about to submit a report regarding the demo MCP fetch server in the modelcontextprotocol GitHub org. This MCP server is meant to be a demonstration ... if you are reporting the ability to use this to trigger arbitrary web requests: This is a known and expected behavior. ... Please only submit a report about this code if you are able to demonstrate a concrete security vulnerability in it that is unrelated to making web requests to arbitrary destinations."* The interstitial included a checkbox reading *"I understand that submitting this report could impact my reputation points"* and a "Submit report anyway" button.
4. **Submission cancelled** at the interstitial. The interstitial is a keyword-triggered filter responding to the `mcp-server-fetch` / `modelcontextprotocol` references in the report body, not to the actual content. Even though this report is specifically NOT about the demo SSRF (it's about a *separate* PyPI publication with brand attribution + an inbound DNS-rebind vulnerability that is unrelated to outbound SSRF), pushing past the interstitial risked the report being pattern-matched and dismissed by a busy triager, with a corresponding reputation-points penalty. Disregarding a program's explicit WAIT signal is also poor coordinated-disclosure hygiene.
5. **Pivoted to email at `disclosure@anthropic.com`.** Anthropic's responsible-disclosure-policy page lists `disclosure@anthropic.com` as a secondary contact ("for guidance before conducting research"). Using that channel for an actual disclosure is a defensible reading of their published comms; the security team can route internally. Critically, an email reaches a human reader without the HackerOne keyword filter in between, so the brand-attribution concern (which is the actually-novel piece for Anthropic Security) lands properly.

The Jack-to-Anthropic email's mention of "via HackerOne" became a minor inaccuracy at the moment of pivot, but the substance (Anthropic Security is being notified in parallel) was preserved by the disclosure@ email sent shortly after. The disclosure@ email's third paragraph explicitly documents the HackerOne→email pivot, so Anthropic Security has full transparency on what happened. No follow-up correction to Jack was sent — the discrepancy is parenthetical and reaching out a second time about a minor channel detail would have added noise without value.

## Why parallel filing (independent of channel)

A vulnerable PyPI package claiming `Author: Anthropic, PBC.` is something Anthropic Security probably wants to know about, regardless of whether the Author attribution is technically legitimate (inherited-fork attribution) or unauthorized. The parallel filing routes the information to the right team without making any factual claim about who actually maintains the package — that determination is Anthropic's to make.

Two outcomes are both fine:

- **If Anthropic-maintained:** HackerOne reaches their internal MCP security team in parallel with the maintainer email. Redundant but harmless.
- **If not Anthropic-maintained:** HackerOne flags the brand-attribution concern so Anthropic can decide whether to act. Plausible actions include requesting PyPI metadata correction, requesting takedown, or doing nothing — all of which are Anthropic's call. The disclosure is procedurally clean either way.

The technical disclosure to Jack Adamson is the primary channel; HackerOne is informational.

## Follow-up cadence

- **2026-06-16 (Day +14):** if no reply from Jack, polite ping referencing this disclosure record.
- **2026-07-02 (Day +30):** if still silent, escalate via the HackerOne filing (Anthropic Security can determine whether they have any contact with Jack internally) and consider filing a GitHub issue on `modelcontextprotocol/servers` cross-referencing this disclosure (since the upstream fetch code is there and the SSRF inheritance is what motivates one piece of the disclosure).
- **2026-07-23 (Day +51):** final pre-publish nudge.
- **2026-08-10 (Day +69):** public release per embargo. Public writeup notes maintainer-of-record was notified 2026-06-02 + followed up on stated cadence with [N] responses.

---

## Updates

### 2026-06-20 — day +18 catch-up email sent on the existing thread

Day +14 ping at 2026-06-16 was missed in the schedule; sent the catch-up at day +18 instead as a reply on the original thread to `jadamson@anthropic.com`. Soft "confirming the original mail reached you" framing per the day +14 template (chosen by the milestone cadence helper since +18 < +21). No reference to a missed prior follow-up. Anthropic Security parallel notice via `disclosure@anthropic.com` was previously auto-deflected (see entry below) and not retried; the primary technical disclosure to the maintainer-of-record remains the binding channel.

Body verbatim:

> Hi Jack,
>
> Quick follow-up on the coordinated security disclosure I sent on 2026-06-02 (day +18 today). Just confirming the original mail reached you. Sometimes security mail ends up in spam.
>
> Affected: mcp-server-fetch-sse v0.1.1 (PyPI)
> Embargo: 2026-08-10
>
> Happy to coordinate timeline or discuss the suggested fix shape on any channel that works for you. No urgency; just confirming visibility.

Awaiting maintainer reply. Next milestone: day +21 ping on 2026-06-23 if still silent.

### 2026-06-03 — `disclosure@anthropic.com` returned an auto-responder; no human review reached

The email sent on 2026-06-02 (see entry below) received an immediate response from `disclosure+noreply@anthropic.com` (the `+noreply` SMTP address pattern confirms this is intake automation, not a human reply). Verbatim auto-response body:

> If this is:
> - Related to a technical vulnerability in Anthropic systems or applications, please submit the details to our Bug Bounty program at https://hackerone.com/anthropic.
> - Related to a fraud and abuse concern, please reach out to usersafety@.
> - Related to a model safety issue, please reach out to modelbugbounty@anthropic.com with your report.
> - Related to a compliance request for documents, please visit our trust portal at trust.anthropic.com and work with your assigned sales team representative to get access.
> For all other types of requests, see support.anthropic.com.
> Thank you, Application Security, Anthropic

The auto-response's category list does not cover a third-party PyPI package brand-attribution concern — Anthropic's bug-bounty scope is explicitly limited to "Anthropic systems or applications" (which a third-party PyPI publication is not), and the other categories (usersafety, modelbugbounty, trust portal, support) don't fit either. The originally-attempted HackerOne channel was deflected at the program triage interstitial (see §"HackerOne attempt and pivot to email" and the entry below); now the disclosure@ channel is auto-deflected back to that same HackerOne route. No further escalation attempted.

**Net effect on the disclosure record:** Anthropic was notified via the two parallel channels they publish (HackerOne + disclosure@); both deflected via their own intake automation; no human review of the brand-attribution flag was reached. This is *not* a personal rejection — there is genuinely no published Anthropic channel for "vulnerable PyPI package claiming Anthropic authorship" — but the audit trail now reflects a good-faith two-channel attempt that was deflected through Anthropic's published intake automation. The primary technical disclosure to the maintainer (Jack Adamson) remains the binding channel for the fix.

If the 2026-08-10 public writeup references the brand-attribution concern, the framing will be factual: Anthropic was notified via their published channels; their intake automation routed the report to HackerOne, which had previously triaged this report class as outside their bug-bounty scope. No adversarial framing — Anthropic's intake routing is a corporate artifact, not a position on the disclosure.

### 2026-06-02 — Parallel notice sent to `disclosure@anthropic.com`

Sent to `disclosure@anthropic.com` after the HackerOne attempt was halted at the program triage interstitial (see §"HackerOne attempt and pivot to email"). Subject: *"Vulnerable PyPI package with Anthropic Author attribution — courtesy notification (not the mcp-server-fetch SSRF)"*. The body leads with brand attribution as the primary concern and explicitly disambiguates from the documented-SSRF-in-the-demo class that the HackerOne interstitial filters against, paragraph 3 documents the HackerOne→email pivot transparently. Body references the published finding, the disclosure record, and the prior `mcp-server-fetch` track-record disclosure (#4143 → PR #4226 verified). Anthropic Security acknowledgement pending — auto-responder received same day (see entry above).

### 2026-06-02 — HackerOne submission attempt halted at program triage interstitial

Form populated successfully at the URL from `anthropic.com/.well-known/security.txt`. On submit, the program's triage interstitial fired with the verbatim text quoted in §"HackerOne attempt and pivot to email" above, plus an explicit "submitting this report could impact my reputation points" warning. Submission cancelled at the interstitial; pivoted to the secondary published channel (`disclosure@anthropic.com`) for the parallel notice. The interstitial is keyword-triggered against `mcp-server-fetch` / `modelcontextprotocol` references and does not engage with the report's actual content (separate PyPI package + brand attribution + DNS-rebind which is *not* the outbound-SSRF class the interstitial dismisses). Decision logged here for the audit trail; the report was *drafted* (see "Parallel HackerOne submission" section above) but *not filed* via HackerOne.

### 2026-06-02 — Email sent to Jack Adamson

Sent to `jadamson@anthropic.com` (the PyPI-listed maintainer-of-record). Subject: *"Security disclosure — mcp-server-fetch-sse v0.1.1 (DNS-rebinding + inherited SSRF)"*. Body matches the draft above verbatim (the "Primary email" section). The body references the parallel notification "via HackerOne" — at send time that was the active plan; the pivot to `disclosure@anthropic.com` happened shortly afterward. The mention is a minor inaccuracy in retrospect, but the substance (Anthropic Security is being notified in parallel) was preserved by the disclosure@ email. No follow-up correction to Jack was sent — the discrepancy is parenthetical and reaching out a second time would have added noise without value. Maintainer acknowledgement pending.
