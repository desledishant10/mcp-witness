# Default SSRF surface in Python MCP HTTP-client servers (mcp-server-fetch, mcp-server-http-request)

**Filed:** 2026-05-12
**Filed by:** Dishant Desle — didesle7@gmail.com
**Filed to:**
- `mcp-server-fetch`: **RESOLVED — fixed upstream by default in a shipped release** — issue [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) (closed `not_planned` 2026-07-30); community fix PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) by @kgarg2468 was never merged and was closed 2026-10-28 under the repo's new issues-only contribution policy; the vulnerability was instead fixed by maintainer PR [#5033](https://github.com/modelcontextprotocol/servers/pull/5033) (merged 2026-10-05, fixes #4838), shipped default-on in PyPI `2026.10.10`+ (see Updates 2026-10-28)
- `mcp-server-http-request`: **maintainer-confirmed unmaintained (2026-06-11); package removed from PyPI (no longer installable) as of 2026-10-28** — email to esteban@statespace.com, gavin@statespace.com (no public issue tracker); see Updates
**Affected:**
- `mcp-server-fetch` `<= 2026.8.18` (PyPI; Anthropic reference) — fixed in `2026.10.10` (first guarded release; byte-verified)
- `mcp-server-http-request` v0.1.0 (PyPI; community) — unmaintained; no fix shipped; **removed from PyPI 2026-10-28** (no longer installable)
**Embargo:** 2026-08-10 (90 days from filing — both packages)
**Status:** **RESOLVED (mcp-server-fetch): fixed upstream by default, PyPI `2026.10.10`+, runtime-verified 2026-10-28. mcp-server-http-request: maintainer-confirmed-unmaintained 2026-06-11 and removed from PyPI 2026-10-28 (no longer installable); no fix shipped.**

---

## Body of the filed report (ready to paste)

> ### Summary
>
> Two PyPI-published Python MCP servers — `mcp-server-fetch` (Anthropic reference) and `mcp-server-http-request` (community) — accept arbitrary URLs from agent tool calls and pass them to `httpx.get()` with no scheme allowlist, no host denylist, and no protection against link-local cloud-metadata addresses. On cloud-hosted agent hosts (EC2, GCP, Azure VMs, ECS tasks), an agent coerced via prompt injection into calling these tools with a metadata-service URL will exfiltrate IAM credentials.
>
> The vulnerability is fully mitigated on Amazon Linux 2023 instances launched with default IMDSv2-Required metadata options (the AL2023 default since 2024), but remains exploitable on:
> - Instances explicitly configured `HttpTokens=optional`
> - Instances launched from older AMIs (AL2 and earlier)
> - GCP and Azure metadata services (different default postures)
> - Internal HTTP services reachable from the agent host (RFC 1918 ranges, in-cluster service IPs)
>
> The same root cause — no in-package scheme/host validation — means host-level mitigation is insufficient as defense-in-depth. The fix belongs in the package itself.
>
> ### Demonstration
>
> Performed against `mcp-server-fetch` v2025.4.7 on an EC2 `t3.micro` (Amazon Linux 2023 AMI, region us-east-1) with IMDSv2 set to Optional. Full reproduction runbook: https://github.com/desledishant10/mcp-scan/blob/main/docs/audit-runbook-ec2-ssrf-verification.md
>
> Reproduction in summary:
>
> 1. Launch a `t3.micro` AL2023 instance with any IAM role attached (we used a role with `AmazonEC2ReadOnlyAccess`).
> 2. Console → instance → Modify metadata options → IMDSv2: Optional.
> 3. SSH in; install Python 3.11+ and `mcp-server-fetch`.
> 4. Run a 15-line MCP client harness asking `fetch` to retrieve `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>/`.
>
> Result (redacted): the tool returned the JSON `{"Code":"Success", "AccessKeyId":"ASIA****", "SecretAccessKey":"wJal****", "Token":"AQoD****", "Expiration":"..."}` — a complete, valid AWS IAM credential triplet. Same outcome expected on `mcp-server-http-request` because the root cause is identical (we didn't separately verify on EC2 in the same session).
>
> ### Why this is a class issue, not a single-package issue
>
> The same scanning workflow (run `mcp-scan-analyze` against the captured `tools/list` of each package) flags both with [MCP-S-009](https://github.com/desledishant10/mcp-scan/blob/main/docs/static-rules.md) — "URL-fetching tool with no apparent allowlist" — based solely on the absence of a JSON Schema `pattern` constraint and the absence of validation keywords in the tool descriptions. Both packages are *symptomatic* of an ecosystem norm in which MCP server authors model the URL parameter as an unconstrained string and trust the agent to be responsible. That norm is wrong: the threat model for MCP servers explicitly includes adversarially-influenced tool arguments via prompt injection.
>
> ### Suggested remediation
>
> A small `mcp-server-url-safety` utility module (or an inline check in each affected package) that:
>
> 1. Allowlists `http://` and `https://` only.
> 2. Resolves the hostname to its IP and rejects RFC-reserved ranges before making the request:
>    - `169.254.0.0/16` (link-local, all cloud-metadata addresses)
>    - `127.0.0.0/8`, `::1` (loopback)
>    - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 private)
>    - `fc00::/7` (IPv6 ULA)
>    - `0.0.0.0/8` (current network)
> 3. Allows an environment-variable opt-in to a customizable allowlist for users who legitimately need to fetch from internal services.
>
> The opt-in pattern is what `mcp-server-fetch`'s existing `--ignore-robots-txt` flag models. The default should be safe; users who know what they're doing can opt out explicitly.
>
> ### Embargo
>
> I'd like to coordinate disclosure with the standard 90-day window. Public release planned for 2026-08-10 unless a fix is in active development, in which case happy to extend. Public release would include this writeup plus the reproduction runbook (no exploit payloads beyond what's already in the public scanner).
>
> I'm happy to test a candidate fix against both packages if you'd like a verification round before release.
>
> ### Tooling
>
> Findings produced by MCP-Scan, an open-source security scanner for MCP servers and AI agents I'm building as a capstone project. Code and full audit trail: https://github.com/desledishant10/mcp-scan
>
> ### Contact
>
> Dishant Desle - didesle7@gmail.com
>
> Thanks for taking a look.

---

## Suggested submission steps

1. **`mcp-server-fetch` filing** (the Anthropic reference — this is the higher-profile one):
   - Open https://github.com/modelcontextprotocol/servers/issues/new
   - Title: `Security: mcp-server-fetch lacks SSRF protection; cloud-hosted agent hosts can leak IAM credentials`
   - Body: paste the report above (only the `> `-prefixed lines, with leading `> ` stripped)
   - Don't @-mention specific maintainers; the security label or a triage will route it
   - **Do not include unredacted credentials anywhere.**

2. **`mcp-server-http-request` filing** (community package):
   - PyPI page: https://pypi.org/project/mcp-server-http-request/
   - Click the "Homepage" or "Source" link to find the GitHub repo
   - File a similar issue (title can be `Security: same SSRF class as mcp-server-fetch — no default URL validation`, body adapted)
   - Cross-link the `mcp-server-fetch` issue

3. **Internal record-keeping** (back here):
   - Append an `## Updates` section to this file with the filing date + the issue URL once posted.
   - Update the `Status:` line at the top from `draft` to `filed`.
   - Push the update.

## Why file both at once

Same root cause across two packages — submitting both on the same day frames the disclosure as ecosystem-wide guidance request rather than per-package finger-pointing. Better tone for community reception.

## What happens if maintainers don't respond

Standard practice:
- **Day +14:** polite ping comment on the issue, "any update?"
- **Day +30:** escalate via the project's documented security contact (security.md, SECURITY contact, or a maintainer email if listed)
- **Day +60:** notify the broader community (e.g., MCP discussion forums, related projects)
- **Day +90:** public release as planned

Updates to this file should reflect each of those touchpoints.

---

## Updates

### 2026-10-28 — RESOLVED: fix shipped default-on upstream; tracking PR closed under new policy

Three developments landed together today, resolving the `mcp-server-fetch` track.

**The vulnerability is fixed upstream, on by default, in a shipped release.** Maintainer PR [#5033](https://github.com/modelcontextprotocol/servers/pull/5033) ("fix(fetch): refuse private, loopback and metadata addresses by default", fixes #4838) merged to `v2/main` on 2026-10-05. The fix is a `_NON_PUBLIC_NETWORKS` denylist (loopback, RFC 1918, `169.254.0.0/16` link-local covering cloud metadata, `100.64.0.0/10`, `fc00::/7`, `fe80::/10`, IPv4-mapped and NAT64) checked by `_is_public_address()` and enforced as an `httpx` request event hook (`_refuse_private_destination`) that runs before every request, redirect hops included, so a public URL cannot bounce the fetch to an internal address. It is on by default and can only be disabled with `--allow-private-ips`. This is the fix shape the original disclosure asked for, and broader.

**Shipped releases (byte-verified against PyPI sdists).** The guard is absent at git tag `2026.8.31` and in the last vulnerable PyPI release `2026.8.18`, and present in `2026.10.10` (first guarded release, uploaded 2026-10-11) through the current `2026.10.28` (uploaded 2026-10-28). Affected range: `<= 2026.8.18`; fixed-in release: `2026.10.10`.

**Independent runtime verification.** The [`poc/ssrf/`](../poc/ssrf/) harness was re-run against `mcp-server-fetch==2026.10.28` via `make demo-fixed-release`: the same `fetch("http://169.254.169.254/latest/meta-data/...")` call that returned the fake `AKIA-FAKE` credential on `2025.4.7` now returns *"Refused to fetch ...: ... which is not a public address. Start the server with --allow-private-ips ..."* The harness classifier was updated to recognize the shipped refusal wording, which differs from the never-merged PR #4226 message.

**The tracking PR was closed, not merged.** Community fix PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) by @kgarg2468 — CI green, externally reviewed, the proposed fix this record had tracked since 2026-05-22 — was closed unmerged on 2026-10-28. The repo adopted an issues-only contribution policy (CONTRIBUTING.md: *"We accept issues, not pull requests. Design and implementation are done by the repository maintainers."*), so outside PRs are closed rather than reviewed, and the maintainer-authored #5033 superseded it.

**Causation note (for honesty in any public writeup).** The original disclosure #4143 was closed `not_planned`, and the shipped fix references a different issue (#4838). This record does not claim the disclosure caused the fix. What it documents is an independent 2026-05 disclosure of the SSRF class, a public reproduction harness maintained across three vulnerable releases, and a correct prediction of the fix shape — now resolved upstream.

### 2026-10-28 — mcp-server-http-request removed from PyPI (no longer installable)

`mcp-server-http-request` is no longer installable from PyPI as of 2026-10-28. The programmatic JSON API (`https://pypi.org/pypi/mcp-server-http-request/json`) and the pip simple index (`https://pypi.org/simple/mcp-server-http-request/`) both return HTTP 404, whereas on 2026-09-10 the package was live and installable at 0.1.0 (a known-good control package returns 200 on the same endpoints today, so this is package-specific, not a PyPI outage).

The exact mechanism — full project deletion vs. deletion of the sole 0.1.0 release — could not be confirmed from public endpoints: the HTML project page sits behind PyPI's bot-challenge and was not scraped. Either way the install vector is gone, which satisfies the yank / deprecation-notice request that had been pending with the maintainer (who confirmed the package unmaintained on 2026-06-11). Recorded as risk-removed, removal mechanism unconfirmed.

### 2026-06-11 — Gavin Chan replied on LinkedIn: package is unmaintained

A few hours after the day +30 LinkedIn DMs went out (see entry below), Gavin Chan replied on his own LinkedIn DM thread with: *"Hey thanks for reaching out. That's not an actively maintained package."*

Significance:
- **Maintainer identity confirmed.** The LinkedIn channel reached a verified cofounder who acknowledges the package. Same identity match as the `Author-email` field in the PyPI wheel metadata.
- **Status confirmed.** Statespace is not actively maintaining `mcp-server-http-request` v0.1.0. This explains the email silence cleanly — no spam-filter mystery, no wrong-address theory, the package itself is orphaned.
- **No commitment to fix.** "Not actively maintained" implies no patch is coming.
- **No commitment yet to yank or deprecate.** Worth following up on — see next step.

Sent a brief follow-up DM on the same thread asking whether Gavin would consider yanking v0.1.0 on PyPI + adding an "unmaintained" notice to the README. Yanking is ~10 minutes of work and would meaningfully reduce real-world risk for anyone who runs `pip install mcp-server-http-request` after the public writeup lands. Framed as a request, not a demand; offered to provide the exact PyPI deprecation steps + a one-paragraph notice draft if useful. Made clear that if yanking isn't an option, the public writeup will still proceed on 2026-08-10 with the maintainer-confirmed-unmaintained framing.

**Updated escalation plan (Statespace track now closed regardless of yank decision):**
- Day +45 (2026-06-26): **no escalation needed.** Maintainer has responded; soft-channel playbook is no longer relevant for this disclosure. If Gavin agrees to yank, post the yank confirmation in this disclosure record + adjust the public writeup framing.
- Day +60 (2026-07-11): if no further reply on the yank ask, send one polite nudge with the prepared deprecation steps.
- Day +90 (2026-08-10): publish per embargo with the documented "maintainer confirmed unmaintained" framing. Whether yank happened or not goes in the writeup as data.

The day +30 escalation is the highest-value outcome of this disclosure track to date — it demonstrates that the LinkedIn-DM channel is materially more effective than email for small-team unmaintained-package scenarios. Worth recording as a methodology lesson for future disclosure-track work.

### 2026-06-11 — day +30: LinkedIn DMs sent to both cofounders

PyPI wheel metadata for `mcp-server-http-request` v0.1.0 confirms `esteban@statespace.com` + `gavin@statespace.com` as the canonical `Author-email` (verified by inspecting the wheel METADATA file directly). The two emails sent on 2026-05-12 and 2026-06-02 were delivered without SMTP bounces — the address routing works — but never received a reply. `statespace.com` is reachable for email but the website does not load (verified independently; also linked from Esteban Safranchik's own LinkedIn profile as the company URL, where it likewise fails to load), suggesting Statespace as a company may be wound down or inactive.

Soft-channel escalation today via LinkedIn. Both cofounders' profiles independently verified — Esteban Safranchik and Gavin Chan both list "Statespace" / "Cofounder" on LinkedIn, identity-matched against the `Author-email` field in the wheel. DMs sent to both. Body of the DMs offered the polite escape valve — "if statespace is wound down and the package is unmaintained, just let me know and the public writeup will note that" — which often surfaces a response from otherwise-silent maintainers because it acknowledges the most likely real-world explanation for the silence.

The naming collision with `statespace.gg` / `statespacelabs` (a Unity / esports company) is coincidental — that GitHub org has 16 repos, none MCP-related; not the same Statespace.

If both DMs are silent at day +45 (2026-06-26), the soft-channel playbook is exhausted. Day +60 (2026-07-11) will be a final-notice email on the thread explicit about the 2026-08-10 publish date. Day +90: publish per embargo. The disclosure record at that point will show good-faith effort beyond the normal standard, with documented channel-by-channel attempts (2 emails, 2 LinkedIn DMs).

### 2026-06-02 — day +21 follow-up ping sent to `mcp-server-http-request` maintainers

No response from `esteban@statespace.com` or `gavin@statespace.com` since the 2026-05-12 filing. Day +14 (2026-05-26) ping was missed in the schedule; sent the follow-up today at day +21 instead. Reply attached to the original thread (not a new thread) so it bumps in their inbox. Brief, non-pushy: references the parallel `mcp-server-fetch` fix shipping + verification as substantive new information that justifies the follow-up, restates suggested fix shape, restates 2026-08-10 embargo. No new ask.

If still silent at day +30 (2026-06-11), escalate via:
- LinkedIn DM to Esteban Safranchik and/or Gavin Chan (statespace.com employees, public)
- `statespace.com` contact form
- GitHub user-profile lookup for either maintainer

If silent through 2026-08-10: publish per embargo, public writeup notes maintainer was notified 2026-05-12 + followed up 2026-06-02 with no response.

Body as sent (quoted as provided by the sender):

> Hi Esteban, Gavin,
>
> Just following up on the disclosure I sent 2026-05-12 for
> mcp-server-http-request v0.1.0. Want to make sure it reached you.
>
> For context on timeline: the parallel disclosure on mcp-server-fetch
> (modelcontextprotocol/servers#4143) had a fix PR submitted within 10
> days and I independently verified the fix on 2026-05-22 — the SSRF
> that previously exfiltrated IAM credentials now refuses cleanly. The
> fix shape that worked there (scheme allowlist + RFC-reserved-range
> host denylist + per-redirect validation) is the same one I suggested
> for your package.
>
> Happy to discuss timeline, alternative remediation, or help implement
> the fix. Original 90-day embargo remains 2026-08-10.
>
> Thanks,
> Dishant

### 2026-05-22 — fix PR independently verified

Same demo script that produced the IAM credential exfil on EC2 was re-run against the fix branch (`kgarg/harden-fetch-ssrf`), this time installed locally — sufficient because the new validation logic checks IP class *before* attempting the network request, so the refusal is observable without metadata reachability.

Before the fix (EC2 verification 2026-05-12, `mcp-server-fetch` v2025.4.7):

```
{"Code":"Success", "AccessKeyId":"ASIA****", "SecretAccessKey":"wJal****",
 "Token":"AQoD****", "Expiration":"2026-05-12T..."}
```

After the fix (local verification 2026-05-22, `mcp-server-fetch` v0.6.3 from the PR branch):

```
Fetching private or non-public IP addresses is not allowed
```

Refusal happens at the validation layer with a clean error message — no network attempt. The per-redirect validation in the PR also closes the 302-bypass path (a public URL redirecting to `169.254.169.254` would otherwise have escaped a first-request-only check; the PR validates after each redirect).

Second comment posted on the PR confirming the verification.

### 2026-05-22 — fix PR opened against `mcp-server-fetch`

PR [modelcontextprotocol/servers#4226](https://github.com/modelcontextprotocol/servers/pull/4226) by `@kgarg2468` opened with title *"fix(fetch): block private network URL fetches"* and the body explicitly listing `Fixes #4143`. The PR's commit summary describes the fix as:

- Validate fetch URLs use `http` / `https` scheme
- Resolve hostnames and reject targets that aren't public IP addresses
- Block `localhost`, private, loopback, link-local, and metadata-service targets
- Follow redirects manually so redirected targets are validated before each request

The redirect-validation step is a *more rigorous* defense than the original disclosure asked for. Without it, an attacker could host a public URL that 302-redirects to `http://169.254.169.254/...` — the in-package scheme/host check would have passed on the initial request and the metadata leak would still occur. Per-redirect validation closes that bypass.

All 16 CI checks pass on the PR. It's awaiting at least one approving review from a maintainer with write access. The fix is on branch `kgarg/harden-fetch-ssrf` if anyone wants to install from the branch and verify.

Half of the class-wide finding is now resolved on the technical side, pending merge. The community half (`mcp-server-http-request`) still has no maintainer response.

### 2026-05-12 — `mcp-server-fetch` issue filed

Filed as **modelcontextprotocol/servers#4143**: https://github.com/modelcontextprotocol/servers/issues/4143

Title used: `Security: mcp-server-fetch lacks SSRF protection; cloud-hosted agent hosts can leak IAM credentials`

Body posted matches the "Body of the filed report" section above verbatim (with the Contact line populated). Awaiting maintainer triage and assignment of a security label.

Next checkpoints:
- **2026-05-26 (Day +14):** if no acknowledgement, polite ping on the issue thread.
- **2026-06-11 (Day +30):** if no engagement, escalate via Anthropic security contact (if available) or via the repo's `SECURITY.md`.
- **2026-08-10 (Day +90):** public release per embargo, regardless of fix status.

### 2026-05-12 — `mcp-server-http-request` email sent

Sent via email to both listed maintainers — `esteban@statespace.com` and `gavin@statespace.com` — using the draft below verbatim (with the minor tone tweaks discussed during preparation).

Same 90-day embargo (2026-08-10). Same follow-up checkpoints: day +14 (2026-05-26) ping, day +30 (2026-06-11) escalate, day +90 release.

Both halves of the class-wide finding (Anthropic reference + community package) are now in flight.

### Originally pending: `mcp-server-http-request` filing (email-based)

The PyPI page lists no homepage, no source URL, and no issue tracker. Only contact channel is the maintainer emails listed in the PyPI metadata:

- Esteban Safranchik — `esteban@statespace.com`
- Gavin Chan — `gavin@statespace.com`

(statespace.com is the publishing org)

Email disclosure is the right channel here — direct to maintainers, with the same 90-day embargo. Email draft below; ready to send.

---

**To:** esteban@statespace.com, gavin@statespace.com
**CC:** *(your email)*
**Subject:** Security: SSRF in mcp-server-http-request (coordinated disclosure, 90-day embargo)

> Hi Esteban, Gavin,
>
> I'm reaching out as a coordinated security disclosure for `mcp-server-http-request` v0.1.0 on PyPI. Filing by email since the package metadata doesn't list a public issue tracker — happy to move to a private channel of your choice if you have one.
>
> **TL;DR:** Same SSRF class as Anthropic's reference `mcp-server-fetch` (disclosed same day as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143)). Your package has no scheme allowlist, no host denylist, and no protection against link-local cloud-metadata addresses. On any cloud-hosted agent host running IMDSv1 or IMDSv2-Optional, an agent prompt-injected into calling `http_get` with an IMDS URL will exfiltrate IAM credentials.
>
> **Why I'm flagging yours alongside Anthropic's:** The root cause is identical and the fix shape is identical. Filing both in the same week reduces the chance that one package gets patched while the other lingers, and frames the disclosure as ecosystem-level guidance rather than per-package finger-pointing.
>
> **Reproduction:** Identical to the Anthropic finding. Full runbook at https://github.com/desledishant10/mcp-scan/blob/main/docs/audit-runbook-ec2-ssrf-verification.md — substitute `mcp_server_http_request` for `mcp_server_fetch` in the demo script. (I verified the fetch path on an EC2 `t3.micro` 2026-05-12 with real IAM credentials retrieved; haven't separately verified yours on EC2 because the underlying issue is identical, but happy to do so if you'd like an explicit reproduction artifact for your own records.)
>
> **Suggested fix:** Mirrors what I proposed to Anthropic — a small in-package URL validator that
>
> 1. Allowlists `http://` and `https://` schemes only.
> 2. Resolves the hostname and rejects RFC-reserved ranges before making the request:
>    - 169.254.0.0/16 (link-local, all cloud-metadata addresses)
>    - 127.0.0.0/8, ::1 (loopback)
>    - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
>    - fc00::/7 (IPv6 ULA)
>    - 0.0.0.0/8
> 3. Provides an opt-in env-var override for users who need to reach internal services.
>
> Five tools in your package (`http_get`, `http_post`, `http_put`, `http_patch`, `http_delete`) all share the surface, so the validator goes once at the request-issuing layer.
>
> **Embargo:** I'd like to coordinate disclosure with a standard 90-day window. Public release planned for 2026-08-10 unless you've shipped a fix or want to extend, in which case happy to accommodate.
>
> **Tooling and disclosure record:** Findings are produced by MCP-Scan, an open-source MCP security scanner I'm building. Full audit trail (including this disclosure draft and the public status of the Anthropic filing) lives at https://github.com/desledishant10/mcp-scan. The detailed finding entry for your package is at https://github.com/desledishant10/mcp-scan/blob/main/findings/2026-05-11-MCP-D-003-http-request-direct-environment-dependent-ssrf.md.
>
> Happy to verify any candidate fix before you ship it.
>
> Thanks for taking a look,
> Dishant Desle
> didesle7@gmail.com

---

After sending, update the `Status:` line at the top of this file to reflect both filings, and append an Updates entry below.
