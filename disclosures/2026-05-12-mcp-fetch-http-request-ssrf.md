# Default SSRF surface in Python MCP HTTP-client servers (mcp-server-fetch, mcp-server-http-request)

**Filed:** 2026-05-12
**Filed by:** Dishant Desle — didesle7@gmail.com
**Filed to:**
- `mcp-server-fetch`: **filed** — https://github.com/modelcontextprotocol/servers/issues/4143
- `mcp-server-http-request`: pending (upstream repo TBD via PyPI page)
**Affected:**
- `mcp-server-fetch` v2025.4.7 (PyPI; Anthropic reference)
- `mcp-server-http-request` v0.1.0 (PyPI; community)
**Embargo:** 2026-08-10 (90 days from filing)
**Status:** filed (mcp-server-fetch); pending (mcp-server-http-request)

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

### 2026-05-12 — `mcp-server-fetch` issue filed

Filed as **modelcontextprotocol/servers#4143**: https://github.com/modelcontextprotocol/servers/issues/4143

Title used: `Security: mcp-server-fetch lacks SSRF protection; cloud-hosted agent hosts can leak IAM credentials`

Body posted matches the "Body of the filed report" section above verbatim (with the Contact line populated). Awaiting maintainer triage and assignment of a security label.

Next checkpoints:
- **2026-05-26 (Day +14):** if no acknowledgement, polite ping on the issue thread.
- **2026-06-11 (Day +30):** if no engagement, escalate via Anthropic security contact (if available) or via the repo's `SECURITY.md`.
- **2026-08-10 (Day +90):** public release per embargo, regardless of fix status.

### Pending: `mcp-server-http-request` filing

The community package needs a separate issue against its upstream repo. To find it: PyPI page → "Homepage" or "Source" link. The disclosure body for that filing should adapt the report above to single-package context and cross-reference modelcontextprotocol/servers#4143 to frame as same-class.
