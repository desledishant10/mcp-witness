# [DRAFT — for publication on or after 2026-08-10] MCP servers and the SSRF blind spot

> **Status:** embargo draft. Public release scheduled for 2026-08-10, the 90-day expiration of the coordinated disclosure of [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143). Sections marked `[TODO post-embargo]` will be updated with maintainer responses and any patch references before publication.

---

# MCP servers and the SSRF blind spot: how two Python packages leak cloud credentials

## TL;DR

In May 2026 I disclosed a class-wide environment-dependent SSRF across two PyPI-published Python MCP servers — Anthropic's reference `mcp-server-fetch` and the community-published `mcp-server-http-request`. On any cloud-hosted agent host where the AWS / GCP / Azure metadata services are reachable (i.e., the default for older AMIs and any AL2023 instance with IMDSv2 set to Optional), an agent that gets prompt-injected into calling the HTTP-fetch tool with a metadata URL exfiltrates IAM credentials. Both packages have the same root cause: no scheme allowlist, no host denylist, no awareness of link-local addresses. The post walks through the discovery (a static rule firing on the captured `tools/list`), the dynamic verification, the EC2 demonstration with real credentials, and what the MCP ecosystem can do about it.

Two notes up front: (1) on Amazon Linux 2023 with default IMDSv2-Required, the bug is fully mitigated at the host level — the package never sends the required token header, so IMDS responds 401. The vulnerability is still real because (a) IMDSv2 isn't required on older AMIs, (b) operators legitimately set IMDSv2 to Optional for compatibility, (c) GCP and Azure metadata services have different default postures, and (d) RFC 1918 internal services don't have any IMDSv2-equivalent. (2) The disclosure was filed on 2026-05-12 with both maintainers. Public release respects the standard 90-day window. *[TODO post-embargo: fix status and any patches]*.

## What MCP is and why this surface exists

The Model Context Protocol — adopted by Anthropic's Claude, OpenAI's ChatGPT, Cursor, Zed, and a growing list of AI hosts — lets agents discover and invoke tools defined by external "MCP servers". A typical server exposes a list of tools, each with a name, a natural-language description, and a JSON Schema for arguments. The agent sees those, decides when to call them, and feeds the results back into the conversation.

For HTTP-fetch tools specifically — the most common kind of MCP server, by my survey of PyPI — the tool boils down to a single function: take a URL from the agent's arguments, fetch it, return the response. There's almost always a parameter named `url` typed as `string` with `format: uri`. That's it. The server trusts the agent to be responsible; the agent might or might not be.

For most non-cloud deployments, this trust is fine. For cloud-hosted agent hosts, it's a credential exfiltration primitive waiting to be activated.

## The discovery: a static rule that fires on metadata-shaped surfaces

I built [MCP-Scan](https://github.com/desledishant10/mcp-scan) as a security testing toolkit for MCP servers — static analyzer + dynamic harness + capability classifier — with the goal of auditing the popular packages systematically. The static analyzer rule **MCP-S-009** flags URL-fetching tools that lack any apparent allowlist:

- the tool has a parameter named `url`/`uri`/`endpoint` or with `format: uri`, **and**
- no JSON Schema `pattern`/`const`/`enum` constraint on that parameter, **and**
- no validation keywords in the tool description (`allowlist`, `scheme is`, `restricted to`, etc.)

That's heuristic — necessary-but-not-sufficient — but it's a high-precision "review this" prompt. Run it against the captured `tools/list` from `mcp-server-fetch`:

```bash
$ mcp-scan-capture --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch \
    -o /tmp/fetch.json
$ mcp-scan-analyze /tmp/fetch.json
[HIGH] MCP-S-009  <captured>:0  fetch
    Tool has URL parameter(s) ['url'] with no schema-level constraint and no
    validation keywords in the description. Likely no scheme allowlist or
    host denylist — verify against SSRF to link-local / loopback / cloud-
    metadata addresses.
```

Run the same against `mcp-server-http-request`: same finding, multiplied by 5 (one per HTTP method).

## Dynamic verification: it's not just a pattern, it's a path

Static rules tell you "this might be vulnerable, look closer." For confidence, you also need a dynamic probe. I built **MCP-D-003** as a scenario that connects to a running server and tries:

- The harness's own canary URL (proves arbitrary egress)
- AWS IMDSv1 metadata service
- ECS task-role endpoint
- GCP `metadata.google.internal`
- Azure IMDS
- Loopback ports
- `file://` URIs
- Non-HTTP schemes (gopher, dict)

Against `mcp-server-fetch` on a dev machine, the result was interesting and *misleading* on first read. The canary endpoint got hit (it's a fetch tool, it fetched). The metadata addresses all failed with `"Failed to fetch robots.txt due to a connection issue"`. The `file://` URIs same. Looked like it had defenses!

But the mechanism was telling. `mcp-server-fetch` does a *politeness check* — fetches `robots.txt` first, then the requested URL only if robots.txt was reachable. On a dev machine, 169.254.169.254 isn't routable, so the robots.txt fetch fails at the TCP layer, and `mcp-server-fetch` bails. **That's an accidental SSRF defense, not a deliberate one.** It only works when the target host doesn't respond to TCP. On any cloud instance where the metadata service does respond to TCP (which is, you know, *all of them*), the robots.txt fetch succeeds with 404 (IMDS has no robots.txt), and `mcp-server-fetch` proceeds to fetch the real URL.

`mcp-server-http-request` doesn't even have this accidental defense — it skips the robots.txt check entirely, just makes the request and waits for a timeout if the host isn't there.

## EC2 demonstration: real credentials

Hypothesis: on actual EC2, the failure mode would be different and credentials would actually come back. Verification time. I launched a `t3.micro` (Amazon Linux 2023, us-east-1), attached an IAM role with `AmazonEC2ReadOnlyAccess`, set IMDSv2 to Optional (the default is Required, which itself mitigates this bug — more on that below), installed `mcp-server-fetch`, and asked it to fetch the IMDS credentials URL via an MCP client harness.

Result, redacted:

```
--- calling fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/') ---

Contents of http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/:
{
  "Code" : "Success",
  "AccessKeyId" : "ASIA****",
  "SecretAccessKey" : "wJal****",
  "Token" : "AQoD****",
  "Expiration" : "2026-05-12T..."
}
```

A working AWS IAM credential triplet, returned by an MCP tool, retrievable by anything that can convince an agent to call `fetch("http://169.254.169.254/...")`. The role and instance were torn down within minutes of capture; credentials expired with their normal lifetime. Full reproduction runbook is in the [MCP-Scan repo](https://github.com/desledishant10/mcp-scan/blob/main/docs/audit-runbook-ec2-ssrf-verification.md).

This is the disclosure-grade artifact. From an attacker's perspective, the chain is: prompt injection → agent calls `fetch` with IMDS URL → credentials returned → attacker pivots to whatever the IAM role permits.

## The class-wide observation: two packages, one root cause

`mcp-server-fetch` and `mcp-server-http-request` are independently maintained — different authors, different version histories, different release cadences. They share `httpx` as their HTTP client (with `httpx<0.28` pinned), and they share an approach to URL handling: take whatever the agent says, pass it to `httpx.get()`, return the response. Neither implements scheme allowlisting, host denylisting, or any awareness of link-local ranges.

This is the more important finding. It's not "a buggy package." It's "an ecosystem norm." Every Python MCP HTTP-client server I've looked at follows the same pattern — the URL parameter is modeled as an unconstrained string, and the assumption is that the agent will be responsible for what URLs it asks to fetch. That assumption is wrong, because the threat model for MCP servers explicitly includes adversarially-influenced tool arguments via prompt injection.

The fix is small and shared across packages. Even better, it should probably be a shared utility:

```python
def safe_fetch_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved:
        raise ValueError(f"Refusing to fetch reserved address: {ip}")
    return httpx.get(url).text
```

That's ~10 lines per package, or ~10 lines once in a shared `mcp-server-url-safety` utility that the ecosystem can depend on. The mitigation pattern is straightforward; the question is whether the maintainers and the ecosystem adopt it.

## Disclosure timeline

- **2026-05-11** — discovery via MCP-Scan static rule; dynamic verification on dev machine
- **2026-05-12 morning** — EC2 reproduction with real IAM credentials retrieved
- **2026-05-12 afternoon** — coordinated disclosure filed:
  - GitHub issue: [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) (`mcp-server-fetch`)
  - Email to maintainers (`mcp-server-http-request`)
- **2026-05-26** — first follow-up checkpoint (planned)
- **2026-06-11** — escalation checkpoint (planned)
- **2026-08-10** — embargo expiration, public release (this post)

*[TODO post-embargo: maintainer responses, patches shipped, CVE numbers if assigned]*

## What the ecosystem should do

For MCP server authors building anything that touches network egress (or any IO sink with cloud-environment relevance):

1. **Don't trust the URL parameter.** Whatever the agent passes in might be attacker-controlled even if the agent itself is honest. Validate scheme and host before issuing the request.
2. **Reject reserved IP ranges by default.** Link-local (169.254/16), loopback (127/8, ::1), RFC 1918 private (10/8, 172.16/12, 192.168/16), IPv6 ULA (fc00::/7). Provide an opt-in for users who need internal access.
3. **Schema-constrain when possible.** A `pattern` or `enum` on the URL parameter is the simplest defense — it pushes constraints into the protocol surface where every downstream auditor can see them.
4. **Don't rely on host-level mitigations.** IMDSv2-Required is great, but the package should not assume the host has it enabled. A coding-assistant or browser-automation MCP host won't always be on AL2023.

For MCP host operators:

1. **Set IMDSv2 to Required** on every cloud instance running an MCP host. This is the single highest-leverage host-level mitigation.
2. **Audit your MCP server inventory.** Run [MCP-Scan](https://github.com/desledishant10/mcp-scan) (or an equivalent) against every server you've enabled and flag any with `MCP-S-009` findings.
3. **Treat MCP servers as untrusted code** that runs with the agent's effective network identity. They are — by design — speaking to the model on your behalf.

## About the tool

[MCP-Scan](https://github.com/desledishant10/mcp-scan) is open source under Apache 2.0. It includes the static analyzer that surfaced this finding, the dynamic harness that verified it, the calibration corpus of 10 hand-labeled MCP servers (now 11), and the full audit trail of this disclosure — including the EC2 reproduction runbook and the disclosure-record template I used. If you want to audit your own MCP servers, three commands get you started:

```bash
pip install mcp-server-fetch          # or any MCP server you want to audit
mcp-scan-capture --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch \
    -o /tmp/tools.json
mcp-scan-analyze /tmp/tools.json
```

The runbook and all findings live in the repo; contributions are welcome.

## Closing

The MCP ecosystem is in the early-adoption phase that every new protocol goes through — fast growth, many small packages, security treated as a follow-up concern. SSRF in HTTP-fetch tools is the first vulnerability class I've documented at scale, but it's almost certainly not the last. The same scanner is finding patterns in command-execution tools, file-handling tools, and tool descriptions that contain agent-directed instructions. Each pattern deserves a careful audit; some will produce more disclosures, some will turn out to be false positives. That's the work.

The Schelling-point question for the ecosystem is whether it adopts secure defaults or learns by repeated incident. Coordinated disclosure with reasonable embargo is one way to nudge it toward the former. So is publishing the runbook, the rule, the scanner, and the methodology in public. Both are open for anyone reading this to take further.

— Dishant Desle, May 2026 (drafted) / *[TODO insert actual publication date]* (published)
