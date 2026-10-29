---
title: "The MCP transport-layer blind spot: six packages, two vulnerability classes, one ecosystem norm"
description: "A survey of six PyPI-published MCP servers found two architectural anti-patterns at the transport boundary: outbound SSRF in URL-fetching tools and inbound DNS rebinding on HTTP-transport servers. One shared root cause, one community fix that never merged, five packages still unfixed, and the scanner methodology that surfaced the pattern."
---

# MCP servers and the transport-layer blind spot: six Python packages, two vulnerability classes, one ecosystem norm

**Dishant Desle**

> **Update — 2026-10-28:** The SSRF half is now **resolved upstream**. `mcp-server-fetch` refuses private, loopback, link-local and cloud-metadata destinations **by default** as of the `2026.10.10` release (maintainer PR [#5033](https://github.com/modelcontextprotocol/servers/pull/5033), merged 2026-10-05; runtime-verified against the `poc/ssrf/` harness on 2026-10-28). The community fix PR #4226 this post discusses was closed **unmerged** the same week under the repo's new issues-only contribution policy; the shipped fix references a separate issue, so the resolution was independent of this disclosure. The narrative below is preserved as written (point-in-time, through 2026-09-10). The DNS-rebinding half remains unfixed across all four packages as of this update.

## TL;DR

Between May and June 2026 I disclosed six vulnerabilities across six PyPI-published Python MCP servers, in two distinct classes. **Outbound SSRF** in URL-fetching tools (two packages: Anthropic's reference `mcp-server-fetch` and the community-published `mcp-server-http-request`) lets an agent coerced via prompt injection retrieve cloud-metadata-service credentials from any host where IMDS is reachable. **Inbound DNS rebinding** on HTTP-transport MCP servers (four packages: `mcp-streamablehttp-proxy`, `mcp-fetch-streamablehttp-server`, `fastmcp-http`, and `mcp-server-fetch-sse`) lets any web page the operator visits issue tool calls against their locally running MCP servers, with no agent prompt injection required. The worst case, `mcp-server-fetch-sse`, composes both: a browser-driven DNS rebind to reach the server, then an inherited pre-fix SSRF inside the wrapped fetch tool to exfiltrate IMDS credentials.

The SSRF half landed a fix fast and then stalled. PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) by external contributor `@kgarg2468` shipped within 10 days of the original disclosure, with a fix shape more defensive than the disclosure asked for (per-redirect validation closes the redirect-bypass class), and I independently verified it on 2026-05-22. But the maintainers closed the disclosure as "not planned," and as of my last check on 2026-09-10 that PR is still open and unmerged while vulnerable releases keep shipping to PyPI. The DNS-rebind half is worse: across four independently authored packages and three maintainer teams, zero fixes shipped. All four are unchanged on PyPI and still vulnerable at the disclosed versions as of 2026-09-10.

Two caveats up front. (1) On Amazon Linux 2023 instances launched with default IMDSv2-Required metadata options, the SSRF half is mitigated at the host level: the package does not send the required token header, so IMDS responds 401. The bug is still real because IMDSv2 is not required on older AMIs, operators legitimately set it to Optional for compatibility, GCP and Azure metadata services have different default postures, and RFC 1918 internal services have no IMDSv2 equivalent. (2) DNS rebinding does not depend on the agent at all. That is the point. The browser is the attack surface.

The takeaway is not "six buggy packages." It is "two architectural anti-patterns at the MCP transport layer, repeating across independently authored servers." Both reduce to the same shape: external constraint, missing in-package enforcement.

## What MCP is and why this surface exists

The Model Context Protocol, adopted by Anthropic's Claude, OpenAI's ChatGPT, Cursor, Zed, and a growing list of AI hosts, lets agents discover and invoke tools defined by external MCP servers. A typical server exposes a list of tools, each with a name, a natural-language description, and a JSON Schema for arguments. The agent sees those, decides when to call them, and feeds the results back into the conversation.

MCP servers come in two transport flavors. **Stdio transport** is the original: the server runs as a subprocess of the agent host, communicating over stdin and stdout. **HTTP transport**, including the newer streamable-HTTP and the older SSE variant, has the server running as a network service with the agent host as a client. Stdio servers face one security surface: what the agent asks them to do. HTTP servers face two: what the agent asks them to do, and what anything else on the network can ask them to do. The HTTP-transport servers in this post are vulnerable on the inbound side; the stdio fetch servers are vulnerable on the outbound side. Together they cover both halves of the transport boundary, each leaking in the way it is built to function.

## Class 1: outbound SSRF in URL-fetching tools

For HTTP-fetch tools, the most common kind of MCP server by my PyPI survey, the implementation boils down to a single function: take a URL from the agent's arguments, fetch it, return the response. There is almost always a parameter named `url` typed as `string` with `format: uri`. The server trusts the agent to be responsible. For most non-cloud deployments, that is fine. For cloud-hosted agent hosts, it is a credential-exfiltration primitive waiting to be activated.

### Discovery: a static rule on the captured tools/list

I built [mcp-witness](https://github.com/desledishant10/mcp-witness) (formerly mcp-scan; renamed mid-survey to avoid collision with an established tool of the same name) as a security testing toolkit for MCP servers: a static analyzer, a dynamic harness, and a capability classifier. The static-analyzer rule **MCP-S-009** flags URL-fetching tools that lack any apparent allowlist:

- the tool has a parameter named `url` / `uri` / `endpoint` or with `format: uri`, and
- no JSON Schema `pattern` / `const` / `enum` constraint on that parameter, and
- no validation keywords in the tool description (`allowlist`, `scheme is`, `restricted to`, and similar).

It is a heuristic, necessary but not sufficient, and a high-precision "review this." Run against the captured `tools/list` from `mcp-server-fetch`:

```bash
$ mcp-witness-capture --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch -o /tmp/fetch.json
$ mcp-witness-analyze /tmp/fetch.json
[HIGH] MCP-S-009  <captured>:0  fetch
    Tool has URL parameter(s) ['url'] with no schema-level constraint and no
    validation keywords in the description. Likely no scheme allowlist or
    host denylist. Verify against SSRF to link-local / loopback / cloud-
    metadata addresses.
```

Same finding against `mcp-server-http-request`, multiplied by five (one per HTTP method).

### Dynamic verification: not just a pattern, a path

Static rules say "this might be vulnerable, look closer." For confidence you need a dynamic probe. **MCP-D-003** connects to a running server and tries a battery of test URLs: the harness's own canary (proves arbitrary egress), AWS IMDSv1, the ECS task-role endpoint, GCP `metadata.google.internal`, Azure IMDS, loopback ports, `file://` URIs, and non-HTTP schemes (gopher, dict).

Against `mcp-server-fetch` on a dev machine, the result was interesting and misleading. The canary hit (it is a fetch tool, it fetched). The metadata addresses all failed with `"Failed to fetch robots.txt due to a connection issue"`. The `file://` URIs did the same. It looked like it had defenses.

But the mechanism is telling. `mcp-server-fetch` does a politeness check: it fetches `robots.txt` first and proceeds to the requested URL only if robots.txt was reachable. On a dev machine, `169.254.169.254` is not routable, so the robots.txt fetch fails at the TCP layer and `mcp-server-fetch` bails. That is an accidental SSRF defense, not a deliberate one. It only works when the target host does not respond to TCP. On any cloud instance where the metadata service does respond to TCP, which is all of them, the robots.txt fetch succeeds with a 404 (IMDS has no robots.txt), and `mcp-server-fetch` proceeds to fetch the real URL.

`mcp-server-http-request` does not even have this accidental defense. It skips robots.txt and just makes the request.

### EC2 demonstration: real credentials

My hypothesis was that on actual EC2 the failure mode would be different and credentials would come back. I launched a `t3.micro` (Amazon Linux 2023, us-east-1), attached an IAM role with `AmazonEC2ReadOnlyAccess`, set IMDSv2 to Optional (the default is Required, which itself mitigates this bug, as discussed below), installed `mcp-server-fetch`, and asked it to fetch the IMDS credentials URL via an MCP client harness.

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

A working AWS IAM credential triplet, returned by an MCP tool, retrievable by anything that can convince an agent to call `fetch("http://169.254.169.254/...")`. The role and instance were torn down within minutes of capture; the credentials expired with their normal lifetime. The full reproduction runbook is in the [mcp-witness repo](https://github.com/desledishant10/mcp-witness/blob/main/docs/audit-runbook-ec2-ssrf-verification.md).

From an attacker's perspective the chain is: prompt injection, then the agent calls `fetch` with the IMDS URL, then credentials are returned, then the attacker pivots to whatever the IAM role permits.

### The fix that shipped fast and never merged

The first half of this is the discovery-to-fix loop working as designed. Ten days after the coordinated disclosure was filed as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143), external contributor `@kgarg2468` opened PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226), *"fix(fetch): block private network URL fetches"*, explicitly fixing the disclosed issue. The commit summary describes the fix as:

- validate that fetch URLs use the `http` / `https` scheme,
- resolve hostnames and reject targets that are not public IP addresses,
- block `localhost`, private, loopback, link-local, and metadata-service targets,
- follow redirects manually so each redirected target is validated before the next request.

That last item, per-redirect validation, is a more rigorous defense than the original disclosure asked for. Without it, an attacker could host a public URL that 302-redirects to `http://169.254.169.254/...`; the in-package scheme/host check would pass on the initial request and the metadata leak would still occur. Per-redirect validation closes that bypass.

On 2026-05-22 I re-ran the same demo script that previously exfiltrated IAM credentials against the fix branch (`kgarg/harden-fetch-ssrf`). Same request, different response:

```
Fetching private or non-public IP addresses is not allowed
```

Refusal at the validation layer with a clean error message, no network attempt, and independent verification posted on the PR.

The second half is where it stops resembling a clean loop. Issue #4143 was closed as "not planned" on 2026-07-30 and consolidated into an older, dormant umbrella issue, [#3741](https://github.com/modelcontextprotocol/servers/issues/3741). As of 2026-09-10, PR #4226 is still open and unmerged: CI green, one external technical-audit review, but no approving review from anyone with write access, which the repository requires to merge, and stale since 2026-06-21. Three releases shipped after the disclosure (v2026.6.4, v2026.7.10, v2026.8.18); the current latest still runs the unguarded fetch path, runtime-verified via the `poc/ssrf/` harness on 2026-09-10. Coordinated-disclosure obligations were satisfied and the 90-day embargo was observed, so I do not read intent into the routing. The outcome is still that a verified, low-risk, self-contained fix for a credential-exfiltration primitive in a reference server has sat unmerged for weeks while releases shipped without it. The full arc of that one package is its own piece: [I found an SSRF in Anthropic's reference MCP server](https://desledishant10.github.io/mcp-witness/docs/ssrf-mcp-server-fetch).

The community companion package `mcp-server-http-request` v0.1.0 (published by the startup statespace) has the identical class and no accidental robots.txt defense at all. I disclosed it by email the same day, since it had no public issue tracker. After thirty days of silence, cofounder Gavin Chan replied on LinkedIn on 2026-06-11: *"That's not an actively maintained package."* I logged it as maintainer-confirmed-unmaintained. No fix.

## Class 2: inbound DNS rebinding on HTTP-transport MCP servers

The SSRF half is about the server reaching out. The DNS-rebind half is about the browser reaching in.

### Why HTTP-transport MCP servers are a different attack surface

When an MCP server runs as an HTTP service, every request to it carries an `Origin` header (or does not, if the request is from a non-browser client). A server intended for local-only use must validate that Origin against an allowlist; otherwise any web page the operator visits can issue requests to the server's endpoints. The web's standard defense against this is the Same-Origin Policy enforced by the browser, but SOP gates on the origin (scheme plus host plus port), and an attacker who controls a domain can defeat the host check via **DNS rebinding**: serve a low-TTL DNS record pointing at an attacker-controlled IP initially, then flip the record to `127.0.0.1` after the page loads. From the browser's perspective the page's origin has not changed; from the network's perspective the requests now hit localhost.

A `localhost` bind sounds defensively reasonable but is not enough on its own. Without server-side Origin/Host validation, the rebind primitive turns any browser tab into a tool-invocation path against locally running MCP servers.

### Discovery: S-014 and the W1 through W4 detector evolution

Static-analyzer rule **MCP-S-014** flags HTTP-transport MCP servers that bind to loopback or `0.0.0.0` without Origin/Host validation. The original v0.1 detector was a string-literal pattern match plus a coarse "does the file mention Origin anywhere" suppression. That fired on none of the four disclosure targets; each of `mcp-streamablehttp-proxy`, `mcp-fetch-streamablehttp-server`, `fastmcp-http`, and `mcp-server-fetch-sse` needed one of the W1 through W4 patches (or manual source review) to surface.

The survey itself taught the detector. Four patches followed:

- **W1: host=variable resolution.** Patterns like `uvicorn.run(app, host=host, port=port)` where `host` is bound to `"0.0.0.0"` earlier (via module-level assignment or a function-parameter default) need a tree-wide pre-pass to track string bindings. Necessary for `mcp-streamablehttp-proxy` and `fastmcp-http`.
- **W2: AST-based Origin suppression.** Substring-matching `origin` anywhere in the file silenced the rule even when the only `origin` mention was inside an LLM prompt string or a wildcard CORS response header. Replaced with an AST walk that looks for actual request-header reads, `request.headers["Origin"]` or `.headers.get("Origin", …)`. Tightens precision substantially.
- **W3: aiohttp bind shapes.** `_SERVER_BIND_METHODS` extended with `run_app` (keyword-host pattern: `web.run_app(app, host="…")`) and `TCPSite` (positional-host pattern: `web.TCPSite(runner, "…", port)`). Necessary for `mcp-server-fetch-sse`.
- **W4: env-var defaults.** `host = os.getenv("HOST", "0.0.0.0")`, common in production-shaped code where the env-var fallback is the deployed bind. `_extract_env_default` resolves the literal second-arg default; `_collect_string_bindings` calls it for `Assign` nodes whose value is a `Call`. Necessary for `mcp-fetch-streamablehttp-server`.

After the patches: four of four surveyed packages correctly flagged. The detector is now what it should have been from the start, and the survey work is what made it that way. The full walkthrough, each patch tied to the specific source file that motivated it, is its own piece: [Detector evolution: MCP-S-014](https://desledishant10.github.io/mcp-witness/docs/detector-evolution-s014).

### Four packages, one pattern

All four targets exhibit the same architectural assumption: *"some external layer handles Origin / Host enforcement."* For two of them (`atrawog/mcp-oauth-gateway`'s `mcp-streamablehttp-proxy` and `mcp-fetch-streamablehttp-server`), the external layer is Traefik configured as part of the larger monorepo, and the in-package code has inline comments explicitly delegating to it. The problem is that the package is also distributed as a standalone PyPI release with its own console script, and the standalone path ships without Traefik. For `fastmcp-http`, the external layer is implicit: Flask's dev server has no auth and no middleware, and operators are presumed to put a reverse proxy in front. For `mcp-server-fetch-sse`, it is a fork of an internal-use-only experiment whose threat-model docs never got updated.

The worst case is `mcp-server-fetch-sse`: a DNS-rebind primitive on the HTTP+SSE transport combined with an inherited pre-fix SSRF in the wrapped fetch tool. The attack chain compounds. Attacker-controlled DNS rebinds to `127.0.0.1`; page JavaScript establishes an SSE session; the page POSTs `tools/call` with an IMDS URL to `/message?sessionId=<id>`; the server accepts (no Origin/Host check) and forwards to the fetch tool; the fetch tool retrieves IMDS (no scheme/host check); credentials return in the response body. Browser-tab-triggered, no agent prompt injection required. The full inbound writeup, including the honest split between the server-side flaw and the harder live-rebind delivery, is [One assumption, four packages](https://desledishant10.github.io/mcp-witness/docs/dns-rebinding-http-mcp-servers).

### Disclosure outcomes

The coordinated-disclosure embargo was 2026-08-10, and it has passed. I checked all four packages against GitHub and PyPI on 2026-09-10. All four are unchanged on PyPI since disclosure, with no fix releases, and all four remain vulnerable at the disclosed versions.

- **`mcp-streamablehttp-proxy` v0.2.0 and `mcp-fetch-streamablehttp-server` v0.2.0** (atrawog). Coordinated disclosure emailed to `atrawog@gmail.com` on 2026-05-12, with a day +21 follow-up on 2026-06-02 and a third email at day +30. No response at any point. Silent.
- **`fastmcp-http` v0.1.4** (ARadRareness). Disclosed via a public GitHub issue, [`ARadRareness/mcp-registry#3`](https://github.com/ARadRareness/mcp-registry/issues/3), on 2026-06-02, as the channel of last resort after GHSA was disabled on the repo, the maintainer profile listed no contact, and PyPI showed only a GitHub-noreply email. The maintainer closed the issue as "completed" on 2026-06-21, with no comment, no commits since, and no fix release. Closed without a fix.
- **`mcp-server-fetch-sse` v0.1.1** (PyPI maintainer-of-record `jadamson@anthropic.com`). Disclosed by email on 2026-06-02, with a parallel courtesy notice to Anthropic Security, discussed next. The maintainer never replied.

## The brand-attribution problem

`mcp-server-fetch-sse` v0.1.1 lists `Author: Anthropic, PBC.` and `Maintainer: Jack Adamson <jadamson@anthropic.com>` in its wheel METADATA. Its README is lifted near-verbatim from Anthropic's official `mcp-server-fetch`: same CAUTION block, same VS Code install badges pointing at the upstream package name. The wrapped fetch implementation looks like a fork of upstream code from before PR #4226 shipped the SSRF fix. From a downstream user's perspective the package presents as Anthropic-published; from outside, I cannot verify whether the attribution is active Anthropic maintenance or attribution inherited from a fork's `pyproject.toml`. PyPI does not verify Author claims.

My disclosure approach was a primary technical disclosure to the published maintainer-of-record at `jadamson@anthropic.com`, with a parallel courtesy notice to Anthropic Security so they could route internally if appropriate. The parallel notice took two attempts. The HackerOne program listed in Anthropic's `.well-known/security.txt` returned a triage interstitial keyword-filtering the report as the documented `mcp-server-fetch` SSRF class, which it is not (separate package, different attack direction, plus a class of vulnerability the interstitial does not cover at all). The interstitial included a "submitting this report could impact your reputation points" warning, HackerOne's signal that the program will not engage with this report class, so I cancelled the submission and switched channels. The email to `disclosure@anthropic.com` (the secondary contact published on Anthropic's responsible-disclosure-policy page) returned a no-reply auto-responder routing back to HackerOne or to specialized channels, none of which fit "third-party PyPI package brand attribution."

Both deflections are corporate-intake-routing artifacts, not Anthropic's position on the disclosure. No human review was reached on the Anthropic side, and the maintainer never replied. The primary technical disclosure to the listed maintainer remains the binding channel for a fix; the parallel-notice piece is documented in the disclosure record for posterity.

## The class-wide observation: one ecosystem norm

Two attack directions, four maintainer teams, six packages, and one architectural anti-pattern.

In the SSRF half: HTTP-fetch tools model the `url` parameter as an unconstrained string and trust the agent to be responsible. The threat model for MCP servers explicitly includes adversarially influenced tool arguments via prompt injection, so the trust assumption is wrong. The fix is small: a scheme allowlist, an IP-class denylist, per-redirect validation. Ten lines per package, or ten lines once in a shared utility.

In the DNS-rebind half: HTTP-transport MCP servers defer Origin/Host enforcement to "some external layer," Traefik in some cases, an unnamed reverse proxy in others, the operator's good judgment in the rest. The standalone deployment path ships without that external layer. The fix is small: a Starlette `TrustedHostMiddleware` for ASGI servers, an aiohttp middleware for aiohttp servers, a Flask `before_request` hook for Flask servers, each validating `Host` and `Origin` against an allowlist. Five to ten lines per package.

Both are the same shape: **external constraint, missing in-package enforcement.** The author assumed someone upstream would handle security: the cloud platform via IMDSv2, the operator via robots.txt being unreachable, the reverse proxy via header rewriting, the agent via judgment. In each case the assumption holds for the deployment the author had in mind and fails for the deployment users actually run.

The shared fix is to **defend in-process** and treat external defenses as defense-in-depth rather than the primary boundary. The corollary is that the default `pip install` plus console-script flow should be safe out of the box; users who know what they are doing can opt out.

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

Ten lines. Per package, or once across the ecosystem.

## Disclosure timeline

- **2026-05-11:** discovery via the S-009 static rule; dynamic verification of D-003 on a dev machine.
- **2026-05-12:** EC2 reproduction with real IAM credentials retrieved; coordinated disclosures filed: GitHub issue #4143 (`mcp-server-fetch`), email to maintainers (`mcp-server-http-request`), email to atrawog (`mcp-streamablehttp-proxy` and `mcp-fetch-streamablehttp-server`, combined).
- **2026-05-22:** PR #4226 (`@kgarg2468`) shipped against `mcp-server-fetch`; the same demo script that previously exfiltrated IAM credentials, re-run against the fix branch, returns `"Fetching private or non-public IP addresses is not allowed"`; independent verification posted on the PR.
- **2026-06-02:** day +21 follow-up pings on the four still-silent maintainers; three new disclosures dispatched: `fastmcp-http` (`ARadRareness/mcp-registry#3`, public-issue channel of last resort), `mcp-server-fetch-sse` (email to `jadamson@anthropic.com`), parallel notice to `disclosure@anthropic.com` after the HackerOne triage interstitial declined the report class.
- **2026-06-11:** day +30 escalation checkpoint; `mcp-server-http-request` confirmed maintainer-unmaintained via the statespace cofounder's LinkedIn reply.
- **2026-06-21:** `fastmcp-http` issue closed as "completed" with no fix.
- **2026-07-30:** `mcp-server-fetch` disclosure #4143 closed as "not planned" and consolidated into dormant umbrella #3741.
- **2026-08-10:** embargo expiration.
- **2026-09-10:** post-embargo verification: PR #4226 still open and unmerged, `mcp-server-fetch` latest (v2026.8.18) still vulnerable; all four DNS-rebind packages unchanged on PyPI and still vulnerable.
- **2026-09-11:** CVE requests filed with MITRE for all six packages (IDs pending assignment).
- **2026-10-05:** `mcp-server-fetch` SSRF fixed upstream by maintainer PR [#5033](https://github.com/modelcontextprotocol/servers/pull/5033) (fixes #4838), refusing non-public destination IPs by default on every redirect hop; merged to `v2/main`.
- **2026-10-28:** fix confirmed shipped default-on in `mcp-server-fetch` `2026.10.10`+ (byte-verified; runtime-verified against the `poc/ssrf/` harness on `2026.10.28`). Community fix PR #4226 closed unmerged under the repo's new issues-only contribution policy. SSRF half resolved; DNS-rebind half still unfixed.

## What the ecosystem should do

For MCP server authors building anything that touches network egress, inbound HTTP transport, or any IO sink with cloud-environment relevance:

1. **Do not trust the URL parameter.** Whatever the agent passes in might be attacker-controlled even if the agent itself is honest. Validate scheme and host before issuing the request.
2. **Reject reserved IP ranges by default** on outbound calls: link-local (`169.254/16`), loopback (`127/8`, `::1`), RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`), IPv6 ULA (`fc00::/7`). Provide an opt-in env var for users who need internal access.
3. **For HTTP-transport servers, validate `Origin` and `Host` headers** in-process. The standalone `pip install` plus console-script flow should be safe; the reverse-proxy-in-front deployment can disable in-process checks via an explicit env var.
4. **Schema-constrain when possible.** A `pattern` or `enum` on the URL parameter is the simplest defense, and it pushes constraints into the protocol surface where every downstream auditor can see them.
5. **Do not rely on host-level mitigations.** IMDSv2-Required is good, but the package should not assume the host has it enabled. A coding-assistant or browser-automation MCP host will not always be on AL2023.

For MCP host operators:

1. **Set IMDSv2 to Required** on every cloud instance running an MCP host. It is the single highest-leverage host-level mitigation.
2. **Audit your MCP server inventory.** Run [mcp-witness](https://github.com/desledishant10/mcp-witness) (or an equivalent) against every server you have enabled and flag any with `MCP-S-009` (outbound SSRF) or `MCP-S-014` (inbound DNS rebind) findings.
3. **Treat MCP servers as untrusted code** that runs with the agent's effective network identity and the operator's effective browser-localhost identity. They are, by design, speaking to the model on your behalf.

For the MCP spec itself:

The spec does not currently mandate validation patterns for HTTP-class tools. Whether that becomes a normative requirement or a recommended-practice section is a spec-track question, but the survey here makes the case: the ecosystem cannot be relied on to enforce security at the package level when the spec implies it is the application's responsibility. A normative section ("HTTP-fetch tools MUST allowlist scheme and reject reserved IP ranges by default" / "HTTP-transport servers MUST validate Origin and Host headers before processing tool calls") would shift the default. The disclosure record here would have looked very different if these were spec-mandated invariants.

## About the tool

[mcp-witness](https://github.com/desledishant10/mcp-witness) is open source under Apache 2.0. It includes the static analyzer (15 rules, 278 tests), the dynamic harness (7 scenarios, two agent drivers: a deterministic stub and a real Claude tool-use loop), the capability classifier, a calibration corpus of 11 hand-labeled MCP servers, the EC2 reproduction runbook used for the SSRF verification, and the full audit trail of all six disclosures covered in this post, including the channel-decision records for the four that needed unusual disclosure paths. If you want to audit your own MCP servers, three commands get you started:

```bash
pip install mcp-server-fetch          # or any MCP server you want to audit
mcp-witness-capture --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch -o /tmp/tools.json
mcp-witness-analyze /tmp/tools.json
```

The runbook, all findings, and the disclosure record live in the repo; contributions are welcome.

## Next

A few follow-ups are worth their own pieces rather than another paragraph here:

- **AST-based vs string-pattern detection: methodology trade-offs.** Triggered by a productive cross-tool discussion on the #4143 thread. Different methodologies have different blind spots, and the comparison is worth a thorough treatment.
- **Cross-language parity.** The analyzer now carries a tree-sitter TypeScript/JavaScript front-end that brings the source rules to TS/JS at parity with Python, so the same transport-layer checks run against TS servers. How the two front-ends share a rule model is its own write-up.
- **MCP-spec engagement.** Whether the security recommendation above gets traction is up to the spec maintainers and the broader community; the open question is where to surface the proposal, whether an issue thread, an RFC draft, or a working-group discussion.

## Closing

The MCP ecosystem is in the early-adoption phase that every new protocol goes through: fast growth, many small packages, security treated as a follow-up concern. Two vulnerability classes are documented at scale here, and almost certainly not the last. The same scanner is finding patterns in command-execution tools, file-handling tools, and tool descriptions that contain agent-directed instructions. Each pattern deserves a careful audit; some will produce more disclosures, some will turn out to be false positives. That is the work.

The question for the ecosystem is whether it adopts secure defaults or learns by repeated incident. Coordinated disclosure with a reasonable embargo is one way to nudge it toward the former. Publishing the runbook, the rules, the scanner, and the methodology in public is another. Both are open for anyone reading this to take further.

Survey conducted May–June 2026; disclosure outcomes verified 2026-09-10.
