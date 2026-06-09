# [DRAFT — for publication on or after 2026-08-10] MCP servers and the transport-layer blind spot

> **Status:** embargo draft. Public release scheduled for 2026-08-10, the 90-day expiration of the coordinated disclosures covering six PyPI-published Python MCP servers across two vulnerability classes. The first of those disclosures, [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143), has already been independently fixed via PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226); the remaining five are still under embargo at draft time. Sections marked `[TODO post-embargo]` will be updated with maintainer responses and any further patches before publication.

---

# MCP servers and the transport-layer blind spot: six Python packages, two vulnerability classes, one ecosystem norm

## TL;DR

Between May and June 2026 I disclosed six vulnerabilities across six PyPI-published Python MCP servers, in two distinct classes. **Outbound SSRF** in URL-fetching tools (2 packages: Anthropic's reference `mcp-server-fetch` and the community-published `mcp-server-http-request`) lets an agent coerced via prompt injection retrieve cloud-metadata-service credentials from any host where IMDS is reachable. **Inbound DNS rebinding** on HTTP-transport MCP servers (4 packages: `mcp-streamablehttp-proxy`, `mcp-fetch-streamablehttp-server`, `fastmcp-http`, and `mcp-server-fetch-sse`) lets any web page the operator visits issue tool calls against their locally-running MCP servers, with no agent prompt-injection required. The worst case — `mcp-server-fetch-sse` — composes both: browser-driven DNS rebind to reach the server, then an inherited pre-PR-#4226 SSRF inside the wrapped fetch tool to exfiltrate IMDS credentials.

The SSRF half landed clean: PR #4226 by external contributor `@kgarg2468` shipped within 10 days of the original disclosure, with a fix shape *more* defensive than the disclosure asked for (per-redirect validation closes the redirect-bypass class), and I independently verified it on 2026-05-22. The DNS-rebind half is split — some maintainers responsive, some silent — but all four are now under coordinated disclosure with the same 2026-08-10 embargo.

Two caveats up front. (1) On Amazon Linux 2023 instances launched with default IMDSv2-Required metadata options, the SSRF half is fully mitigated at the host level — the package doesn't send the required token header, so IMDS responds 401. The bug is still real because IMDSv2 isn't required on older AMIs, operators legitimately set it to Optional for compatibility, GCP and Azure metadata services have different default postures, and RFC 1918 internal services have no IMDSv2 equivalent. (2) DNS rebinding doesn't depend on the agent at all — that's the point. The browser is the attack surface. *[TODO post-embargo: refresh maintainer-response state for the five still-embargoed disclosures.]*

The takeaway isn't "six buggy packages." It's "two architectural anti-patterns at the MCP transport layer, repeating across independently-authored servers." Both reduce to the same shape: external constraint, missing in-package enforcement.

## What MCP is and why this surface exists

The Model Context Protocol — adopted by Anthropic's Claude, OpenAI's ChatGPT, Cursor, Zed, and a growing list of AI hosts — lets agents discover and invoke tools defined by external "MCP servers." A typical server exposes a list of tools, each with a name, a natural-language description, and a JSON Schema for arguments. The agent sees those, decides when to call them, and feeds the results back into the conversation.

MCP servers come in two transport flavors. **Stdio transport** is the original: server runs as a subprocess of the agent host, communication over stdin/stdout. **HTTP transport** — including the newer streamable-HTTP and the older SSE variant — has the server running as a network service, with the agent host as a client. Stdio servers face one security surface: what the agent asks them to do. HTTP servers face two: what the agent asks them to do, *and* what anything else on the network can ask them to do. The HTTP-transport servers in this post are vulnerable on the inbound side; the stdio fetch servers are vulnerable on the outbound side. Together they cover both halves of the transport boundary, both leaking in the way they're built to function.

## Class 1: outbound SSRF in URL-fetching tools

For HTTP-fetch tools — the most common kind of MCP server, by my PyPI survey — the implementation boils down to a single function: take a URL from the agent's arguments, fetch it, return the response. There's almost always a parameter named `url` typed as `string` with `format: uri`. The server trusts the agent to be responsible. For most non-cloud deployments, that's fine. For cloud-hosted agent hosts, it's a credential-exfiltration primitive waiting to be activated.

### Discovery: a static rule on the captured tools/list

I built [mcpsentry](https://github.com/desledishant10/mcpsentry) (formerly mcp-scan; renamed mid-survey to avoid collision with an established tool of the same name) as a security testing toolkit for MCP servers — static analyzer + dynamic harness + capability classifier. The static-analyzer rule **MCP-S-009** flags URL-fetching tools that lack any apparent allowlist:

- the tool has a parameter named `url` / `uri` / `endpoint` or with `format: uri`, *and*
- no JSON Schema `pattern` / `const` / `enum` constraint on that parameter, *and*
- no validation keywords in the tool description (`allowlist`, `scheme is`, `restricted to`, etc.)

Heuristic — necessary-but-not-sufficient — but high-precision "review this." Run against the captured `tools/list` from `mcp-server-fetch`:

```bash
$ mcpsentry-capture --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch -o /tmp/fetch.json
$ mcpsentry-analyze /tmp/fetch.json
[HIGH] MCP-S-009  <captured>:0  fetch
    Tool has URL parameter(s) ['url'] with no schema-level constraint and no
    validation keywords in the description. Likely no scheme allowlist or
    host denylist — verify against SSRF to link-local / loopback / cloud-
    metadata addresses.
```

Same finding against `mcp-server-http-request`, multiplied by 5 (one per HTTP method).

### Dynamic verification: not just a pattern, a path

Static rules say "this might be vulnerable, look closer." For confidence you need a dynamic probe. **MCP-D-003** connects to a running server and tries a battery of test URLs: the harness's own canary (proves arbitrary egress), AWS IMDSv1, ECS task-role endpoint, GCP `metadata.google.internal`, Azure IMDS, loopback ports, `file://` URIs, and non-HTTP schemes (gopher, dict).

Against `mcp-server-fetch` on a dev machine, the result was interesting and *misleading*. The canary hit (it's a fetch tool, it fetched). The metadata addresses all failed with `"Failed to fetch robots.txt due to a connection issue"`. The `file://` URIs same. Looked like it had defenses.

But the mechanism is telling. `mcp-server-fetch` does a politeness check — fetches `robots.txt` first, proceeds to the requested URL only if robots.txt was reachable. On a dev machine, `169.254.169.254` isn't routable, so the robots.txt fetch fails at TCP layer and `mcp-server-fetch` bails. **That's an accidental SSRF defense, not a deliberate one.** It only works when the target host doesn't respond to TCP. On any cloud instance where the metadata service does respond to TCP (which is, you know, *all of them*), the robots.txt fetch succeeds with 404 (IMDS has no robots.txt), and `mcp-server-fetch` proceeds to fetch the real URL.

`mcp-server-http-request` doesn't even have this accidental defense — it skips robots.txt and just makes the request.

### EC2 demonstration: real credentials

Hypothesis: on actual EC2 the failure mode would be different and credentials would actually come back. I launched a `t3.micro` (Amazon Linux 2023, us-east-1), attached an IAM role with `AmazonEC2ReadOnlyAccess`, set IMDSv2 to Optional (the default is Required, which itself mitigates this bug — more on that below), installed `mcp-server-fetch`, and asked it to fetch the IMDS credentials URL via an MCP client harness.

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

A working AWS IAM credential triplet, returned by an MCP tool, retrievable by anything that can convince an agent to call `fetch("http://169.254.169.254/...")`. The role and instance were torn down within minutes of capture; the credentials expired with their normal lifetime. Full reproduction runbook is in the [mcpsentry repo](https://github.com/desledishant10/mcpsentry/blob/main/docs/audit-runbook-ec2-ssrf-verification.md).

From an attacker's perspective the chain is: prompt injection → agent calls `fetch` with IMDS URL → credentials returned → attacker pivots to whatever the IAM role permits.

### The fix shipped pre-embargo

This is the discovery-to-fix loop working as designed. Ten days after the coordinated disclosure was filed as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143), external contributor `@kgarg2468` opened PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) — *"fix(fetch): block private network URL fetches"* — explicitly fixing the disclosed issue. The PR's commit summary describes the fix as:

- Validate fetch URLs use the `http` / `https` scheme
- Resolve hostnames and reject targets that aren't public IP addresses
- Block `localhost`, private, loopback, link-local, and metadata-service targets
- Follow redirects manually so each redirected target is validated *before* the next request

That last item — per-redirect validation — is a more rigorous defense than the original disclosure asked for. Without it, an attacker could host a public URL that 302-redirects to `http://169.254.169.254/...`; the in-package scheme/host check would pass on the initial request and the metadata leak would still occur. Per-redirect validation closes that bypass.

On 2026-05-22, I re-ran the same demo script that previously exfiltrated IAM credentials against the fix branch (`kgarg/harden-fetch-ssrf`). Same request, different response:

```
Fetching private or non-public IP addresses is not allowed
```

Refusal at the validation layer with a clean error message; no network attempt. Independent verification comment posted on the PR.

This is what responsible disclosure looks like when it works. *[TODO post-embargo: status of mcp-server-http-request fix — silent at draft time despite a day +21 ping on 2026-06-02.]*

## Class 2: inbound DNS rebinding on HTTP-transport MCP servers

The SSRF half is about the server reaching out. The DNS-rebind half is about the browser reaching in.

### Why HTTP-transport MCP servers are a different attack surface

When an MCP server runs as an HTTP service, every request to it carries an `Origin` header (or doesn't, if the request is from a non-browser client). A server intended for local-only use must validate that Origin against an allowlist; otherwise any web page the operator visits can issue same-origin requests to the server's endpoints. The web's standard defense against this is the Same-Origin Policy enforced by the browser — but SOP gates on the *origin* (scheme + host + port), and an attacker who controls a domain can defeat the host check via **DNS rebinding**: serve a low-TTL DNS record pointing at an attacker-controlled IP initially, then flip the record to `127.0.0.1` after the page loads. From the browser's perspective the page's origin hasn't changed; from the network's perspective the requests now hit localhost.

`localhost` bind sounds defensively reasonable but isn't enough on its own. Without server-side Origin/Host validation, the rebind primitive turns any browser tab into a tool-invocation path against locally-running MCP servers.

### Discovery: S-014 and the W1–W4 detector evolution

Static-analyzer rule **MCP-S-014** flags HTTP-transport MCP servers that bind to loopback / `0.0.0.0` without Origin/Host validation. Original v0.1 detector was a string-literal pattern match plus a coarse "does the file mention Origin anywhere" suppression. That caught the first two findings (`mcp-streamablehttp-proxy`, `mcp-fetch-streamablehttp-server`) but missed the other two surveyed targets entirely.

The survey itself taught the detector. Four patches (W1–W4) followed:

- **W1: host=variable resolution.** Patterns like `uvicorn.run(app, host=host, port=port)` where `host` is bound to `"0.0.0.0"` earlier (via module-level assignment or function-parameter default) need a tree-wide pre-pass to track string bindings. Necessary for `mcp-streamablehttp-proxy` and `fastmcp-http`.
- **W2: AST-based Origin suppression.** Substring-matching `origin` anywhere in the file silenced the rule even when the only `origin` mention was inside an LLM prompt string or in a wildcard CORS response header. Replaced with an AST walk that looks for actual request-header *reads* — `request.headers["Origin"]` or `.headers.get("Origin", …)`. Tightens precision substantially.
- **W3: aiohttp bind shapes.** `_SERVER_BIND_METHODS` extended with `run_app` (keyword-host pattern: `web.run_app(app, host="…")`) and `TCPSite` (positional-host pattern: `web.TCPSite(runner, "…", port)`). Necessary for `mcp-server-fetch-sse`.
- **W4: env-var defaults.** `host = os.getenv("HOST", "0.0.0.0")` — common in production-shaped code where the env-var fallback *is* the deployed bind. `_extract_env_default` resolves the literal second-arg default; `_collect_string_bindings` calls it for `Assign` nodes whose value is a `Call`. Necessary for `mcp-fetch-streamablehttp-server`.

After the patches: 4 of 4 surveyed packages correctly flagged. The detector is now what it should have been from the start; the survey work is what made it that way.

### Four packages, one pattern

All four targets exhibit the same architectural assumption: *"some external layer handles Origin / Host enforcement."* For two of them (`atrawog/mcp-oauth-gateway`'s `mcp-streamablehttp-proxy` and `mcp-fetch-streamablehttp-server`), the external layer is Traefik configured as part of the larger monorepo — the in-package code has inline comments explicitly delegating to it. The problem is the package is also distributed as a standalone PyPI release with its own console script, and the standalone path ships without Traefik. For `fastmcp-http`, the external layer is implicit — Flask's dev server has no auth and no middleware, and operators are presumed to put a reverse proxy in front. For `mcp-server-fetch-sse`, it's a fork of an internal-use-only experiment whose threat-model docs never got updated.

The worst case is `mcp-server-fetch-sse`: a DNS-rebind primitive on the HTTP+SSE transport combined with an inherited pre-PR-#4226 SSRF in the wrapped fetch tool. The attack chain compounds: attacker-controlled DNS rebinds to `127.0.0.1`, page JavaScript establishes an SSE session, page POSTs `tools/call` with an IMDS URL to `/message?sessionId=<id>`, server accepts (no Origin/Host check) and forwards to the fetch tool, fetch tool retrieves IMDS (no scheme/host check), credentials return in the response body. Browser-tab-triggered, no agent prompt-injection required.

### Disclosure outcomes (mixed)

- **`mcp-streamablehttp-proxy` + `mcp-fetch-streamablehttp-server`** (atrawog) — coordinated disclosure filed 2026-05-12 via email after the repo's GitHub Security Advisory form returned 404; day +21 ping sent 2026-06-02; *[TODO post-embargo: maintainer response status]*
- **`fastmcp-http`** (ARadRareness) — public-issue channel of last resort filed as [`ARadRareness/mcp-registry#3`](https://github.com/ARadRareness/mcp-registry/issues/3) after verification that GHSA was disabled, the maintainer's profile lists no contact, and PyPI shows only a GitHub-noreply email; *[TODO post-embargo: reply status]*
- **`mcp-server-fetch-sse`** (jadamson@anthropic.com listed as maintainer) — email to listed maintainer; parallel courtesy notice (see next section)

## The brand-attribution problem

`mcp-server-fetch-sse` v0.1.1 lists `Author: Anthropic, PBC.` and `Maintainer: Jack Adamson <jadamson@anthropic.com>` in its wheel METADATA. Its README is lifted near-verbatim from Anthropic's official `mcp-server-fetch` — same CAUTION block, same VS Code install badges that point at the upstream package name. The wrapped fetch implementation looks like a fork of upstream code from before PR #4226 shipped the SSRF fix. From a downstream user's perspective the package presents as Anthropic-published; from outside, I can't verify whether the attribution is active Anthropic maintenance or attribution inherited from a fork's `pyproject.toml`. PyPI doesn't verify Author claims.

Disclosure approach: primary technical disclosure to the published maintainer-of-record at `jadamson@anthropic.com`; parallel courtesy notice to Anthropic Security so they could route internally if appropriate. The parallel notice took two attempts. The HackerOne program listed in Anthropic's `.well-known/security.txt` returned a triage interstitial keyword-filtering the report as the documented `mcp-server-fetch` SSRF class (which it isn't — separate package, different attack direction, plus a different class of vulnerability the interstitial doesn't cover at all). The interstitial included a "submitting this report could impact my reputation points" warning, which is HackerOne signaling that the program won't engage with this report class — so I cancelled the submission and switched channels. The email to `disclosure@anthropic.com` (the secondary contact published on Anthropic's responsible-disclosure-policy page) returned a no-reply auto-responder routing back to HackerOne or to specialized channels (none of which fit "third-party PyPI package brand attribution").

Both deflections are corporate-intake-routing artifacts, not Anthropic's position on the disclosure. The primary technical disclosure to the listed maintainer remains the binding channel for the fix; the parallel-notice piece is documented in the disclosure record for posterity. *[TODO post-embargo: maintainer response state.]*

## The class-wide observation: one ecosystem norm

Two attack directions, four maintainer teams, six packages — and one architectural anti-pattern.

In the SSRF half: HTTP-fetch tools model the `url` parameter as an unconstrained string and trust the agent to be responsible. The threat model for MCP servers explicitly includes adversarially-influenced tool arguments via prompt injection, so the trust assumption is wrong. The fix is small: scheme allowlist, IP-class denylist, per-redirect validation. Ten lines per package, or ten lines once in a shared utility.

In the DNS-rebind half: HTTP-transport MCP servers defer Origin/Host enforcement to "some external layer" — Traefik in some cases, an unnamed reverse proxy in others, the operator's good judgment in the rest. The standalone deployment path ships without that external layer. The fix is small: a Starlette `TrustedHostMiddleware` for ASGI servers, an aiohttp middleware for aiohttp servers, a Flask `before_request` hook for Flask servers, validating `Host` and `Origin` against an allowlist. Five to ten lines per package.

Both are the same shape: **external constraint, missing in-package enforcement.** The package's author assumed someone upstream would handle security — the cloud platform via IMDSv2, the operator via robots.txt being unreachable, the reverse proxy via header rewriting, the agent via judgment. In each case the assumption holds for the deployment the author had in mind, and fails for the deployment users actually do.

The shared fix is to **defend in-process**, and treat external defenses as defense-in-depth rather than the primary boundary. The corollary is that the in-process defenses should be off-by-default-but-on-by-default-for-the-default-deployment — the default `pip install` + console-script flow should be safe; users who know what they're doing can opt out.

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

- **2026-05-11** — discovery via S-009 static rule; dynamic verification of D-003 on dev machine
- **2026-05-12** — EC2 reproduction with real IAM credentials retrieved; coordinated disclosures filed:
  - GitHub issue #4143 (`mcp-server-fetch`)
  - Email to maintainers (`mcp-server-http-request`)
  - Email to atrawog (`mcp-streamablehttp-proxy` + `mcp-fetch-streamablehttp-server` combined)
- **2026-05-22** — PR #4226 (`@kgarg2468`) shipped against `mcp-server-fetch`; same demo script that previously exfiltrated IAM credentials re-run against the fix branch returns `"Fetching private or non-public IP addresses is not allowed"`; independent verification posted on the PR
- **2026-06-02** — day +21 follow-up pings on the four still-silent maintainers; three new disclosures dispatched: `fastmcp-http` (`ARadRareness/mcp-registry#3` public-issue channel of last resort), `mcp-server-fetch-sse` email to `jadamson@anthropic.com`, parallel notice to `disclosure@anthropic.com` (after HackerOne triage interstitial declined the report class)
- **2026-06-11** — day +30 escalation checkpoint *[TODO post-embargo: actual outcomes]*
- **2026-08-10** — embargo expiration, public release (this post)

## What the ecosystem should do

For MCP server authors building anything that touches network egress, inbound HTTP transport, or any IO sink with cloud-environment relevance:

1. **Don't trust the URL parameter.** Whatever the agent passes in might be attacker-controlled even if the agent itself is honest. Validate scheme and host before issuing the request.
2. **Reject reserved IP ranges by default** on outbound calls. Link-local (`169.254/16`), loopback (`127/8`, `::1`), RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`), IPv6 ULA (`fc00::/7`). Provide an opt-in env var for users who need internal access.
3. **For HTTP-transport servers, validate `Origin` and `Host` headers** in-process. The standalone `pip install` + console-script flow should be safe; the reverse-proxy-in-front deployment can disable in-process checks via explicit env var.
4. **Schema-constrain when possible.** A `pattern` or `enum` on the URL parameter is the simplest defense — it pushes constraints into the protocol surface where every downstream auditor can see them.
5. **Don't rely on host-level mitigations.** IMDSv2-Required is great, but the package should not assume the host has it enabled. A coding-assistant or browser-automation MCP host won't always be on AL2023.

For MCP host operators:

1. **Set IMDSv2 to Required** on every cloud instance running an MCP host. Single highest-leverage host-level mitigation.
2. **Audit your MCP server inventory.** Run [mcpsentry](https://github.com/desledishant10/mcpsentry) (or an equivalent) against every server you've enabled and flag any with `MCP-S-009` (outbound SSRF) or `MCP-S-014` (inbound DNS rebind) findings.
3. **Treat MCP servers as untrusted code** that runs with the agent's effective network identity and the operator's effective browser-localhost identity. They are — by design — speaking to the model on your behalf.

For the MCP spec itself:

The spec does not currently mandate validation patterns for HTTP-class tools. Whether that becomes a normative requirement or a recommended-practice section is a spec-track question, but the survey here makes the case: the ecosystem can't be relied on to enforce security at the package level when the spec implies it's the application's responsibility. A normative section — "HTTP-fetch tools MUST allowlist scheme and reject reserved IP ranges by default" / "HTTP-transport servers MUST validate Origin and Host headers before processing tool calls" — would shift the default. The disclosure record here would have looked very different if these were spec-mandated invariants.

## About the tool

[mcpsentry](https://github.com/desledishant10/mcpsentry) is open source under Apache 2.0. It includes the static analyzer (14 rules, 164 tests), the dynamic harness (7 scenarios, two agent drivers), the calibration corpus of 10 hand-labeled MCP servers, the EC2 reproduction runbook used for the SSRF verification, and the full audit trail of all six disclosures covered in this post — including the channel-decision audit trails for the four that needed unusual disclosure paths. If you want to audit your own MCP servers, three commands get you started:

```bash
pip install mcp-server-fetch          # or any MCP server you want to audit
mcpsentry-capture --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch -o /tmp/tools.json
mcpsentry-analyze /tmp/tools.json
```

The runbook, all findings, and the disclosure record live in the repo; contributions are welcome.

## Next

A few follow-ups are planned, each scoped to the kind of writeup that deserves its own piece rather than another paragraph here:

- **The v0.3 detector patches (W1–W4) deserve their own technical writeup.** AST-based static analysis for "external constraint, missing in-package enforcement" patterns is interesting territory; the four-patch series surfaced specific evolution lessons that other rule authors could lift.
- **AST-based vs string-pattern detection: methodology trade-offs.** Triggered by a productive cross-tool discussion on the #4143 thread. Different methodologies have different blind spots; the comparison is worth a thorough piece.
- **MCP-spec engagement.** Whether the security-spec recommendation above gets traction is up to the spec maintainers and the broader community; the open question is where to surface the proposal — issue thread, RFC draft, or working-group discussion. Suggestions welcome.

## Closing

The MCP ecosystem is in the early-adoption phase that every new protocol goes through — fast growth, many small packages, security treated as a follow-up concern. Two vulnerability classes documented at scale here; almost certainly not the last. The same scanner is finding patterns in command-execution tools, file-handling tools, and tool descriptions that contain agent-directed instructions. Each pattern deserves a careful audit; some will produce more disclosures, some will turn out to be false positives. That's the work.

The Schelling-point question for the ecosystem is whether it adopts secure defaults or learns by repeated incident. Coordinated disclosure with reasonable embargo is one way to nudge it toward the former. Publishing the runbook, the rules, the scanner, and the methodology in public is another. Both are open for anyone reading this to take further.

— Dishant Desle, May–June 2026 (drafted) / *[TODO insert actual publication date]* (published)
