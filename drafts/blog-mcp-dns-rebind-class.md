# One assumption, four packages: inbound DNS rebinding across HTTP-transport MCP servers

**Dishant Desle**

Four PyPI-published Python MCP servers. Three maintainer teams who have never spoken to each other. One architectural assumption repeated in every one: that some external layer, a reverse proxy or the operator's good judgment, will validate the `Origin` and `Host` headers on inbound HTTP requests. In the deployment those packages actually ship, that layer is not there. So all four accept requests from any web origin: any page the operator visits can reach in and drive their local MCP tools.

I want to be precise about the framing, because it is the whole point. This is not four bugs. It is one wrong assumption at the MCP transport layer, instantiated four times by people working independently. That is the kind of thing a scanner is supposed to surface: not a bug but a pattern.

This piece is the inbound companion to [my writeup on the outbound SSRF](https://github.com/desledishant10/mcp-witness/blob/main/drafts/blog-mcp-server-fetch-ssrf.md) in `mcp-server-fetch`. SSRF is the server reaching out to an attacker-chosen URL. DNS rebinding is a browser reaching in to attacker-chosen tools. What makes the inbound class worse to sit with is the trigger. SSRF needs an agent and usually a prompt injection to steer it. DNS rebinding needs neither. The operator visits a web page. That is the entire attack.

## The mechanism

MCP servers come in two transport flavors. A stdio server runs as a subprocess of the agent host and talks over stdin and stdout. It faces exactly one question: what does the agent ask it to do. An HTTP-transport server runs as a network service, and it faces two: what the agent asks it to do, and what anything else that can open a socket to it asks it to do. The second question is the one that gets overlooked.

That network service binds a socket, typically to `127.0.0.1` (loopback) or `0.0.0.0` (all interfaces), and accepts JSON-RPC over HTTP. Every browser request to it carries an `Origin` header for the issuing page and a `Host` header for the address it was sent to. A server meant for local use has to read those headers and check them against an allowlist. If it does not, it processes a tool call from `https://attacker.example` exactly like one from a legitimate local client.

The web's built-in defense against a page talking to your localhost is the Same-Origin Policy, enforced by the browser. But SOP gates on the origin, which is scheme plus host plus port. An attacker who controls a domain can defeat the host part with DNS rebinding: serve a DNS record for `attacker.example` with a very low TTL pointing at the attacker's own IP, let the victim's browser load the page from there, then flip the record to resolve `attacker.example` to `127.0.0.1`. The browser still believes the page's origin is `attacker.example`, so it treats a `fetch()` to `attacker.example` as same-origin and sends it without complaint. The socket now lands on the victim's loopback interface, where the MCP server is listening. To the network, the request just walked in the front door.

So binding to localhost is not a defense on its own: it keeps the port off the network, but does nothing against a browser convinced the local port is same-origin. The only thing that stops the rebind is the server reading `Origin` and `Host` and refusing what does not match. None of the four packages does that.

## The four packages

**`mcp-streamablehttp-proxy` v0.2.0**, published from the `atrawog/mcp-oauth-gateway` monorepo, binds `127.0.0.1` and runs a FastAPI app with no in-process Origin or Host check. A code comment in `create_app` delegates CORS to Traefik middleware, present in the monorepo but not in the standalone `pip install` plus console-script path. This one is the worst multiplier, because it is a proxy: it fronts an arbitrary stdio MCP server, so a successful rebind reaches whatever tool the fronted server exposes. Point it at a shell server and you have unauthenticated remote code execution on the operator's workstation, once the rebind lands, which the honest caveat below explains is the non-trivial step.

**`mcp-fetch-streamablehttp-server` v0.2.0**, from the same monorepo, binds `0.0.0.0`, all interfaces, with a `# noqa: S104` comment suppressing Bandit's warning about exactly that. No in-process check either. It goes one step further and sends `Access-Control-Allow-Origin: *`, the opposite of a defense: it tells every browser that any origin may read the responses. Because it also wraps a fetch tool, it carries the outbound SSRF surface on top of the inbound rebind surface.

**`fastmcp-http` v0.1.4**, from `ARadRareness/mcp-registry`, is a Flask development server on `0.0.0.0` with no middleware, no auth, and no Origin or Host validation anywhere in the package. No reverse proxy is referenced or shipped; the assumption that something downstream will front it is here left entirely unstated.

**`mcp-server-fetch-sse` v0.1.1** is an aiohttp HTTP-plus-SSE server with no Origin or Host validation, and it is the worst case, so it gets its own section.

## The worst case

`mcp-server-fetch-sse` composes two primitives that are bad on their own into a chain worse than either: a DNS-rebindable HTTP server that wraps a fetch tool inheriting a pre-fix SSRF. Chain them and you get a fully browser-driven path to cloud credentials with no agent anywhere in the loop.

The chain, step by step:

1. The attacker rebinds `attacker.example` to `127.0.0.1` while the operator has the page open.
2. Page JavaScript opens an SSE session against the local server. No Origin check, so the session is granted.
3. The page POSTs a `tools/call` naming the fetch tool with an IMDS URL as the argument, something like `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>/`.
4. The server accepts the call (again, no Origin or Host validation) and forwards it to the wrapped fetch tool.
5. The fetch tool retrieves the metadata endpoint (no scheme or host check) and the credentials come back in the response body, which the SSE session hands to the page.

No agent is in this loop. No prompt injection. No model decides anything. Every hop is a missing check that would have broken the chain: an Origin allowlist on the inbound side, an IP-class denylist on the outbound side. Neither is present, and the operator's only action was to load a web page. Step one, the live browser rebind, is the part that takes real engineering.

## The detector caught one of four, then the survey fixed the detector

The static rule that surfaces this class is MCP-S-014 in [mcp-witness](https://github.com/desledishant10/mcp-witness), which flags HTTP-transport MCP servers that bind without reading and validating `Origin` or `Host`. When I first ran the survey, the v0.2 detector flagged none of the four. The survey itself drove four patches (W1 through W4) that brought the rule from zero of four to four of four, each teaching it a bind or origin-read shape it had missed: a host bound to a variable or function-parameter default, a too-broad "mentions origin somewhere" suppression that a wildcard-CORS response header was quietly satisfying, the aiohttp bind shapes (`web.TCPSite`, `web.run_app`), and `os.getenv("HOST", "0.0.0.0")` env-var defaults. The full walkthrough is its own piece, [docs/detector-evolution-s014.md](https://github.com/desledishant10/mcp-witness/blob/main/docs/detector-evolution-s014.md): each patch came from a specific source file the detector had missed, not from brainstorming.

## The honest caveat

I have to be careful here, because it would be easy to oversell this, and the oversell is exactly what a careful reader should catch me on.

The server-side flaw is real and directly demonstrable: these servers accept a request carrying a mismatched, attacker-controlled `Origin` and `Host`. Proving that does not require a browser or any rebind timing at all. The quick harness sends a mismatched Origin and Host, and the server accepts it in about five seconds, with no browser in the loop. That is the vulnerability: the missing validation, not in dispute and not dependent on anything clever.

Landing a full real-world browser rebind does take engineering, because a browser is not obligated to re-resolve DNS the instant the attacker flips the record. Chromium enforces a minimum DNS cache TTL of roughly 60 seconds, so a live rebind is not instantaneous and takes work to make reliable. That constraint is about the delivery vector, not about the server-side flaw. I am not claiming a one-click instant rebind. The rebind is the real, but non-trivial, way a browser reaches the missing validation. Keeping those two things separate is the difference between an accurate writeup and a marketing one.

## Reproduction

The harness lives at [`poc/dns-rebind/`](https://github.com/desledishant10/mcp-witness/tree/main/poc/dns-rebind), built around that same honesty split.

`make demo-quick` runs in about five seconds with no Docker: it sends the mismatched-header request directly and shows the server accepting it, the server-side flaw in the form that is not in dispute.

`make demo-full` runs in about 60 seconds and stands up the full containerized chain: a victim running `mcp-streamablehttp-proxy` v0.2.0 wrapping `mcp-server-time`, an attacker nginx server, a custom rebind DNS server with the TTL-flip behavior, and a Playwright-driven browser that loads the attacker page and pivots to the victim's MCP endpoint. That is the delivery vector, the part that takes the engineering, and the inbound counterpart to the repo's `poc/ssrf` harness.

## What happened after the embargo lifted

Here is where the arc stops resembling a clean loop. The coordinated-disclosure embargo was 2026-08-10, and it has passed. I checked all four packages against GitHub and PyPI on 2026-09-10.

All four are unchanged on PyPI since disclosure: `mcp-streamablehttp-proxy` v0.2.0 (2025-07-02), `mcp-fetch-streamablehttp-server` v0.2.0 (2025-07-02), `fastmcp-http` v0.1.4 (2024-12-29), `mcp-server-fetch-sse` v0.1.1 (2025-06-29). No fix releases. All four remain vulnerable at the disclosed versions.

`fastmcp-http` (ARadRareness): I disclosed via a public GitHub issue, `ARadRareness/mcp-registry#3`, on 2026-06-02. That was the channel of last resort: GHSA disabled on the repo, no contact on the maintainer profile, only a GitHub-noreply email on PyPI. The maintainer closed the issue as "completed" on 2026-06-21, with no comment, no commits to the repository since the disclosure, and no fix release. Closed without a fix.

`mcp-streamablehttp-proxy` and `mcp-fetch-streamablehttp-server` (atrawog): I emailed `atrawog@gmail.com` on 2026-05-12, followed up on day +21 (2026-06-02), and sent a third email at day +30. No response at any point. Silent.

`mcp-server-fetch-sse`: I disclosed by email to the PyPI-listed maintainer-of-record, `jadamson@anthropic.com`, on 2026-06-02, and sent a parallel courtesy notice to Anthropic Security (`disclosure@anthropic.com`) because the package's wheel METADATA lists `Author: Anthropic, PBC`. The HackerOne intake linked from Anthropic's `security.txt` declined the report class at a triage interstitial, and the `disclosure@` email returned a no-reply auto-responder routing back to HackerOne. No human review was reached on the Anthropic side, and the maintainer never replied. Two qualifiers, both in fairness: those deflections are corporate-intake-routing artifacts, not Anthropic's position on the disclosure; and I cannot verify whether the `Author: Anthropic, PBC` attribution reflects active maintenance or attribution inherited from a fork's `pyproject.toml`, since PyPI does not verify Author claims.

The net across four independently authored packages and three maintainer teams: zero fixes shipped. One issue closed as "completed" without a fix, the other three silent. I extend the benefit of the doubt on intent. Small maintainers have finite bandwidth, and a package that lists a corporate author may have no active human behind it. But the embargo has passed, the versions are unchanged, and the writeup has to say so plainly.

This is a sober contrast to the outbound SSRF class, where at least a working community fix exists, even though the vendor there declined to merge it. For the inbound class there is no fix at all. Nobody has yet written the five to ten lines that would retire it: a Starlette `TrustedHostMiddleware` for the ASGI servers, an aiohttp middleware for the aiohttp server, or a Flask `before_request` hook for the Flask server, each validating `Host` and `Origin` against an allowlist.

## Why this is one bug, not four

The single sentence that describes all four is "some external layer handles Origin and Host enforcement." Traefik in the atrawog monorepo, an unnamed reverse proxy for the Flask server, the operator's good judgment in the rest. The assumption holds cleanly for the deployment the author had in mind, and fails for the one users actually run, because the standalone `pip install` plus console-script flow ships without that external layer.

That is the same shape as the outbound SSRF class: an external constraint quietly load-bearing, with no in-process enforcement behind it when the constraint is absent. These are not a pile of individual bugs. They are one belief about where the boundary lives, held independently by four sets of authors, wrong the same way each time. The correction is to defend in-process by default and treat the reverse proxy as defense in depth, not as the boundary: safe out of the box on the plain `pip install` path, with an explicit opt-in env var for operators who really do run behind a proxy that handles this. The whole class is waiting on ten lines apiece.

mcp-witness is open source under Apache 2.0 at <https://github.com/desledishant10/mcp-witness>. The detector, the reproduction harness, and the full disclosure record for all four packages live there. If you run HTTP-transport MCP servers, the audit is a few minutes of work. The fix, when someone decides to ship it, is a few lines.
