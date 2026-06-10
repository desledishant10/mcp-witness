# Example 02 — The SSRF class across two packages

What "class issue, not single-package issue" looks like in code. Same static rule (MCP-S-009), two independently-maintained PyPI packages, identical finding shape. Both disclosed under the same embargo; one already fixed upstream.

## Run

```bash
# Audit both captures back-to-back
mcpsentry-analyze captured-mcp-server-fetch.json
mcpsentry-analyze captured-mcp-server-http-request.json
```

## Expected output

### `mcp-server-fetch` (Anthropic reference; one tool, one URL parameter)

```
[HIGH] MCP-S-001  <captured>:0  fetch
[HIGH] MCP-S-009  <captured>:0  fetch
2 findings.
```

One `fetch` tool with a URL parameter, no constraint, no validation language. Disclosed as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143); fix shipped in [PR #4226](https://github.com/modelcontextprotocol/servers/pull/4226).

### `mcp-server-http-request` (community; five tools, five URL parameters)

```
[HIGH] MCP-S-009  <captured>:0  http_get
[HIGH] MCP-S-009  <captured>:0  http_post
[HIGH] MCP-S-009  <captured>:0  http_put
[HIGH] MCP-S-009  <captured>:0  http_patch
[HIGH] MCP-S-009  <captured>:0  http_delete

5 findings.
```

Five HTTP-method tools, each with the same shape: URL parameter, no constraint, no validation language. The same SSRF surface multiplied by 5.

Note: `mcp-server-http-request`'s tool descriptions are written in a more declarative voice than `mcp-server-fetch`'s — no second-person imperatives directed at the model — so S-001 doesn't fire on this package. S-009 is the load-bearing finding for the SSRF class; S-001 adds context when it's also present.

## The class observation

Two independently-developed packages, two different maintainers, two different release cadences. They share `httpx` as their HTTP client (with `httpx<0.28` pinned), and they share an approach to URL handling: take whatever the agent says, pass it to `httpx.get()`, return the response. Neither implements scheme allowlisting, host denylisting, or any awareness of link-local ranges.

This is the more important finding. It's not "a buggy package." It's "an ecosystem norm." Every Python MCP HTTP-client server I've looked at follows the same pattern — the URL parameter is modeled as an unconstrained string, and the assumption is that the agent will be responsible for what URLs it asks to fetch. That assumption is wrong, because the threat model for MCP servers explicitly includes adversarially-influenced tool arguments via prompt injection.

## What "responsible" looks like as a code change

The fix is small and shared. The PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) that landed for `mcp-server-fetch` is the reference implementation; it added:

- Scheme allowlist (`http`, `https` only)
- IP-class denylist (link-local `169.254/16`, loopback `127/8`, `::1`, RFC 1918 ranges, IPv6 ULA `fc00::/7`)
- **Per-redirect validation** — a more rigorous defense than the original disclosure asked for, since it closes a 302-bypass class (public URL → 302 → `169.254.169.254/...` would otherwise escape a first-request-only check)

The same diff pattern translates near-verbatim to `mcp-server-http-request` and any other server in the class. That's the "small and shared fix" the survey makes the case for.

## How to find SSRF surface in your own audits

Same pattern as Example 01, applied to whichever server is in scope:

```bash
mcpsentry-audit <pypi-package>
```

Look for S-009 specifically — it's the load-bearing finding for SSRF. S-001 adds context (the tool is written to nudge the model) but S-009 is what tells you the implementation doesn't constrain the URL.

## Related material

- Full survey writeup (covers both SSRF + DNS rebinding classes): blog draft at `drafts/blog-draft-2026-08-10-mcp-transport-layer-blind-spot.md` (embargo expires 2026-08-10)
- Detailed finding entries: [findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md](../../findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md) and [findings/2026-05-11-MCP-D-003-http-request-direct-environment-dependent-ssrf.md](../../findings/2026-05-11-MCP-D-003-http-request-direct-environment-dependent-ssrf.md)
- EC2 reproduction runbook: [docs/audit-runbook-ec2-ssrf-verification.md](../../docs/audit-runbook-ec2-ssrf-verification.md)
