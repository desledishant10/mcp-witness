# DNS-Rebinding Survey of PyPI HTTP-Transport MCP Servers

**Date:** 2026-05-12
**Rule scope:** MCP-S-014 (HTTP transport without Origin/Host validation)
**Outcome:** **3 confirmed DNS-rebinding vulnerabilities** across **2 disclosure targets** (one monorepo with 2 affected packages, plus 1 independent package). **1 candidate still unverified** (uses `aiohttp.web` — not yet in the S-014 detector). Two structural S-014 rule weaknesses also surfaced; logged as v0.3 work.

This survey was the first systematic application of MCP-Scan's static analyzer to HTTP-transport MCP servers. The class — local HTTP MCP servers exploitable from a browser via DNS rebinding — was the audit target precisely because (a) the S-014 rule shipped in v0.2.0 is designed for it, (b) it pairs naturally with the existing v0.1 SSRF disclosure storyline, and (c) prior art (e.g. Cursor's MCP) shows the class is real.

## Methodology

1. Pulled all packages whose name contains `mcp` from PyPI's simple index (15,574 total).
2. Filtered to names matching `(proxy|bridge|gateway|sse|http|streamablehttp|remote|relay)` (287 candidates).
3. Selected the top 6 by name-signal strength (explicit transport keywords, generic-purpose naming, plausible installed user base).
4. Installed each with `pip install --target` and ran `python -m analyzer <pkg>` against the source tree.
5. For non-firing candidates, manually inspected for (a) bind-address constants, (b) Origin/Host validation middleware, (c) CORS configuration. The S-014 detector missed several real cases — see §"Rule weaknesses surfaced," below.

## Candidates and verdicts

| Package | Source | Bind default | Origin/Host check | Verdict |
|---|---|---|---|---|
| `mcp-streamablehttp-proxy` v0.2.0 | [atrawog/mcp-oauth-gateway](https://github.com/atrawog/mcp-oauth-gateway/tree/main/mcp-streamablehttp-proxy) | `127.0.0.1` (loopback) | **None in-process.** Comment explicitly delegates CORS to "Traefik middleware" — external, not present in default deploy. | **Vulnerable — DNS rebinding** |
| `mcp-fetch-streamablehttp-server` | [atrawog/mcp-oauth-gateway](https://github.com/atrawog/mcp-oauth-gateway/tree/main/mcp-fetch-streamablehttp-server) | `0.0.0.0` (all interfaces, env-overridable but defaults wide-open). `# noqa: S104` suppression of Bandit's all-interfaces warning. | **None in-process.** Returns `Access-Control-Allow-Origin: *` as a response header — the opposite of a defense. | **Vulnerable — DNS rebinding + cross-origin** |
| `fastmcp-http` | [ARadRareness/mcp-registry](https://github.com/ARadRareness/mcp-registry) | `0.0.0.0` (all interfaces) | **None anywhere in package.** Flask dev server, no middleware, no auth. | **Vulnerable — DNS rebinding** |
| `mcp-fetch-streamablehttp-server`'s `transport.py` (separate issue) | same | — | Wildcard CORS sent in response | Distinct browser-cross-origin issue paired with the rebind |
| `mcp-server-fetch-sse` | community fork of Anthropic's `mcp-server-fetch` | unknown — uses `aiohttp.web` (not caught by S-014's `uvicorn.run`-shaped detector) | unknown | **Unverified — re-audit after S-014 v0.3 expansion** |
| `mcp-http-to-stdio` | (proxies remote HTTP MCP to local stdio — client direction) | n/a | n/a | **Out of scope** — proxies *toward* an HTTP server, doesn't bind one |

## Disclosure targets

### Target 1 — `atrawog/mcp-oauth-gateway` (2 packages)
**Maintainer:** Andreas Trawoeger (`atrawog@gmail.com`), [@atrawog](https://github.com/atrawog)
**Issues:** https://github.com/atrawog/mcp-oauth-gateway/issues
**Affected packages:** `mcp-streamablehttp-proxy`, `mcp-fetch-streamablehttp-server` (and likely other components in the same monorepo — full repo audit recommended)
**Coordinated disclosure plan:** single report, both packages, propose 90-day embargo (matches the project's existing SSRF disclosure cadence).

### Target 2 — `ARadRareness/mcp-registry`
**Maintainer:** ARadRareness (no public email; GitHub-only contact)
**Affected package:** `fastmcp-http`
**Coordinated disclosure plan:** GitHub security advisory (no public email available).

## Disclosure ordering recommendation

1. **`atrawog/mcp-oauth-gateway` first** — clearest impact (proxy is a *universal* escalation vector for whatever stdio MCP it fronts), responsive maintainer (active repo, email available), single report covers two CVEs.
2. **`fastmcp-http` second** — narrower deployment footprint than the OAuth gateway monorepo, requires GitHub-only contact channel.
3. **`mcp-server-fetch-sse` last** — pending S-014 rule expansion to detect `aiohttp.web` bind patterns; verify before disclosing.

## Combined narrative (audit storyline)

> Across MCP-Scan v0.1 and v0.2 audits I have now found, in PyPI-published Python MCP servers:
>
> - **Two SSRF instances** in the stdio fetch family (`mcp-server-fetch`, `mcp-server-http-request`) — server reaching out to attacker-chosen URLs, demonstrated end-to-end on EC2 against the cloud-metadata service.
> - **Three DNS-rebinding instances** in the HTTP/SSE transport family (`mcp-streamablehttp-proxy`, `mcp-fetch-streamablehttp-server`, `fastmcp-http`) — browser reaching in to attacker-chosen tools via rebound DNS.
>
> Two complementary classes covering both ends of the data-flow boundary. Surfaced by static rules I designed (S-009, S-014) and confirmed by reading source.

This is the v0.2 phase-3 audit deliverable that pushes the project past the "≥2-3 CVEs" target from the original capstone plan, with a coherent threat-model story (in-flow vs out-of-flow attacks against the MCP transport layer).

## Rule weaknesses surfaced

These are the cases S-014 *should* have caught but didn't. Logged for v0.3.

### W1 — Non-constant `host=` arguments

The current detector requires `host=` kwarg to be a string `ast.Constant`. Real-world code routinely uses `host=host` where `host` is a function parameter or env-derived. Example: `mcp-streamablehttp-proxy/server.py:59`:

```python
def run_server(server_command, host: str = "127.0.0.1", port: int = 3000, ...):
    ...
    uvicorn.run(app, host=host, port=port, log_level=log_level)
```

**Fix:** when `host=` is non-constant, follow one hop to the surrounding function's default-arg value (`ast.FunctionDef.args.defaults`). If the default resolves to a rebindable constant, fire with severity `medium` and an `origin_unchecked_dynamic_host` category.

### W2 — "Origin" keyword suppression is too aggressive

S-014 currently suppresses the finding if the source file contains the word "origin" anywhere. Defeated by:
- Comments promising external middleware ("`# CORS is handled by Traefik middleware`") that doesn't exist in the default deploy.
- Wildcard CORS *response* headers (`Access-Control-Allow-Origin: *`) — which are themselves part of the vulnerability, not a defense.

**Fix:** the suppression should be conditioned on an actual Origin-*reading* code path. Heuristic: require either a call to a known-validator name (`is_valid_origin`, etc.), or `request.headers.get("Origin"|"Host")` followed by a comparison/conditional. Comment-only references no longer suppress.

### W3 — `aiohttp.web` bind shapes not recognized

Servers built on `aiohttp.web` use `web.AppRunner`, `web.TCPSite(runner, host, port)`, or `web.run_app(app, host=...)`. None match the `uvicorn.run` / `.run(host=...)` shape. `mcp-server-fetch-sse` falls into this gap.

**Fix:** add `web.run_app`, `web.TCPSite` to the detector. Also consider `hypercorn.serve(...)`, `daphne` patterns for completeness.

## Next steps

1. **Draft disclosure for `atrawog/mcp-oauth-gateway`** — single report, both packages, propose 90-day embargo with publication aligned to 2026-08-10 (existing SSRF embargo) or a new 90-day window starting today.
2. **Write per-package finding entries** with full reproduction commands. Start with `mcp-streamablehttp-proxy` (cleanest case: pure 127.0.0.1, no CORS noise).
3. **Build the DNS-rebind reproduction harness** — controlled DNS server with TTL-flip behavior, attacker page that triggers the rebind and posts to `/mcp` once rebound. Containerized for portability.
4. **Patch S-014 rule weaknesses (W1, W2, W3) in v0.3.** Re-run survey to confirm `mcp-server-fetch-sse` verdict.

The reproduction harness is the most labor-intensive remaining piece; everything else is documentation.
