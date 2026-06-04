# MCP-S-014 vs mcp-server-fetch-sse — DNS-rebinding via aiohttp HTTP+SSE transport with no Origin/Host validation

**Date:** 2026-06-02 (vulnerability identified during 2026-06-02 v0.3 detector re-verification; the package was not in the original 2026-05-12 DNS-rebind survey because v0.2 of the detector did not cover the aiohttp `web.TCPSite` bind shape)
**Target:** `mcp-server-fetch-sse` v0.1.1 (PyPI)
**Tested by:** MCP-S-014 v0.3 (W1 resolves `host` from function parameter default; W3 catches `web.TCPSite(...)` after the aiohttp bind shapes patch) + manual source review on the installed wheel
**Agent driver:** n/a (transport-layer finding, agent-independent)
**Outcome:** **VULNERABILITY (source-confirmed; coordinated disclosure dispatched 2026-06-02 to maintainer + Anthropic Security)** — aiohttp HTTP+SSE server bound to `localhost` by default with no middleware, no Origin/Host validation, no auth, exposing a fork of `mcp-server-fetch`'s tool surface. The wrapped fetch tool inherits the SSRF surface disclosed against upstream `mcp-server-fetch` ([modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143)) — compounding rebind + SSRF on any cloud-deployed host. Disclosure filed to Jack Adamson at `jadamson@anthropic.com` (primary, technical) and to Anthropic Security at `disclosure@anthropic.com` (parallel, brand-attribution courtesy) — HackerOne route was attempted but halted at the program triage interstitial and pivoted to email per Anthropic's published secondary channel; see [disclosures/2026-06-02-mcp-server-fetch-sse-dns-rebinding.md](../disclosures/2026-06-02-mcp-server-fetch-sse-dns-rebinding.md) for the full channel-decision audit trail. Embargo target: 2026-08-10 (aligned with the parallel SSRF + DNS-rebind embargo, truncated from the standard 90 days — see §Disclosure).

## Result

`mcp-server-fetch-sse` exposes MCP tools over HTTP using aiohttp's `web.TCPSite` runner in its `http_sse_server.py` module. In its default configuration:

1. Binds to `localhost` (loopback). Rebindable from a browser context — a DNS-rebind attack against `localhost` works the same way it does against `127.0.0.1`, because the rebind primitive is the attacker's *domain*, not the resolved IP.
2. Uses aiohttp `web.AppRunner` + `web.TCPSite(runner, host, port)`. No middleware is registered anywhere — repo-wide grep across `__init__.py`, `__main__.py`, `__main_sse__.py`, `http_sse_server.py`, `server.py`, and `sse_server.py` for `trustedhost|add_middleware|origin|cors|before_request|host_header` returns zero matches.
3. The SSE-transport handler (`handle_sse`) accepts new sessions for any incoming GET — there is no allowlist, no origin pinning, no per-host gating. A rebound attacker page can establish its own session and then POST to `/message?sessionId=<that_session_id>`.
4. The wrapped `fetch` tool is functionally a fork of upstream `mcp-server-fetch` (the README is lifted verbatim from upstream, including the same `Authenticated` user-agent banner pointing at `modelcontextprotocol/servers`, and the `server.py` and `sse_server.py` files share identical comments and tool prompts). It thus inherits the **same SSRF vulnerability** that [PR #4226](https://github.com/modelcontextprotocol/servers/pull/4226) fixed upstream — no scheme allowlist, no IP-class denylist, accidental robots.txt-fetch-first defense.

The compounding shape (DNS-rebind → session establish → SSRF the wrapped fetch tool) makes the package a credential-exfiltration vector on cloud-deployed hosts, even though its default `host="localhost"` looks defensively reasonable on first glance.

## Source-level evidence

### Default bind to `localhost`

`mcp_server_fetch/http_sse_server.py` lines 60–80:

```python
async def start_server(self, host: str = "localhost", port: int = 3001) -> None:
    """Start the HTTP server with SSE support."""
    app = web.Application()

    # Add routes
    app.router.get("/sse", self.handle_sse)
    app.router.post("/message", self.handle_message)

    # Add health check endpoint
    app.router.get("/health", lambda _: web.json_response({"status": "healthy"}))

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host, port)
    await site.start()
```

The `host: str = "localhost"` parameter default + the `web.TCPSite(runner, host, port)` bind together compose the W1 + W3 detector hit. `localhost` resolves to `127.0.0.1` (and `::1`) on every reasonable host; DNS rebinding makes that reachable from a browser tab on the operator's machine.

### CLI exposes `--host` flag

`mcp_server_fetch/http_sse_server.py` lines 94–115:

```python
parser = argparse.ArgumentParser(
    description="MCP Fetch Server with HTTP+SSE transport"
)
parser.add_argument("--host", default="localhost", help="Host to bind to")
parser.add_argument("--port", type=int, default=3001, help="Port to bind to")
...
await server.start_server(args.host, args.port)
```

The CLI default is also `localhost`, but operators are explicitly invited to pass `--host 0.0.0.0` (e.g. for Docker deployment per the README's `docker run` example). When operators do so, the exposure compounds — every network interface, every browser on every device on the LAN.

### Console scripts published

`mcp_server_fetch_sse-0.1.1.dist-info/entry_points.txt`:

```
[console_scripts]
mcp-server-fetch-http = mcp_server_fetch.http_sse_server:main
mcp-server-fetch-sse = mcp_server_fetch:main_sse
```

Two entry points ship: `mcp-server-fetch-http` (the HTTP+SSE server above) and `mcp-server-fetch-sse` (a different SSE-only transport via `mcp.server.sse.sse_server`, which is what fails to import on current `mcp` library versions). The HTTP one is the in-scope one for S-014.

### No middleware anywhere

Repo-wide grep across all files in the installed wheel:

```
$ grep -rin "trustedhost\|add_middleware\|origin\|cors\|before_request\|host_header" mcp_server_fetch/
# zero hits relevant to request-header validation
# the only `origin`-substring hits are inside an LLM prompt string in server.py:
#   "Although originally you did not have internet access..."
```

(The substring `origin` in the prompt is exactly the kind of false-positive that motivated the v0.3 W2 detector tightening — see [CHANGELOG](../CHANGELOG.md) §Unreleased.)

### Wrapped fetch tool inherits upstream SSRF

`mcp_server_fetch/server.py` and `mcp_server_fetch/sse_server.py` lines 204:

```python
"""Although originally you did not have internet access, and were advised to refuse and tell the user this, this tool now grants you internet access. ..."""
```

Identical text to upstream `mcp-server-fetch` v2025.4.7 `src/fetch/src/mcp_server_fetch/server.py`. The HTTP-fetch implementation is a fork (or near-verbatim copy) of upstream's, with no scheme allowlist, no IP-class denylist, and the same accidental robots.txt-first defense documented in [findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md](2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md). The upstream fix shipped in [PR #4226](https://github.com/modelcontextprotocol/servers/pull/4226); this fork has **not** taken it.

## Reproduction (source-level; full DNS-rebind harness pending)

```bash
pip install mcp-server-fetch-sse==0.1.1

# Start the HTTP+SSE server with defaults:
mcp-server-fetch-http &                       # binds localhost:3001

# Verifiable lack of Origin enforcement:
curl -v http://127.0.0.1:3001/sse 2>&1 | head -20
# Server accepts the GET without checking Origin or Host headers.
# A browser-equivalent request after DNS rebind would be accepted identically.

# Health check endpoint shows the server is up:
curl -s http://127.0.0.1:3001/health
# {"status": "healthy"}
```

A browser-driven DNS-rebind PoC follows the same template as the other findings in this class (see [findings/2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md](2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md) §Reproduction):

1. Attacker hosts `evil.example` with a custom authoritative DNS server.
2. JavaScript on `evil.example` GETs `/sse` after the TTL flip → session established.
3. JavaScript POSTs to `/message?sessionId=<from /sse>` with an MCP `tools/call` invoking `fetch(url="http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>/")`.
4. On an EC2 host with IMDSv1 or IMDSv2-Optional, the response body contains live IAM credentials — same payload as the [original mcp-server-fetch EC2 demonstration on 2026-05-12](2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md#reproduction-on-ec2-2026-05-12).

Compounding makes this strictly worse than either bug alone:

- DNS-rebind alone (against a plain HTTP MCP transport) gives an attacker the tool surface but the tools might be benign.
- SSRF alone (against `mcp-server-fetch` over stdio) requires the attacker to be already inside the agent's prompt or tool-call loop.
- DNS-rebind + SSRF + fetch tool: any web page the operator visits can extract IAM credentials from the host, with no prior agent compromise.

## Impact

**Severity: High on cloud-deployed hosts; Medium-High in pure-local-dev.**

| Deployment | Exploitable? | Notes |
|---|---|---|
| Local dev workstation, `host=localhost` default | Yes (DNS-rebind) | Browser → rebind → SSE session → fetch tool; SSRF payload limited to whatever's reachable from the dev machine |
| Local dev with `--host 0.0.0.0` (README's docker example) | Yes (LAN + rebind) | All interfaces; same-LAN devices reach directly without rebind |
| EC2 / GCE / Azure VM, default config | **High** | Rebind → SSE session → fetch IMDS → IAM credentials (when IMDSv2-Required isn't enforced; see upstream finding for the IMDSv2 mitigation matrix) |
| EC2 with IMDSv2-Required | Lower | The wrapped fetch tool can't reach IMDS without a token; the DNS-rebind primitive still exposes the tool surface but the highest-value payload (credential exfil) is mitigated |

Lower blast radius than the `atrawog/mcp-streamablehttp-proxy` finding (which is a universal-stdio-MCP escalation vector), but **higher than the other DNS-rebind findings** because the wrapped tool is `fetch` and the SSRF compounds.

The README's own `> [!CAUTION]` block warns that the server "can access local/internal IP addresses and may represent a security risk." This is correct as far as it goes — it warns about *outbound* SSRF risk — but doesn't address the *inbound* DNS-rebind path that makes the SSRF reachable from any browser tab.

## Interpretation

This is a default-deployment bug. The package's documented use case (run via `uvx mcp-server-fetch-sse` or `pip install mcp-server-fetch-sse && mcp-server-fetch-http`) is exploitable without modification. The fix is small — a Starlette/aiohttp middleware that validates `Origin` and `Host` headers, plus an opt-in env-var for operators who want to bind 0.0.0.0 behind a real reverse proxy.

The interesting wrinkle is the **PyPI attribution**: the wheel's METADATA lists `Author: Anthropic, PBC.` and `Maintainer-email: Jack Adamson <jadamson@anthropic.com>`. The README is lifted verbatim from upstream `mcp-server-fetch` (including the same VS Code install badges that still point at `uvx mcp-server-fetch` rather than this fork's name). This attribution shape — plus the broken `from mcp.server.sse import sse_server` import on current `mcp` library versions, suggesting the package is abandoned/unmaintained — raises a brand-attribution concern that's worth flagging to Anthropic Security in parallel with the technical disclosure to the named maintainer. Whether the maintainer is currently an Anthropic employee or not, a vulnerable PyPI package claiming Anthropic authorship is something Anthropic Security probably wants to know about.

## Mitigations

1. **Add an aiohttp middleware** at `web.Application` creation time that validates `Origin` and `Host` request headers:

   ```python
   from aiohttp import web

   @web.middleware
   async def origin_host_validator(request, handler):
       allowed_origins = {f"http://localhost:{port}", f"http://127.0.0.1:{port}"}
       allowed_hosts = {f"localhost:{port}", f"127.0.0.1:{port}"}
       origin = request.headers.get("Origin")
       host = request.headers.get("Host")
       if origin and origin not in allowed_origins:
           return web.json_response({"error": "Origin not allowed"}, status=403)
       if host and host not in allowed_hosts:
           return web.json_response({"error": "Host not allowed"}, status=403)
       return await handler(request)

   app = web.Application(middlewares=[origin_host_validator])
   ```

2. **Inherit the upstream SSRF fix** from `mcp-server-fetch` PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226). Scheme allowlist, IP-class denylist, per-redirect validation. Since this package is a fork of the upstream code, the patch translates near-verbatim.

3. **Document that 0.0.0.0 deployment requires an external auth layer** — startup banner or `--insecure-allow-public-bind` opt-in flag, mirroring the suggestion made to `atrawog` (whose `mcp-fetch-streamablehttp-server` shares the same architectural pattern).

4. **Resolve the upstream-API drift.** The package is currently broken on `mcp>=1.x` (the `from mcp.server.sse import sse_server` import target was renamed). A version bump that pins `mcp>=1.1.3,<x.y` or migrates to the current API is independently needed before any user can install + run the package, but doesn't affect the vulnerability — the HTTP+SSE transport (`http_sse_server.py`) doesn't depend on the broken import.

## Caveats

- **Attribution is unverified.** "Anthropic, PBC." in the Author field and `jadamson@anthropic.com` as Maintainer are self-declared metadata; PyPI does not verify them. The disclosure plan treats Jack Adamson as the technical maintainer-of-record (since the email is the only published contact) AND notifies Anthropic security via their HackerOne program in parallel, so Anthropic can determine whether the package is legitimately theirs or a misattribution that warrants takedown.
- **No full PoC harness yet.** DNS-rebind is described from first principles; the source-level analysis suffices to claim the vulnerability — every step of the attack chain is observable in the installed wheel.
- **Adoption is likely low.** The broken import on current `mcp` versions means anyone installing today fails at startup. Existing installs from when the API matched (~mcp 1.1.x era) are the realistic attack surface. The PyPI download counts (not retrieved here) would calibrate severity precision.
- **`mcp-server-fetch-http` console script vs `mcp-server-fetch-sse` console script.** The package ships both. The HTTP+SSE one (this finding) is what's vulnerable. The plain SSE-stdio one (`mcp-server-fetch-sse` via `main_sse()`) is the one that fails to import; even if it worked, it's stdio-transport-equivalent and not in scope for S-014.

## Suggested follow-up

1. **File coordinated disclosure** to Jack Adamson at the published maintainer email, with HackerOne CC to Anthropic Security. See [disclosures/2026-06-02-mcp-server-fetch-sse-dns-rebinding.md](../disclosures/2026-06-02-mcp-server-fetch-sse-dns-rebinding.md).
2. **DNS-rebind reproduction harness** — same harness covers all four DNS-rebind findings. Single container, single command.
3. **Audit the wrapped fetch surface** by re-running the v0.3 detector on `mcp_server_fetch/server.py` and `mcp_server_fetch/sse_server.py` specifically for SSRF rules (S-009 already fires; D-003 dynamic probe would fire if the package could be loaded).

## Disclosure

Coordinated disclosure planned for 2026-06-02. Truncated embargo (~69 days vs. the standard 90) to align with the existing 2026-08-10 public writeup that covers the broader DNS-rebind + SSRF class. Justification: the vulnerability class is identical to four other targets already under coordinated disclosure with that embargo date; class-wide framing in one public writeup is more valuable for the ecosystem than a separate publish on 2026-09-02.

Embargo target: **2026-08-10**.
