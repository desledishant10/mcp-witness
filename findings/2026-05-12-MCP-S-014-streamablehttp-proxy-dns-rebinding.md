# MCP-S-014 vs mcp-streamablehttp-proxy — DNS-rebinding via missing Origin/Host validation

**Date:** 2026-05-12
**Target:** `mcp-streamablehttp-proxy` v0.2.0 (PyPI; [atrawog/mcp-oauth-gateway](https://github.com/atrawog/mcp-oauth-gateway/tree/main/mcp-streamablehttp-proxy))
**Tested by:** MCP-S-014 (static, after rule W1 fix would have fired automatically) + manual source review
**Agent driver:** n/a (transport-layer finding, agent-independent)
**Outcome:** **VULNERABILITY (source-confirmed; full browser DNS-rebind PoC pending repro harness)** — universal escalation vector against any stdio MCP server the proxy fronts. Coordinated disclosure drafted at [disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md](../disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md). Embargo target: 2026-08-10.

## Result

`mcp-streamablehttp-proxy` bridges stdio MCP servers to HTTP for browser-/remote-agent access. In its documented default configuration — `pip install` + run via console script — it binds a FastAPI app to `127.0.0.1:3000` and accepts `POST /mcp` JSON-RPC requests **with no Origin or Host header validation, no authentication, and no in-process CORS middleware**. The repository's intended posture is to front the proxy with Traefik as an OAuth reverse proxy, but the default `pip install` deployment ships without Traefik and the package contains no fallback enforcement.

Any web page visited by the operator can, after DNS rebinding turns the attacker domain into `127.0.0.1`, issue same-origin POST requests to `/mcp` and invoke whatever tool the wrapped stdio MCP exposes. **The escalation is universal**: it inherits the toolset of whatever stdio MCP is behind the proxy at launch time. With `mcp-server-shell`, the result is unauthenticated RCE on the operator's workstation; with `mcp-server-aidd` (33 tools, fs-write + exec), full developer-host takeover.

## Source-level evidence

### Bind to loopback by default

`mcp_streamablehttp_proxy/server.py` lines 12–59:

```python
def run_server(
    server_command: List[str],
    host: str = "127.0.0.1",
    port: int = 3000,
    session_timeout: int = 300,
    log_level: str = "info",
):
    ...
    # Create FastAPI app
    app = create_app(server_command, session_timeout)

    # Run server without automatic trailing slash redirects
    uvicorn.run(app, host=host, port=port, log_level=log_level)
```

Loopback bind is rebindable from a browser context — an attacker-controlled domain that resolves to `127.0.0.1` after a TTL flip can issue requests against the proxy as same-origin from the browser's perspective.

### No middleware in `create_app`

`mcp_streamablehttp_proxy/proxy.py` lines 389–395:

```python
def create_app(server_command: List[str], session_timeout: int = 300) -> FastAPI:
    """Create FastAPI app with MCP proxy endpoints."""
    app = FastAPI()

    # CORS is handled by Traefik middleware - no need to configure here
    # This ensures CORS headers are set in only one place as required
```

No `app.add_middleware(...)` call anywhere in the package. Repo-wide grep for `add_middleware`, `Middleware(`, `TrustedHostMiddleware`, `CORSMiddleware`, `AuthMiddleware` returns zero matches.

### Handler explicitly disclaims validation

`mcp_streamablehttp_proxy/proxy.py` lines 419–421 (`handle_mcp`):

```python
@app.post("/mcp")
async def handle_mcp(request: Request):
    """Handle MCP requests without trailing slash redirect."""
    # CORS is handled by Traefik middleware - no validation needed here
```

The comment is a hint — the maintainer explicitly assumed Traefik would handle Origin enforcement upstream of this handler. In the default deployment, there is no Traefik.

## Reproduction (source-level; full PoC harness pending)

Verifiable from source by issuing a request with no Origin header and observing acceptance:

```bash
pip install mcp-streamablehttp-proxy==0.2.0 mcp-server-time
mcp-streamablehttp-proxy python -m mcp_server_time &      # binds 127.0.0.1:3000

# Browser-equivalent request with no Origin allowlist enforced:
curl -X POST http://127.0.0.1:3000/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
         "params":{"protocolVersion":"2025-06-18","capabilities":{},
                    "clientInfo":{"name":"poc","version":"0"}}}'
```

Expected: 200 OK with a populated `Mcp-Session-Id` response header. The same request with an `Origin: https://attacker.example` header is accepted identically — the server doesn't read or compare the Origin header anywhere in the handler chain.

A browser-driven DNS-rebind PoC follows the standard template:

1. Attacker hosts `evil.example` with a custom authoritative DNS server.
2. Initial resolution returns attacker IP with low TTL.
3. JavaScript on `evil.example` waits past the TTL (or forces a re-resolution).
4. DNS server flips, returning `127.0.0.1` for `evil.example`.
5. JavaScript issues `fetch('http://evil.example:3000/mcp', { method: 'POST', body: JSON.stringify({...tools/call...}) })`. Browser treats it as same-origin (the page is loaded from `evil.example` and the request goes to `evil.example`). Request lands on the operator's local proxy.
6. Proxy accepts the request and invokes the requested tool on the wrapped stdio MCP server.

The full repro harness is the subject of follow-up work — see §"Suggested follow-up" below.

## Impact

**Severity: High.** Two threat-model conditions:

1. **Operator runs the proxy on their dev workstation** (the default deployment per the README's hello-world). This is the intended use case for browser-based MCP clients.
2. **Operator visits any web page in any browser** while the proxy is running. No interaction beyond visiting the page is required.

Once both conditions hold, the attacker page can execute arbitrary tools via the wrapped MCP server. The blast radius is whatever the wrapped server can do:

| Wrapped server | Tools exposed | Attacker capability |
|---|---|---|
| `mcp-server-shell` | `execute_command` | Unauthenticated RCE |
| `mcp-server-aidd` | 33 tools (read/write/exec) | Full filesystem + shell takeover |
| `mcp-server-git` | 12 tools (commit/checkout/branch) | Repo manipulation |
| `mcp-server-fetch` | URL fetch | Server-side fetch → recursive SSRF + cloud-metadata exfil per [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) |

The proxy is the universal multiplier — every stdio MCP server inherits the rebindability when fronted by it.

## Interpretation

**This is a default-deployment bug, not a misuse bug.** The maintainer's architectural assumption (Traefik fronts every deploy) is reasonable for the OAuth gateway as a whole, but the package is published as a standalone PyPI distribution with its own console script and a `host="127.0.0.1"` default that implies standalone use is supported. The standalone path needs in-process Origin enforcement.

The fix is small and local — `TrustedHostMiddleware` + a one-paragraph startup banner if running in non-Traefik mode is enough.

## Mitigations

In the package, in order of effort vs payoff:

1. **Add `TrustedHostMiddleware`** at `create_app` time:

    ```python
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", f"127.0.0.1:{port}", f"localhost:{port}"],
    )
    ```

    Blocks Host-header-based DNS rebind cleanly.

2. **Read and validate `Origin`** on `/mcp` POST. Standard MCP-spec-compliant defense: accept absent Origin (non-browser clients) OR Origin matching an allowlist; reject everything else.

3. **Refuse to start without an explicit `MCP_TRUST_HEADER_HANDLED_EXTERNALLY=1` env var** if the operator clearly wants the Traefik-fronted posture. Startup banner explains the threat model and points at the env var.

4. **Update inline comments** that delegate to Traefik so they don't lull future contributors into removing in-process middleware that does get added.

For operators who can't wait for a patched release: front the proxy with a reverse proxy (Caddy, nginx, Traefik) that enforces Origin/Host allowlist, or bind to a Unix domain socket instead of TCP.

## Caveats

- **Default deployment is the bug, not the package's existence.** Run with Traefik in front and the bug is mitigated. The disclosure is calibrated to this — recommended remediation gives the maintainer an opt-in path to preserve the Traefik posture while making the standalone path safe.
- **No full PoC harness yet.** The DNS-rebind reproduction is described from first principles; a containerized end-to-end demonstration is the next deliverable (see [findings/2026-05-12-dns-rebinding-survey.md](2026-05-12-dns-rebinding-survey.md) §"Next steps"). Source-level analysis alone is sufficient to claim the vulnerability — every component of the attack is observable in the code without execution.

## Suggested follow-up

1. **File the GitHub Security Advisory** per [disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md](../disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md) — covers this finding and the sibling `mcp-fetch-streamablehttp-server` finding in one report.
2. **Build the DNS-rebind reproduction harness.** Docker compose: attacker DNS server with TTL-flip behavior, attacker web server, victim container running the proxy. Browser PoC in the victim container or via Playwright. Single command demonstrates end-to-end.
3. **Patch S-014 W1** in MCP-Scan v0.3 so the `host=variable` pattern at `server.py:59` is detected automatically (currently the rule's static detector requires an `ast.Constant` host value).
4. **Audit the rest of the `atrawog/mcp-oauth-gateway` monorepo.** If two packages share the "Traefik handles CORS" assumption, others likely do too — the disclosure already requests a maintainer-driven full repo audit.

## Disclosure

Coordinated disclosure drafted; covers both this finding and `mcp-fetch-streamablehttp-server` in one report. Status: draft, awaiting filing as a GitHub Security Advisory against `atrawog/mcp-oauth-gateway`.

Full disclosure body and submission steps: [disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md](../disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md). Embargo target 2026-08-10, aligning with the existing SSRF disclosure for `mcp-server-fetch` / `mcp-server-http-request`.
