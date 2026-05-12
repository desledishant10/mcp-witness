# DNS-rebinding in mcp-oauth-gateway HTTP-transport packages (mcp-streamablehttp-proxy, mcp-fetch-streamablehttp-server)

**Filed:** 2026-05-12
**Filed by:** Dishant Desle — didesle7@gmail.com
**Filed to:**
- Preferred: GitHub Security Advisory (private) — https://github.com/atrawog/mcp-oauth-gateway/security/advisories/new
- Fallback / heads-up: email to Andreas Trawoeger — `atrawog@gmail.com` (listed as `Author-email` in the `mcp-fetch-streamablehttp-server` PyPI metadata)
**Affected:**
- `mcp-streamablehttp-proxy` v0.2.0 (PyPI)
- `mcp-fetch-streamablehttp-server` v0.2.0 (PyPI)
- Likely additional components in the same `atrawog/mcp-oauth-gateway` monorepo — full repo audit recommended by maintainer.
**Embargo:** 2026-08-10 (90 days from filing — aligns with the project's existing SSRF embargo for `mcp-server-fetch` / `mcp-server-http-request`)
**Status:** **draft**

---

## Body of the report (ready to paste)

> ### Summary
>
> Two PyPI-published Python MCP server components in the `atrawog/mcp-oauth-gateway` monorepo expose HTTP MCP endpoints with no in-process Origin or Host validation. When run in their default configuration — which is the documented `pip install` + `console-script` workflow, not the fully-orchestrated Traefik-fronted deployment — they are exploitable from a web browser via DNS rebinding.
>
> - **`mcp-streamablehttp-proxy` v0.2.0** binds to `127.0.0.1` by default and is a universal escalation vector: it proxies an arbitrary stdio MCP server (chosen by the operator at launch time) onto HTTP. A successful DNS-rebind against the proxy gives a remote attacker the full toolset of whatever MCP server is behind it — `mcp-server-shell` → RCE, `mcp-server-aidd` → filesystem-write + exec, etc.
> - **`mcp-fetch-streamablehttp-server` v0.2.0** is worse: it binds to `0.0.0.0` by default (an explicit `# noqa: S104` Bandit-suppression sits next to the bind, acknowledging and dismissing the "binding to all interfaces" warning) and sends `Access-Control-Allow-Origin: *` in responses. It is reachable on every network interface of the host. DNS rebind is one attack path; direct cross-origin access from a same-network browser is another.
>
> ### Root cause
>
> Both packages omit any middleware that inspects the `Origin` or `Host` header against an allowlist, and neither package adds Starlette/FastAPI's `TrustedHostMiddleware`. The codebase delegates this concern to "Traefik middleware" (verbatim, as inline comments — see file references below), but Traefik is an external reverse proxy that is not present in the default `pip install` deployment.
>
> A browser visiting attacker-controlled `https://evil.example` is therefore able, once DNS-rebinding completes, to issue same-origin POST requests against `http://127.0.0.1:3000/mcp` and have them accepted.
>
> ### File references — `mcp-streamablehttp-proxy` v0.2.0
>
> - `mcp_streamablehttp_proxy/server.py:59`
>
>     ```python
>     def run_server(
>         server_command: List[str],
>         host: str = "127.0.0.1",
>         port: int = 3000,
>         ...
>     ):
>         ...
>         uvicorn.run(app, host=host, port=port, log_level=log_level)
>     ```
>
> - `mcp_streamablehttp_proxy/proxy.py:389-395` (`create_app`):
>
>     ```python
>     def create_app(server_command: List[str], session_timeout: int = 300) -> FastAPI:
>         """Create FastAPI app with MCP proxy endpoints."""
>         app = FastAPI()
>
>         # CORS is handled by Traefik middleware - no need to configure here
>         # This ensures CORS headers are set in only one place as required
>     ```
>
>     No `app.add_middleware(...)` call follows. No `TrustedHostMiddleware`. No Origin reading in the handler:
>
> - `mcp_streamablehttp_proxy/proxy.py:419-421` (`handle_mcp`):
>
>     ```python
>     @app.post("/mcp")
>     async def handle_mcp(request: Request):
>         """Handle MCP requests without trailing slash redirect."""
>         # CORS is handled by Traefik middleware - no validation needed here
>     ```
>
> ### File references — `mcp-fetch-streamablehttp-server` v0.2.0
>
> - `mcp_fetch_streamablehttp_server/__main__.py:28-46`
>
>     ```python
>     host = os.getenv("HOST", "0.0.0.0")  # noqa: S104
>     port = int(os.getenv("PORT", "3000"))
>     ...
>     uvicorn.run(
>         app,
>         host=host,
>         port=port,
>         ...
>     )
>     ```
>
> - `mcp_fetch_streamablehttp_server/transport.py:38-46`
>
>     ```python
>     return (
>         200,
>         {
>             "Access-Control-Allow-Origin": "*",
>             "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
>             ...
>         },
>         ...
>     )
>     ```
>
> A repo-wide grep across both packages for `add_middleware`, `Middleware(`, `TrustedHost`, `CORSMiddleware`, `AuthMiddleware` returns zero matches.
>
> ### Impact
>
> **Default deployment is exploitable; documented "production" deployment with Traefik is not.** The disconnect between these two postures is the bug.
>
> - **`mcp-streamablehttp-proxy`**: Operator runs `mcp-streamablehttp-proxy <stdio-mcp-cmd>` on a dev workstation (the README's hello-world). Server binds to `127.0.0.1:3000`. Operator opens any browser tab. Attacker page (any origin) performs DNS rebind, then issues `POST http://attacker-domain:3000/mcp` with an MCP JSON-RPC `tools/call` payload. Proxy invokes the requested tool on the wrapped stdio MCP. If the wrapped server is `mcp-server-shell` (a real PyPI package), the result is unauthenticated remote code execution against the operator's workstation, from any web page the operator visits.
> - **`mcp-fetch-streamablehttp-server`**: Same DNS rebind path. Additionally exposed on the host's external interfaces (`0.0.0.0`). The wrapped tool here is a URL fetcher, so a successful rebind also recursively pulls in the SSRF surface already disclosed against `mcp-server-fetch` ([modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143)) — DNS rebind to reach the server, then drive the fetcher to `http://169.254.169.254/...` if the host is in AWS / GCP / Azure.
>
> ### Reproduction
>
> A full PoC requires a DNS server with TTL-flip behavior under attacker control. I have not yet built the harness — happy to construct one for verification on a maintainer-chosen target if useful. In the meantime, the bug is verifiable from source alone:
>
> 1. `pip install mcp-streamablehttp-proxy==0.2.0` in a clean venv.
> 2. `pip install mcp-server-time` (any stdio MCP server; this one is harmless).
> 3. `mcp-streamablehttp-proxy python -m mcp_server_time` — binds to `127.0.0.1:3000`.
> 4. From the same machine (browser-equivalent, no Origin allowlist enforced):
>
>     ```bash
>     curl -X POST http://127.0.0.1:3000/mcp \
>         -H "Content-Type: application/json" \
>         -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"poc","version":"0"}}}'
>     ```
>
>     The server accepts the request and initializes the session without checking the Origin header. The same request from a browser context with `Origin: https://attacker.example` is accepted identically once DNS rebinding turns `attacker.example` into `127.0.0.1` in the resolver cache.
>
> The fast verification is confirming the absence of Origin checking — the request goes through with **no** Origin header at all, demonstrating the validator isn't there.
>
> ### Suggested remediation
>
> 1. **Add `TrustedHostMiddleware`** at app-creation time in both packages:
>
>     ```python
>     from starlette.middleware.trustedhost import TrustedHostMiddleware
>     app.add_middleware(
>         TrustedHostMiddleware,
>         allowed_hosts=["127.0.0.1", "localhost", f"127.0.0.1:{port}", f"localhost:{port}"],
>     )
>     ```
>
> 2. **Validate the `Origin` header** on the `POST /mcp` handler. For purely local use, the simplest rule is: accept requests where `Origin` is absent (non-browser clients) OR where `Origin` matches a configured allowlist. Reject everything else. This is the standard MCP-spec-compliant defense against DNS rebinding.
>
> 3. **Default `host` to `127.0.0.1`** in `mcp-fetch-streamablehttp-server`, not `0.0.0.0`. The `# noqa: S104` should be removed — Bandit was right. Users who want `0.0.0.0` can opt in explicitly via `HOST=0.0.0.0` env var, and that opt-in should be paired with a startup-time warning recommending an external auth layer.
>
> 4. **Update the inline comments** that delegate Origin/CORS to Traefik. Either:
>     - Remove the comments and add the in-process middleware (option 1), making the default safe.
>     - Or, keep the delegation model but make the package refuse to start in non-Traefik mode unless an explicit `MCP_TRUST_HOST_HEADER=1` env var is set, with a startup banner explaining the threat model.
>
> 5. **For `mcp-fetch-streamablehttp-server`** specifically: inherit the SSRF fix from upstream `mcp-server-fetch` (this is the subject of [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) — the same root cause).
>
> ### Why I'm flagging both at once
>
> Both packages are from the same monorepo, share the same architectural assumption (Traefik fronts everything), and have identical fix shape. Filing as one coordinated disclosure rather than two unrelated ones reduces context-switching and frames the issue as a project-level posture question rather than per-package fingerpointing. I'd also recommend a full repo audit of `atrawog/mcp-oauth-gateway` — if these two share the assumption, other components likely do too.
>
> ### Tooling
>
> Findings produced by [MCP-Scan](https://github.com/desledishant10/mcp-scan), an open-source security scanner for MCP servers I'm building as a capstone. The detection in question is rule [MCP-S-014](https://github.com/desledishant10/mcp-scan/blob/main/docs/static-rules.md#mcp-s-014--http-transport-missing-originhost-validation). Full survey context: [findings/2026-05-12-dns-rebinding-survey.md](https://github.com/desledishant10/mcp-scan/blob/main/findings/2026-05-12-dns-rebinding-survey.md).
>
> ### Embargo
>
> Standard 90 days. Public release 2026-08-10 unless a fix is in active development, in which case happy to extend. The release date aligns with my prior SSRF disclosure embargo so the public writeup can frame both classes together. No exploit code will be published before the embargo expires beyond the source-level analysis already in this report; reproduction artifacts (DNS-rebind harness, browser PoC) are gated on maintainer sign-off.
>
> ### Contact
>
> Dishant Desle — didesle7@gmail.com
>
> Thanks for taking a look.

---

## Suggested submission steps

1. **GitHub Security Advisory** (preferred — structured, private, can request a CVE):
   - Open https://github.com/atrawog/mcp-oauth-gateway/security/advisories/new
   - Title: `DNS-rebinding: mcp-streamablehttp-proxy and mcp-fetch-streamablehttp-server expose HTTP MCP endpoints without Origin/Host validation`
   - Affected products: list both packages with their PyPI versions
   - Body: paste the report above (just the `> `-prefixed content, with `> ` stripped)
   - Request a CVE via the GHSA form (one of the toggles at the bottom)

2. **Heads-up email to atrawog@gmail.com** (so the maintainer notices the advisory promptly):
   - Subject: `Security advisory filed against atrawog/mcp-oauth-gateway (DNS rebinding in 2 PyPI packages, 90-day embargo)`
   - Body: 3-line note pointing at the advisory URL once posted; no technical details in the email (the advisory carries them and is the durable record).

3. **Internal record-keeping** (back here):
   - Update `Status:` from `draft` to `filed` once the advisory is posted.
   - Append an `## Updates` section with the advisory URL and posting timestamp.
   - Cross-link from `findings/2026-05-12-dns-rebinding-survey.md`.

## What happens if maintainer doesn't respond

Standard cadence:
- **Day +14 (2026-05-26):** comment on the advisory thread, polite "any update?"
- **Day +30 (2026-06-11):** if no engagement, send a direct email to `atrawog@gmail.com` referencing the advisory.
- **Day +60 (2026-07-11):** if still silent, notify the broader MCP ecosystem (an issue on `modelcontextprotocol/servers` cross-referencing the package, an MCP Discord/forum heads-up). At this point the existence of the issue is acceptable to disclose; concrete PoC is not.
- **Day +90 (2026-08-10):** public release per embargo, regardless of fix status. Aligns with the SSRF embargo so the blog post covers both classes.

## Why a GitHub Security Advisory rather than a public issue

The atrawog/mcp-oauth-gateway repo has the Security tab enabled (we should verify before filing; if not, fall back to an email). GHSA gives:
- Private channel with the maintainer until the advisory is published.
- Structured CVE-request workflow built in.
- A timeline record that survives if the maintainer ever rewrites issue history.

The earlier SSRF disclosures used public issues + emails because (a) `modelcontextprotocol/servers` is a high-traffic repo where a public issue lands with the right people, and (b) `mcp-server-http-request` had no public issue tracker. Here the right channel is the security tab.

---

## Updates

_(none yet — draft. Append timestamped entries below as the disclosure progresses.)_
