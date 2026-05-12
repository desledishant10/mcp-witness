# MCP-S-014 vs mcp-fetch-streamablehttp-server — DNS-rebinding + all-interfaces bind + recursive SSRF

**Date:** 2026-05-12
**Target:** `mcp-fetch-streamablehttp-server` v0.2.0 (PyPI; [atrawog/mcp-oauth-gateway](https://github.com/atrawog/mcp-oauth-gateway/tree/main/mcp-fetch-streamablehttp-server))
**Tested by:** MCP-S-014 (static; W2 keyword-suppression false-negative — rule was silenced by the wildcard CORS *response* header) + manual source review
**Agent driver:** n/a (transport-layer finding, agent-independent)
**Outcome:** **VULNERABILITY (source-confirmed)** — composes DNS-rebinding with all-interfaces bind and inherits the SSRF surface from upstream `mcp-server-fetch`. Three-way compounding. Coordinated disclosure drafted at [disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md](../disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md). Embargo target: 2026-08-10.

## Result

`mcp-fetch-streamablehttp-server` is a Streamable HTTP transport variant of `mcp-server-fetch`. In its default configuration it:

1. Binds to **`0.0.0.0`** — every network interface, not just loopback. The bind site is annotated with `# noqa: S104`, an explicit Bandit suppression of the "binding to all interfaces" warning.
2. Has **no Origin/Host validation middleware** anywhere in the package. Same architectural delegation to Traefik as the sibling `mcp-streamablehttp-proxy`, but the standalone deploy has no Traefik.
3. Sends **`Access-Control-Allow-Origin: *`** as a response header on its endpoints, which combined with the absence of authentication means any browser context (same-origin via DNS rebind, or cross-origin via wildcard CORS) can drive the server.
4. Wraps an HTTP fetch tool, so a successful rebind also pulls in the SSRF surface that is the subject of [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) (`mcp-server-fetch` upstream, same maintainer/repo family).

Net effect: an attacker page can, from anywhere on the operator's network, drive the server to fetch arbitrary URLs — including cloud-metadata endpoints on the operator's host, link-local addresses, and internal HTTP services.

## Source-level evidence

### `0.0.0.0` default, Bandit-suppressed

`mcp_fetch_streamablehttp_server/__main__.py` lines 28–46:

```python
# Get host and port from environment
host = os.getenv("HOST", "0.0.0.0")  # noqa: S104
port = int(os.getenv("PORT", "3000"))

# Log startup info
logger.info(f"Starting {settings.server_name} v{settings.server_version}")
logger.info(f"MCP Protocol: {settings.protocol_version}")
logger.info(f"Listening on {host}:{port}")

# Run with uvicorn
uvicorn.run(
    app,
    host=host,
    port=port,
    log_level="info",
    access_log=True,
    use_colors=True,
    lifespan="on",
)
```

`# noqa: S104` is the Bandit suppression code specifically for "binding to all interfaces." The suppression makes the choice deliberate; the comment provides no justification.

### Wildcard CORS in responses

`mcp_fetch_streamablehttp_server/transport.py` lines 38–46:

```python
return (
    200,
    {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": ("Content-Type, Mcp-Session-Id, MCP-Protocol-Version"),
        "Access-Control-Max-Age": "86400",
    },
    ...
)
```

Wildcard `Access-Control-Allow-Origin` is the canonical "any origin can read this" CORS posture. Combined with no credential check, it means any browser-originated cross-origin request is accepted at the application layer. (Browsers prevent wildcard + `credentials: 'include'`, but the package doesn't issue cookies — and the rebind path doesn't need cross-origin because DNS rebinding makes the request *same*-origin.)

### No defensive middleware

Repo-wide grep across the package for `add_middleware`, `Middleware(`, `TrustedHost`, `CORSMiddleware`, `AuthMiddleware` returns zero matches. The wildcard CORS headers are emitted by the response constructor in `transport.py` — there is no policy layer that could be turned off via configuration.

## Reproduction (source-level; full PoC harness pending)

Verifiable on a single host without a DNS server, since `0.0.0.0` makes the server reachable directly:

```bash
pip install mcp-fetch-streamablehttp-server==0.2.0
python -m mcp_fetch_streamablehttp_server &       # binds 0.0.0.0:3000

# From any host on the same network — no Origin allowlist:
curl -X POST http://<victim-ip>:3000/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
         "params":{"protocolVersion":"2025-06-18","capabilities":{},
                    "clientInfo":{"name":"poc","version":"0"}}}'
```

Expected: 200 OK with `Access-Control-Allow-Origin: *` in the response headers. From there, a `tools/call` request driving the fetch tool against `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>/` reproduces the SSRF behavior already disclosed against upstream `mcp-server-fetch` ([modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143)) — the wrapped fetch code path is the same.

The DNS-rebind path is the *additional* attack surface on top of the direct cross-network exposure — described in detail in the sibling finding [findings/2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md](2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md).

## Impact

**Severity: High to Critical**, depending on deployment:

- **Cloud-hosted deployment (EC2, GCE, Azure VM, container running on a cloud host)**: an attacker on the same VPC, or via DNS rebind from anywhere, drives the fetch tool to `http://169.254.169.254/...` and exfiltrates IAM credentials. This is the [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) SSRF, except now reachable from a browser context — the previously-disclosed SSRF required prompt injection of a co-resident agent; here, no agent is in the loop at all.
- **Dev workstation behind a corporate network**: an attacker on the same LAN (coffee shop wifi, conference network) reaches the open `0.0.0.0:3000` directly. The fetch tool then targets internal services (`http://gitlab.internal/`, `http://kubernetes.default/`, link-local addresses).
- **Localhost-only thanks to a host firewall**: still exploitable via DNS rebind from any browser tab the operator opens.

The recursive SSRF is the unusual property of this finding — most DNS-rebind vulnerabilities compromise the rebound service itself. Here, the rebound service is *also* a server-side fetch primitive, so the attack reaches both the local service surface (RCE-shaped — drive the fetch against internal endpoints) and the cloud metadata surface (credentials-exfil-shaped).

## Interpretation

**This is the most severe of the three findings in the DNS-rebind survey.** The combination of:

1. `0.0.0.0` bind (network-reachable, not just rebindable)
2. Wildcard CORS responses (cross-origin browser access)
3. Recursive SSRF reach via the wrapped fetch tool (escalation to cloud metadata)

…makes it materially worse than the `mcp-streamablehttp-proxy` finding, which is "only" universal-escalation-against-127.0.0.1.

The `# noqa: S104` suppression is also worth flagging in disclosure: it indicates the maintainer was warned about the all-interfaces bind by automated tooling and chose to suppress the warning. A small "in plain English" startup banner explaining the trade-off would have prevented this entire class.

## Mitigations

Same shape as the sibling proxy finding plus one extra:

1. **Default `host` to `127.0.0.1`**, not `0.0.0.0`. Remove the `# noqa: S104`. Bandit was right.
2. **Add `TrustedHostMiddleware`** to the FastAPI / Starlette app at construction time (see sibling finding §"Mitigations" for the snippet).
3. **Validate the `Origin` header** on `/mcp` POST.
4. **Stop emitting wildcard `Access-Control-Allow-Origin: *`**. Either remove the CORS response headers entirely (let middleware handle it), or echo the request `Origin` only if it matches an allowlist.
5. **Inherit the SSRF fix from upstream `mcp-server-fetch`** when that fix lands per [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143). Same scheme allowlist + RFC-reserved-range host denylist.

For operators who can't wait for a patched release: set `HOST=127.0.0.1` env var (mitigates the cross-network reach but leaves DNS-rebind exposure on the local loopback), and front the server with a reverse proxy that enforces Origin allowlist.

## Caveats

- **`# noqa: S104` is a tell.** The maintainer is aware that 0.0.0.0 is a flagged pattern. Disclosure tone should reflect that this isn't an accidental oversight; it's an intentional choice with an unmodeled threat. Recommendation: keep the disclosure technically focused, propose the env-var-opt-in pattern as a way to honor both the "we want 0.0.0.0 for production" and "we want safe defaults for `pip install`" use cases.
- **Recursive SSRF is the unusual property.** Standard DNS-rebind reach + standard fetch SSRF would normally be two separate disclosures. Here they compose, and the writeup should make the composition explicit so the severity calibration is unambiguous.

## Suggested follow-up

1. **Include this finding in the same GitHub Security Advisory** as the sibling `mcp-streamablehttp-proxy` finding. Single advisory, two affected packages, one CVE request (or two — let the GHSA workflow decide).
2. **DNS-rebind PoC harness** (see sibling finding §"Suggested follow-up").
3. **Cloud reproduction.** Repeat the EC2 demo from the upstream SSRF finding ([docs/audit-runbook-ec2-ssrf-verification.md](../docs/audit-runbook-ec2-ssrf-verification.md)) against this package — substitute `python -m mcp_fetch_streamablehttp_server` for the stdio fetch server, drive it via the HTTP `/mcp` endpoint rather than stdio JSON-RPC. Should reproduce the credential exfil with the same redacted-IMDS-output trace.
4. **Patch S-014 W2** in MCP-Scan v0.3 — currently the rule's keyword-suppression is silenced by *any* "origin" mention, including the `Access-Control-Allow-Origin: *` *response* header (which is itself a vulnerability indicator, not a defense). After W2 is patched, this finding would have fired automatically rather than via manual review.

## Disclosure

Co-disclosed with the sibling `mcp-streamablehttp-proxy` finding in a single coordinated advisory — both packages are in the same `atrawog/mcp-oauth-gateway` monorepo, share the same architectural assumption, and have the same fix shape. Filing as one advisory rather than two reduces context-switching for the maintainer and frames the disclosure as a project-level posture question.

Full disclosure body and submission steps: [disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md](../disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md). Status: draft. Embargo target: 2026-08-10.
