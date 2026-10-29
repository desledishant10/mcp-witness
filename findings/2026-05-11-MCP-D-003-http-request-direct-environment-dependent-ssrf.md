# MCP-D-003 vs mcp-server-http-request — environment-dependent SSRF (second instance)

**Date:** 2026-05-11
**Target:** `mcp-server-http-request` v0.1.0 (PyPI; community-published)
**Tested by:** [scenarios/MCP-D-003-ssrf-url-fetcher.yaml](../scenarios/MCP-D-003-ssrf-url-fetcher.yaml) + a targeted follow-up probe
**Agent driver:** n/a (direct mode — harness as MCP client)
**Outcome:** **VULNERABILITY (disclosure email-filed 2026-05-12)** — same class as the [mcp-server-fetch finding](2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md), which was demonstrated on EC2 the same day. Coordinated disclosure sent direct to maintainers (`esteban@statespace.com`, `gavin@statespace.com`) since no public issue tracker is listed on PyPI. Embargo: 2026-08-10. **Update: maintainer-confirmed unmaintained (2026-06-11); package removed from PyPI and no longer installable as of 2026-10-28 (JSON API + pip simple index both 404; was live at 0.1.0 on 2026-09-10; removal mechanism unconfirmed, HTML page bot-walled).**

## Result

`mcp-server-http-request` exposes the same environment-dependent SSRF surface as `mcp-server-fetch`, but through a **different mechanism** and from a **different vendor** (community PyPI package, not Anthropic's official reference). This is the project's second confirmed instance of the same vulnerability class — strong signal that the lack of default SSRF protection is a *class-wide pattern* across the Python MCP HTTP-client ecosystem, not a single-package bug.

## Reproduction

```bash
pip install mcp-server-http-request
mcp-scan-capture --server-cmd mcp-server-http-request -o /tmp/http-request.json
mcp-scan-classify /tmp/http-request.json    # → 5 net_egress tools at high confidence
mcp-scan-test scenarios/MCP-D-003-ssrf-url-fetcher.yaml \
    --server-cmd mcp-server-http-request
```

Targeted probe (faster than full D-003):

```python
async with TracedMCPClient("mcp-server-http-request") as cli:
    for url in [canary_url, "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"]:
        r = await cli.call_tool("http_get", {"url": url})
```

## What's different from the fetch finding

| Aspect | mcp-server-fetch | mcp-server-http-request |
|---|---|---|
| Vendor | Anthropic (reference impl) | Community / third-party PyPI |
| HTTP client | `httpx<0.28` | `httpx<0.28` |
| Incidental defense on dev | robots.txt fetch fails on TCP-unreachable hosts → blocks main fetch | none — fails open immediately |
| Defense against `file://` | robots.txt check fails → blocks | httpx's built-in scheme rejection → blocks |
| Defense against IMDS on dev | robots.txt-first delays then errors | request itself times out |
| Defense against IMDS on cloud | **fails open** — robots.txt 404 → fetch proceeds | **fails open** — direct request returns metadata |

So fetch has an *accidental* defense that breaks on cloud; http-request has *no* defense even on dev (except httpx's scheme allowlist).

The end-state vulnerability is the same: agent prompt-injected → calls `http_get("http://169.254.169.254/...")` → metadata + credentials returned.

## Per-payload observations

```
GET http://127.0.0.1:<port>/<token>/probe (canary)
  → Status 204; canary recorded the hit ✓
  → User-Agent: "ModelContextProtocol/1.0 (HTTP-Request; ..."

GET http://169.254.169.254/latest/meta-data/
  → TIMEOUT (>8s) on dev machine.
  → On EC2: would return metadata immediately.

GET file:///etc/passwd
  → UnsupportedProtocol("Request URL is missing an 'http://' or 'https://' protocol.")
  → This is httpx rejecting non-http schemes, NOT mcp-server-http-request.
```

## Why this is more concerning than the single fetch finding

1. **It's a class-wide pattern, not a one-server bug.** Two Python MCP HTTP-client servers, two vendors, same root cause: no scheme allowlist for non-file schemes (gopher/dict could still be added if httpx is replaced), no host denylist for link-local / RFC 1918 / loopback, no metadata-service-aware blocking.

2. **http-request has FIVE tools** (`http_get`, `http_post`, `http_put`, `http_patch`, `http_delete`), all with the same surface. fetch has one. Attacker has more methods to choose from for whatever IMDS endpoint requires a specific verb.

3. **No accidental defense at all** on http-request — even the robots.txt circumstance that protects fetch on dev machines is absent here. On any environment where metadata services are reachable, no protection.

4. **The User-Agent string `"ModelContextProtocol/1.0 (HTTP-Request; ..."` is a fingerprint** — any service receiving requests from this package can identify it. Low severity, but worth noting; a defender monitoring inbound IMDS requests would see this UA and know the source.

## EC2 verification status

Direct EC2 demonstration was performed for `mcp-server-fetch` ([finding](2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md#reproduction-on-ec2-2026-05-12)) and successfully retrieved IAM credentials. `mcp-server-http-request` was not separately demonstrated on EC2 — both packages share the underlying root cause (no scheme allowlist, no host denylist, both depend on httpx), so the same outcome applies. Direct verification on http-request is a 5-minute add-on to the same EC2 instance if needed for the disclosure.

## Suggested follow-up

1. **Reproduce on EC2** — single ~$0.50 t3.micro, two pip installs, two `mcp-scan-test` runs. Same instance can verify both fetch and http-request in one go.
2. **Coordinated disclosure** — file an issue against http-request's GitHub (the PyPI page should link it) referencing the same root cause as fetch. Cross-reference the fetch issue when it's filed.
3. **Refine D-003 oracle** as previously noted — require `all_of: [canary_hit, trace_contains:<metadata-pattern>]` to avoid false positives on benign fetch tools. Today's oracle fires `canary_hit` on any HTTP fetch, which is correct only in conjunction with the manual trace interpretation done here.
4. **Author a new D-007** specifically targeting cloud-metadata-service URLs (no canary, just the sensitive-pattern oracle). Would more cleanly distinguish "tool egress (expected)" from "tool egress to dangerous targets (vulnerability)."

## Disclosure

Warrants coordinated disclosure to the `mcp-server-http-request` maintainer alongside the fetch finding. The shared root cause makes a single advisory covering both packages more impactful than two separate disclosures. Suggested wording:

> Two PyPI-published Python MCP servers, `mcp-server-fetch` (Anthropic reference) and `mcp-server-http-request` (community), lack explicit SSRF protection. Neither has a scheme allowlist (beyond httpx defaults) or host denylist for link-local, loopback, or cloud metadata addresses. On cloud-hosted agent hosts, this enables credential exfiltration via prompt injection that coerces the agent into calling the HTTP-fetch tool with a metadata URL. The class-wide nature (two independent implementations, same flaw) suggests the MCP server ecosystem needs guidance — possibly a documented best-practice or a shared `mcp-net-safety` utility package — to make secure-by-default the norm.
