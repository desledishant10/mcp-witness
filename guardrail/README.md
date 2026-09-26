# guardrail

A runtime MCP guardrail proxy. It enforces, live, the same policy the
[detections](../detections/) catch after the fact: detect and prevent from one
set of rules.

The guardrail sits between an MCP client (the agent host) and a stdio MCP
server, inspects the JSON-RPC traffic, and stops the disclosed attacks before
they land:

- **SSRF egress block.** A `tools/call` whose URL argument resolves to a
  reserved address (link-local IMDS, RFC1918, loopback) is refused with a
  JSON-RPC error before it reaches the server, so the credential fetch never
  happens. Hostnames are resolved first, which catches `metadata.google.internal`
  and any attacker domain pointed at the metadata IP.
- **Tool "rug pull" detection.** The guardrail pins each tool definition the
  first time it sees it in a `tools/list`. If a later `tools/list` changes a
  tool's definition, that tool is flagged and subsequent calls to it are
  refused. This is the `MCP-D-004` mutate-after-approval vector.

Every decision is emitted as a structured event compatible with the detections
event schema, so a runtime block and a SIEM detection describe the same thing.

## Use it

```bash
# Guard the reference fetch server: a coerced IMDS fetch is refused in-line.
mcp-witness-guardrail --mode block -- python -m mcp_server_fetch

# Watch without blocking (flag decisions to stderr, still forward).
mcp-witness-guardrail --mode monitor -- <server command>

# Exempt an internal host you legitimately fetch.
mcp-witness-guardrail --allow-host 10.0.0.5 -- <server command>
```

Point your MCP client at `mcp-witness-guardrail -- <server command>` instead of
`<server command>`. Decisions are logged as JSON lines on stderr.

## How it is built

```
netcheck.py      reserved-IP classification + hostname resolution
policy.py        GuardrailPolicy: SSRF check, rug-pull pin/compare, Decision
interceptor.py   pure client-request / server-response interception
proxy.py         stdio transport (pump_* functions + StdioGuardrailProxy)
cli.py           mcp-witness-guardrail entry point
```

The policy and interceptor are pure and hold no I/O, so the whole decision path
is unit-tested; the `pump_*` functions are tested over byte-line iterators; and
an end-to-end test runs the proxy in front of a real server subprocess and
confirms an SSRF call is blocked before the server can leak.

```bash
make test        # the module's pytest suite
make demo        # block an SSRF call through the proxy, no external server
```

## Scope and honesty

This is defense in depth, not a substitute for fixing the server. It reduces the
blast radius of a URL-fetching tool and catches tool mutation, but an operator
should still run a patched server and set IMDSv2 to Required. v1 covers the
stdio transport; the inbound HTTP-transport Origin/Host enforcement (the other
half of the DNS-rebind class) is a natural next addition and is already covered
on the detection side by the Suricata and Sigma rules in `../detections/`.
