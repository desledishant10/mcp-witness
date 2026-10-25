# Moved: this writeup is now published

**"MCP servers and the transport-layer blind spot: six Python packages, two vulnerability classes, one ecosystem norm"** has moved to its published home:

- Published page: <https://desledishant10.github.io/mcp-witness/docs/mcp-transport-layer-blind-spot>
- Source in this repo: [`docs/mcp-transport-layer-blind-spot.md`](../docs/mcp-transport-layer-blind-spot.md)

This is the cross-cutting synthesis of the two per-class writeups:

- [SSRF in `mcp-server-fetch`](../docs/ssrf-mcp-server-fetch.md) (outbound)
- [DNS rebinding across HTTP-transport servers](../docs/dns-rebinding-http-mcp-servers.md) (inbound)

The disclosure record for all six packages lives at [`disclosures/`](../disclosures); the reproduction harnesses are at [`poc/ssrf/`](../poc/ssrf) and [`poc/dns-rebind/`](../poc/dns-rebind).
