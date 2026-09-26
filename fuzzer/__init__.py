"""mcp-witness fuzzer: an automated dynamic fuzzer for MCP servers.

It captures a server's ``tools/list``, generates capability-aware adversarial
arguments for each tool (SSRF payloads for URL parameters, traversal for path
parameters, injection for command/query parameters, plus type-confusion,
boundary, and protocol malformations), sends them to a locally-run server, and
classifies each response with an oracle that flags crashes, hangs, information
leaks, and real vulnerability signals.

Intended for auditing MCP servers you run yourself, with responsible disclosure
for anything it surfaces. Every finding is a candidate that needs manual
confirmation before it is a vulnerability.
"""

from fuzzer.engine import run_campaign

__all__ = ["run_campaign"]
