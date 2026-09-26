"""mcp-witness guardrail: a runtime MCP interceptor that enforces, live, the
same policy the detections in ``detections/`` catch after the fact.

It sits between an MCP client (the agent host) and an MCP server, inspects the
JSON-RPC traffic, and stops the disclosed attacks before they land:

* an SSRF tool call whose URL resolves to a reserved address (IMDS / RFC1918)
  is refused before the server ever fetches it;
* a tool whose definition changed since it was first seen (a tools/list "rug
  pull") is flagged, and calls to it are refused.

Every decision is emitted as a structured event compatible with the detections
event schema, so blocking at runtime and detecting in the SIEM share one shape.
"""

from guardrail.http_origin import (
    OriginGuardASGI,
    OriginGuardWSGI,
    OriginHostPolicy,
    aiohttp_origin_guard,
)
from guardrail.policy import Decision, GuardrailPolicy

__all__ = [
    "Decision",
    "GuardrailPolicy",
    "OriginHostPolicy",
    "OriginGuardASGI",
    "OriginGuardWSGI",
    "aiohttp_origin_guard",
]
