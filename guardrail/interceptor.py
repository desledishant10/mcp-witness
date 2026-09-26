"""Pure JSON-RPC interception, independent of transport.

``intercept_client_request`` inspects a message travelling client -> server and
either forwards it or short-circuits it with a JSON-RPC error back to the
client. ``intercept_server_response`` inspects a message travelling
server -> client and records tool-definition changes. Both are pure functions
of the policy state and the message, so the proxy is a thin I/O shell over
them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from guardrail.policy import Decision, GuardrailPolicy

# JSON-RPC application error code for a guardrail block.
GUARDRAIL_BLOCKED = -32001


@dataclass
class Interception:
    forward: dict | None  # message to pass through (None means drop it)
    reply: dict | None = None  # message to send back to the origin instead
    decisions: list[Decision] = field(default_factory=list)


def _error_reply(request_id, decision: Decision) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": GUARDRAIL_BLOCKED,
            "message": f"blocked by mcp-witness guardrail: {decision.reason}",
            "data": {"rule": decision.rule},
        },
    }


def intercept_client_request(policy: GuardrailPolicy, message: dict) -> Interception:
    if message.get("method") == "tools/call":
        params = message.get("params") or {}
        decision = policy.check_tool_call(params.get("name"), params.get("arguments"))
        if decision.blocked:
            return Interception(
                forward=None,
                reply=_error_reply(message.get("id"), decision),
                decisions=[decision],
            )
        if decision.action == "flag":
            return Interception(forward=message, decisions=[decision])
    return Interception(forward=message)


def intercept_server_response(policy: GuardrailPolicy, message: dict) -> Interception:
    result = message.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        decisions = policy.observe_tools(result["tools"])
        return Interception(forward=message, decisions=decisions)
    return Interception(forward=message)
