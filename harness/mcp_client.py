"""MCP client wrapper with JSON-RPC trace recording.

v0.1 scope: stdio transport, direct black-box client (Mode 1 — no agent
under test, no proxying). Trace is captured at the session-call boundary
— each tools/call etc. is logged with its request and response payloads.

Stream-level interception for proxy mode (required by scenarios MCP-D-001,
D-004, D-005) is a v0.2 deliverable and lives in a separate module.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass
class TraceFrame:
    ts: float
    direction: str  # "out" (client→server) or "in" (server→client)
    method: str  # JSON-RPC method, e.g. "tools/call"
    payload: dict[str, Any]


@dataclass
class Trace:
    frames: list[TraceFrame] = field(default_factory=list)

    def record(self, direction: str, method: str, payload: dict[str, Any]) -> None:
        self.frames.append(TraceFrame(time.time(), direction, method, payload))

    def matches(self, pattern: str, where: str = "any") -> int:
        """Count frames whose JSON-serialized payload matches a regex."""
        import json
        import re

        rx = re.compile(pattern)
        n = 0
        for f in self.frames:
            if where != "any" and f.direction != ("out" if where == "request" else "in"):
                continue
            if rx.search(json.dumps(f.payload, default=str)):
                n += 1
        return n


class TracedMCPClient:
    """Direct MCP client over stdio with session-level trace recording.

    Methods are added as scenarios need them. v0.1 ships list_tools and
    call_tool — enough for MCP-D-002 (path traversal) and MCP-D-003 (SSRF).
    """

    def __init__(
        self, command: str, args: list[str] | None = None, env: dict[str, str] | None = None
    ) -> None:
        self.params = StdioServerParameters(command=command, args=args or [], env=env)
        self.trace = Trace()
        self._session: ClientSession | None = None
        self._stdio_cm = None
        self._session_cm = None

    async def __aenter__(self) -> TracedMCPClient:
        self._stdio_cm = stdio_client(self.params)
        read, write = await self._stdio_cm.__aenter__()
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session_cm:
            await self._session_cm.__aexit__(*exc)
        if self._stdio_cm:
            await self._stdio_cm.__aexit__(*exc)

    async def list_tools(self):
        assert self._session is not None
        self.trace.record("out", "tools/list", {})
        result = await self._session.list_tools()
        self.trace.record("in", "tools/list", _dump(result))
        return result

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        assert self._session is not None
        self.trace.record("out", "tools/call", {"name": name, "arguments": arguments})
        result = await self._session.call_tool(name, arguments)
        self.trace.record("in", "tools/call", _dump(result))
        return result


def _dump(obj: Any) -> dict[str, Any]:
    """Best-effort coerce a pydantic / JSON-RPC object to a plain dict."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, dict):
        return obj
    return {"repr": repr(obj)}
