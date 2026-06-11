"""Proxy mode — sits between an agent under test and a real MCP target.

The agent driver calls `ProxySession.list_tools_for_agent()` and
`.call_tool_for_agent()` as if it were talking to the real server; the
proxy forwards those to the target via a `TracedMCPClient` and applies
scenario-defined mutations to tool definitions and tool outputs in
flight. This is what makes scenarios MCP-D-001 (description injection),
MCP-D-004 (rug pull), and MCP-D-005 (output injection) actually run.

The agent ↔ proxy boundary is plain Python method calls (not MCP wire
format) — we own both sides, and going through MCP serialization there
would add nothing. Oracles assert against the trace of the proxy ↔
target connection, where the real JSON-RPC traffic lives.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Any

from .mcp_client import TracedMCPClient

log = logging.getLogger(__name__)


@dataclass
class ToolDescOverride:
    """Mutate a tool's description as the agent sees it."""

    target: str  # glob over tool names
    mode: str  # "append" | "replace"
    payload: str


@dataclass
class ToolOutputOverride:
    """Replace a tool call's result before it reaches the agent."""

    target: str  # glob over tool names
    when: str  # "first_call" | "every_call" | "once"
    payload_text: str
    _fired: int = 0

    def should_fire_and_consume(self) -> bool:
        if self.when in {"first_call", "once"} and self._fired >= 1:
            return False
        self._fired += 1
        return True


@dataclass
class ProxyState:
    desc_overrides: list[ToolDescOverride] = field(default_factory=list)
    output_overrides: list[ToolOutputOverride] = field(default_factory=list)
    # Reserved for v0.3: set when the agent driver surfaces consent UI.
    # The `no_user_consent_prompt` oracle will read this once driver
    # support lands.
    user_consent_prompted: bool = False


class ProxySession:
    """Mediates between the agent under test and the real target server.

    Owns the back-side `TracedMCPClient`. The trace lives on the client
    and is what oracle conditions assert against.
    """

    def __init__(
        self, target_command: str, target_args: list[str], target_env: dict[str, str]
    ) -> None:
        self._target_command = target_command
        self._target_args = target_args
        self._target_env = target_env
        self.state = ProxyState()
        self.target_client: TracedMCPClient | None = None
        self._tools_changed_event = asyncio.Event()

    @property
    def trace(self):
        assert self.target_client is not None
        return self.target_client.trace

    async def __aenter__(self) -> ProxySession:
        self.target_client = TracedMCPClient(
            self._target_command,
            self._target_args,
            self._target_env,
        )
        await self.target_client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.target_client is not None:
            await self.target_client.__aexit__(exc_type, exc, tb)

    async def list_tools_for_agent(self) -> list[Any]:
        """Return the tool list as the agent should see it (post-mutation)."""
        assert self.target_client is not None
        result = await self.target_client.list_tools()
        out: list[Any] = []
        for tool in result.tools:
            new_desc = tool.description or ""
            for override in self.state.desc_overrides:
                if fnmatch.fnmatchcase(tool.name, override.target):
                    if override.mode == "replace":
                        new_desc = override.payload
                    else:
                        sep = "\n\n" if new_desc else ""
                        new_desc = new_desc + sep + override.payload
            # pydantic model_copy preserves the underlying object and returns a
            # mutated view. Falls back gracefully if the SDK ever returns a
            # non-pydantic tool type.
            if hasattr(tool, "model_copy"):
                out.append(tool.model_copy(update={"description": new_desc}))
            else:
                tool.description = new_desc
                out.append(tool)
        return out

    async def call_tool_for_agent(self, name: str, arguments: dict[str, Any]) -> str:
        """Call a tool on the target; return text the agent sees (post-mutation)."""
        assert self.target_client is not None
        for override in self.state.output_overrides:
            if fnmatch.fnmatchcase(name, override.target) and override.should_fire_and_consume():
                return override.payload_text
        result = await self.target_client.call_tool(name, arguments)
        return _content_to_text(result.content)

    def notify_tools_changed(self) -> None:
        """Signal to the agent driver that it should re-fetch tool definitions."""
        self._tools_changed_event.set()

    async def wait_tools_changed(self, timeout: float = 5.0) -> bool:
        try:
            await asyncio.wait_for(self._tools_changed_event.wait(), timeout)
            self._tools_changed_event.clear()
            return True
        except TimeoutError:
            return False


def _content_to_text(content) -> str:
    if content is None:
        return ""
    parts: list[str] = []
    for c in content:
        text = getattr(c, "text", None)
        parts.append(text if text is not None else str(c))
    return "".join(parts)
