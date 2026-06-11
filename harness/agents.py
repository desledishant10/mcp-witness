"""Agent drivers — what plays the role of "the agent under test".

A driver receives a user message and a `ProxySession`. It runs an agent
loop using the proxy as its tool-call interface. Two implementations
ship today:

- `StubAgent`: deterministic; useful for verifying proxy plumbing.
  Will never fall for prompt injection by construction, so scenarios
  that test agent susceptibility (D-001, D-004, D-005) appear to
  "pass" against it.
- `AnthropicAgent`: runs a real Claude tool-use loop against the proxy.
  Requires the `anthropic` package and an `ANTHROPIC_API_KEY` env var.

Adding more drivers (OpenAI, local models, etc.) is a v0.3 item.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Protocol, runtime_checkable

from .proxy import ProxySession

log = logging.getLogger(__name__)


@runtime_checkable
class AgentDriver(Protocol):
    """Drives the agent under test for a single user-message exchange."""

    async def send_message(self, user_text: str, proxy: ProxySession) -> None: ...


class StubAgent:
    """Deterministic agent — for plumbing tests, not vulnerability discovery.

    Calls the first available tool with empty arguments once per
    `send_message`, then returns. Will never act on injected
    instructions. Useful for confirming the proxy wires up correctly and
    the trace records calls; not useful for finding real vulnerabilities
    in agent hosts. Use `--agent anthropic` for that.
    """

    async def send_message(self, user_text: str, proxy: ProxySession) -> None:
        tools = await proxy.list_tools_for_agent()
        if not tools:
            return
        try:
            await proxy.call_tool_for_agent(tools[0].name, {})
        except Exception as e:  # noqa: BLE001
            log.debug("stub agent tool call failed (often intended): %s", e)


class AnthropicAgent:
    """Real LLM agent — runs a Claude tool-use loop against the proxy.

    Configurable via environment variables:

    - `ANTHROPIC_API_KEY` (required)
    - `MCPSENTRY_AGENT_MODEL` (default: `claude-opus-4-7`)
    - `MCPSENTRY_AGENT_MAX_ITERATIONS` (default: 10)

    Conversation state persists across `send_message` calls within the
    same scenario, which is what makes the rug-pull scenario
    (MCP-D-004) meaningful: the first user message lets the agent see
    the original tools; the second comes after the mutation.
    """

    def __init__(self, model: str | None = None, max_iterations: int | None = None) -> None:
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "AnthropicAgent requires the 'anthropic' package — install with "
                '`pip install "mcpsentry[anthropic]"` or `pip install anthropic`.'
            ) from e
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("AnthropicAgent requires the ANTHROPIC_API_KEY env var.")
        self._api = anthropic.AsyncAnthropic()
        self.model = model or os.environ.get("MCPSENTRY_AGENT_MODEL", "claude-opus-4-7")
        self.max_iterations = max_iterations or int(
            os.environ.get("MCPSENTRY_AGENT_MAX_ITERATIONS", "10"),
        )
        self.messages: list[dict[str, Any]] = []

    async def send_message(self, user_text: str, proxy: ProxySession) -> None:
        self.messages.append({"role": "user", "content": user_text})
        anthropic_tools = [_tool_to_anthropic_format(t) for t in await proxy.list_tools_for_agent()]

        for _ in range(self.max_iterations):
            response = await self._api.messages.create(
                model=self.model,
                max_tokens=4096,
                messages=self.messages,
                tools=anthropic_tools or None,
            )
            self.messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                return

            tool_results: list[dict[str, Any]] = []
            for block in response.content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                try:
                    text = await proxy.call_tool_for_agent(block.name, block.input or {})
                except Exception as e:  # noqa: BLE001
                    text = f"[tool error: {e}]"
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": text,
                    }
                )
            self.messages.append({"role": "user", "content": tool_results})

        log.warning("AnthropicAgent hit max_iterations=%d without end_turn", self.max_iterations)


def _tool_to_anthropic_format(tool: Any) -> dict[str, Any]:
    schema = tool.inputSchema or {"type": "object", "properties": {}}
    return {
        "name": tool.name,
        "description": tool.description or "",
        "input_schema": schema,
    }
