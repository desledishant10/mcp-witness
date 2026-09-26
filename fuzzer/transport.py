"""Live MCP transport for the fuzzer.

Bridges the async ``TracedMCPClient`` (stdio JSON-RPC) to the synchronous
engine by running an asyncio loop in a background thread and submitting each
call to it. ``fetch_tools`` lists a server's tools without sending any payload
(used by --dry-run); ``run_live`` runs a full campaign.

A per-call timeout maps to a ``hang`` outcome; a transport failure (the server
process dying) maps to ``crash``. After a crash the session is dead, so the
campaign winds down rather than hammering a dead process; restart-on-crash is
a future improvement.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import TimeoutError as FutureTimeout

from fuzzer.engine import run_campaign
from fuzzer.models import CallResult, Campaign, FuzzFinding
from harness.mcp_client import TracedMCPClient


def _flatten(result) -> tuple[str, bool]:
    """Flatten an MCP CallToolResult into (text, is_error)."""
    data = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
    is_error = bool(data.get("isError"))
    parts: list[str] = []
    for block in data.get("content") or []:
        if isinstance(block, dict):
            parts.append(block.get("text") or block.get("data") or "")
        else:
            parts.append(str(block))
    return ("\n".join(p for p in parts if p), is_error)


def _tool_to_dict(tool) -> dict:
    if hasattr(tool, "model_dump"):
        return tool.model_dump(mode="json")
    return dict(tool)


class _LoopThread:
    """An asyncio event loop running in a daemon thread."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._thread.start()

    def submit(self, coro, timeout: float):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)


class TransportError(RuntimeError):
    """The server could not be launched or spoke the protocol incorrectly."""


def _with_client(server_cmd: list[str], fn: Callable[[TracedMCPClient, _LoopThread], object]):
    command, args = server_cmd[0], server_cmd[1:]
    lt = _LoopThread()
    client = TracedMCPClient(command, args)
    entered = False
    try:
        try:
            lt.submit(client.__aenter__(), timeout=30)
            entered = True
        except Exception as exc:  # noqa: BLE001 - surface a clean transport error
            raise TransportError(f"could not start or initialize the server: {exc}") from exc
        return fn(client, lt)
    finally:
        if entered:
            try:
                lt.submit(client.__aexit__(None, None, None), timeout=10)
            except Exception:
                pass
        lt.close()


def fetch_tools(server_cmd: list[str]) -> list[dict]:
    """Connect, list tools, disconnect. Sends no fuzz payloads."""
    return _with_client(
        server_cmd,
        lambda client, lt: [_tool_to_dict(t) for t in lt.submit(client.list_tools(), 30).tools],
    )


def run_live(
    server_cmd: list[str],
    *,
    max_per_tool: int = 48,
    per_call_timeout: float = 10.0,
    on_finding: Callable[[FuzzFinding], None] | None = None,
) -> Campaign:
    def _campaign(client: TracedMCPClient, lt: _LoopThread) -> Campaign:
        tools = [_tool_to_dict(t) for t in lt.submit(client.list_tools(), 30).tools]

        def call_fn(name: str, arguments: dict) -> CallResult:
            try:
                result = lt.submit(client.call_tool(name, arguments), per_call_timeout)
            except FutureTimeout:
                return CallResult(timed_out=True)
            except Exception as exc:  # noqa: BLE001 - a transport failure is a signal, not a bug here
                return CallResult(text=str(exc), crashed=True)
            text, is_error = _flatten(result)
            return CallResult(text=text, is_error=is_error)

        return run_campaign(
            " ".join(server_cmd), tools, call_fn, max_per_tool=max_per_tool, on_finding=on_finding
        )

    return _with_client(server_cmd, _campaign)
