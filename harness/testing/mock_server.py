"""Minimal mock MCP server for testing the harness end-to-end.

Launches as a subprocess (`python -m harness.testing.mock_server`) and
reads its tool config from the JSON file pointed to by the env var
`MCPSCAN_MOCK_CONFIG`. Each tool has a `behavior` that controls how
`tools/call` responds:

- `echo`                    Returns the call arguments as a JSON string.
- `vulnerable_file_read`    Reads the file at the `path` argument with NO
                            validation — the canonical path-traversal sink.
- `vulnerable_http_fetch`   Performs an HTTP GET to the `url` argument
                            with NO scheme or host validation — the
                            canonical SSRF sink.
- `fixed:<text>`            Returns the literal text after the colon.

Example config (consumed by tests, not shipped):

    {"tools": [
        {"name": "read_file",
         "description": "Reads a file at the given path.",
         "input_schema": {"type": "object",
                          "properties": {"path": {"type": "string"}}},
         "behavior": "vulnerable_file_read"}
    ]}

NB: SDK imports may shift across `mcp` versions. If they break, the
necessary adjustments are usually one-line changes to the import block.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import aiohttp
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server


def _load_config() -> dict[str, Any]:
    path = os.environ.get("MCPSCAN_MOCK_CONFIG")
    if not path:
        return {"tools": []}
    return json.loads(Path(path).read_text())


async def _execute_behavior(behavior: str, args: dict[str, Any]) -> str:
    if behavior == "echo":
        return json.dumps(args)
    if behavior == "vulnerable_file_read":
        return Path(args.get("path", "")).read_text()
    if behavior == "vulnerable_http_fetch":
        url = args.get("url", "")
        timeout = aiohttp.ClientTimeout(total=5.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                return await resp.text()
    if behavior.startswith("fixed:"):
        return behavior[len("fixed:"):]
    raise ValueError(f"unknown mock behavior: {behavior!r}")


async def main() -> None:
    config = _load_config()
    srv: Server = Server("mcp-scan-mock")

    @srv.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=t["name"],
                description=t.get("description", ""),
                inputSchema=t.get(
                    "input_schema",
                    {"type": "object", "properties": {}},
                ),
            )
            for t in config.get("tools", [])
        ]

    @srv.call_tool()
    async def handle_call_tool(name: str, arguments: dict[str, Any]):
        tool_cfg = next((t for t in config.get("tools", []) if t["name"] == name), None)
        if tool_cfg is None:
            return [types.TextContent(type="text", text=f"unknown tool: {name}")]
        behavior = tool_cfg.get("behavior", "echo")
        try:
            text = await _execute_behavior(behavior, arguments or {})
        except Exception as e:                          # noqa: BLE001
            text = f"behavior error: {type(e).__name__}: {e}"
        return [types.TextContent(type="text", text=text)]

    init_options = InitializationOptions(
        server_name="mcp-scan-mock",
        server_version="0.1.0",
        capabilities=srv.get_capabilities(
            notification_options=NotificationOptions(),
            experimental_capabilities={},
        ),
    )
    async with stdio_server() as (read, write):
        await srv.run(read, write, init_options)


if __name__ == "__main__":
    asyncio.run(main())
