"""Capture an MCP server's tools/list output to JSON.

Used to assemble calibration-corpus entries — connect to any stdio MCP
server, dump every tool definition, then either feed the JSON to
`mcpsentry-classify` (one-shot classification check) or to
`mcpsentry-scaffold-gt` (start a new ground-truth file).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .mcp_client import TracedMCPClient
from .runner import Target


async def capture(target: Target) -> dict:
    async with TracedMCPClient(target.command, target.args, target.env) as client:
        result = await client.list_tools()
    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.inputSchema or {"type": "object", "properties": {}},
            }
            for t in result.tools
        ]
    }


def main() -> int:
    p = argparse.ArgumentParser(prog="mcpsentry-capture")
    p.add_argument(
        "--server-cmd", required=True, help="Command to launch the MCP server (stdio transport)."
    )
    p.add_argument(
        "--server-arg",
        action="append",
        default=[],
        help="Argument to pass to the server command (repeatable).",
    )
    p.add_argument("--output", "-o", type=Path, help="Output file. Default: stdout.")
    args = p.parse_args()

    target = Target(command=args.server_cmd, args=args.server_arg)
    data = asyncio.run(capture(target))
    text = json.dumps(data, indent=2)
    if args.output:
        args.output.write_text(text + "\n")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
