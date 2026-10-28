"""Capture an MCP server's tools/list output to JSON.

Used to assemble calibration-corpus entries — connect to any stdio MCP
server, dump every tool definition, then either feed the JSON to
`mcp-witness-classify` (one-shot classification check) or to
`mcp-witness-scaffold-gt` (start a new ground-truth file).
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
    return {"tools": [_serialize_tool(t) for t in result.tools]}


def _serialize_tool(t) -> dict:
    """Serialize one SDK Tool to the captured JSON shape.

    Carries `annotations` through as a sibling of `inputSchema`, matching
    the real tools/list response, so MCP-S-004 can compare a declared
    `readOnlyHint` / `destructiveHint` against the tool's actual behavior.
    Most servers set no annotations, so the key is omitted when absent
    rather than written as an empty object.
    """
    out = {
        "name": t.name,
        "description": t.description or "",
        "inputSchema": t.inputSchema or {"type": "object", "properties": {}},
    }
    ann = _annotations_dict(getattr(t, "annotations", None))
    if ann:
        out["annotations"] = ann
    return out


def _annotations_dict(annotations) -> dict:
    """Best-effort conversion of an SDK ToolAnnotations object to a plain dict,
    dropping None-valued hints. Never raises: a malformed or unexpected
    annotations object must not abort the whole capture, so any failure just
    yields no annotations for that tool."""
    if annotations is None:
        return {}
    try:
        # ToolAnnotations is a pydantic model on the SDK Tool; fall back to
        # dict() for anything that already behaves like a mapping.
        if hasattr(annotations, "model_dump"):
            return annotations.model_dump(exclude_none=True)
        return {k: v for k, v in dict(annotations).items() if v is not None}
    except (TypeError, ValueError):
        return {}


def main() -> int:
    p = argparse.ArgumentParser(prog="mcp-witness-capture")
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
