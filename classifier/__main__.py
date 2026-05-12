"""CLI: classify MCP tool definitions provided as JSON.

Reads JSON from stdin or a file. Accepts:
- A list of tool objects.
- A dict with a `tools` field (typical: a `tools/list` response).
- A single tool object.

Output is the classification result as pretty-printed JSON on stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .classify import classify_server, classify_tool


def main() -> int:
    p = argparse.ArgumentParser(prog="mcp-scan-classify")
    p.add_argument("input", type=Path, nargs="?", default=None,
                   help="Path to JSON file; reads stdin if omitted.")
    args = p.parse_args()

    raw = args.input.read_text() if args.input else sys.stdin.read()
    data = json.loads(raw)

    if isinstance(data, list):
        result = classify_server(data)
    elif isinstance(data, dict) and "tools" in data:
        result = classify_server(data["tools"])
    elif isinstance(data, dict):
        result = classify_tool(data)
    else:
        sys.stderr.write("Input must be a tool dict, a list of tools, or {\"tools\": [...]}\n")
        return 2

    json.dump(asdict(result), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
