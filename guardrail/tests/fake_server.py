"""A minimal stdio JSON-RPC server for guardrail integration tests.

It answers tool calls. If a fetch ever reaches it for the IMDS address, it
returns a body containing ``LEAKED-CREDENTIALS`` so a test can assert the
guardrail stopped the call from ever arriving here. Not an MCP server; just
enough of the shape to drive the proxy.
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    for raw in sys.stdin.buffer:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        mid = message.get("id")
        if message.get("method") == "tools/call":
            args = (message.get("params") or {}).get("arguments") or {}
            url = args.get("url", "")
            body = "LEAKED-CREDENTIALS" if "169.254.169.254" in url else f"fetched {url}"
            response = {
                "jsonrpc": "2.0",
                "id": mid,
                "result": {"content": [{"type": "text", "text": body}]},
            }
        else:
            response = {"jsonrpc": "2.0", "id": mid, "result": {"ok": True}}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
