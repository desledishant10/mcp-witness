"""A no-network demo of the fuzzer against an in-process vulnerable server.

Shows the engine finding path traversal, SSRF, and command injection while
leaving a well-behaved tool alone.

    python -m fuzzer.demo
"""

from __future__ import annotations

from fuzzer.engine import run_campaign
from fuzzer.models import CallResult
from fuzzer.report import format_report


def _schema(param: str) -> dict:
    return {"type": "object", "properties": {param: {"type": "string"}}, "required": [param]}


TOOLS = [
    {"name": "read_file", "description": "Read a file", "inputSchema": _schema("path")},
    {"name": "fetch", "description": "Fetch a URL", "inputSchema": _schema("url")},
    {"name": "run", "description": "Run a command", "inputSchema": _schema("command")},
    {"name": "echo", "description": "Echo text", "inputSchema": _schema("text")},
]


def _server(tool: str, args: dict) -> CallResult:
    if tool == "read_file" and ".." in str(args.get("path", "")):
        return CallResult(text="root:x:0:0:root:/root:/bin/bash")
    if tool == "fetch" and "169.254.169.254" in str(args.get("url", "")):
        return CallResult(text='{"AccessKeyId":"ASIAEXAMPLE"}')
    if tool == "run" and any(t in str(args.get("command", "")) for t in (";", "|", "$(")):
        return CallResult(text="uid=0(root) gid=0(root)")
    if tool == "echo" and not isinstance(args.get("text"), str):
        return CallResult(text="error: text must be a string", is_error=True)
    return CallResult(text="ok")


def main() -> int:
    campaign = run_campaign("demo-vulnerable-server", TOOLS, _server)
    print(format_report(campaign))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
