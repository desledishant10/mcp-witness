"""An in-process, deliberately vulnerable MCP-shaped server for fuzzer tests.

It is a ``call_fn(tool, arguments) -> CallResult`` plus the matching tool
definitions. Each tool models one bug class so the engine can be shown to find
it: path traversal, SSRF, command injection, a raw SQL error, a crash on a huge
input, and an unhandled-exception leak. ``safe_echo`` is well-behaved and must
never produce a finding.
"""

from __future__ import annotations

from fuzzer.models import CallResult


def _schema(pname: str) -> dict:
    return {
        "type": "object",
        "properties": {pname: {"type": "string"}},
        "required": [pname],
    }


TOOLS = [
    {"name": "read_file", "description": "Read a file from disk", "inputSchema": _schema("path")},
    {"name": "fetch", "description": "Fetch a URL", "inputSchema": _schema("url")},
    {"name": "run", "description": "Run a shell command", "inputSchema": _schema("command")},
    {"name": "query_db", "description": "Run a database query", "inputSchema": _schema("query")},
    {"name": "parse", "description": "Parse content", "inputSchema": _schema("content")},
    {"name": "explode", "description": "Process data", "inputSchema": _schema("data")},
    {"name": "safe_echo", "description": "Echo text back", "inputSchema": _schema("text")},
]


def call(tool: str, arguments: dict) -> CallResult:
    if tool == "read_file":
        path = str(arguments.get("path", ""))
        if "etc/passwd" in path or ".." in path:
            return CallResult(text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\n")
        return CallResult(text="hello world")

    if tool == "fetch":
        url = str(arguments.get("url", ""))
        if "169.254.169.254" in url:
            return CallResult(text='{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"redacted"}')
        if url.startswith("file://"):
            return CallResult(text="root:x:0:0:root:/root:/bin/bash")
        return CallResult(text="<html>ok</html>")

    if tool == "run":
        command = str(arguments.get("command", ""))
        if any(tok in command for tok in (";", "|", "$(", "`", "&&", "\n")):
            return CallResult(text="uid=0(root) gid=0(root) groups=0(root)")
        return CallResult(text="done")

    if tool == "query_db":
        query = str(arguments.get("query", ""))
        if "'" in query or "--" in query or "UNION" in query:
            return CallResult(
                text='sqlite3.OperationalError: near "OR": syntax error', is_error=True
            )
        return CallResult(text="[]")

    if tool == "parse":
        content = arguments.get("content")
        if not isinstance(content, str):
            return CallResult(
                text=(
                    "Traceback (most recent call last):\n"
                    '  File "server.py", line 42, in parse\n'
                    "    return json.loads(content)\n"
                    "TypeError: expected string"
                ),
                is_error=True,
            )
        return CallResult(text="parsed")

    if tool == "explode":
        data = arguments.get("data")
        if isinstance(data, str) and len(data) >= 100_000:
            return CallResult(crashed=True)
        return CallResult(text="ok")

    if tool == "safe_echo":
        text = arguments.get("text")
        if not isinstance(text, str):
            return CallResult(text="error: 'text' must be a string", is_error=True)
        return CallResult(text=text[:50])

    return CallResult(text="unknown tool", is_error=True)
