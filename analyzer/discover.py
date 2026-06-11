"""Discover MCP tool definitions in Python source.

v0.1 recognizes the FastMCP-style decorator pattern: any function whose
decorator list contains `something.tool` or `something.tool(...)`. That
covers the vast majority of modern Python MCP servers built on
`mcp.server.fastmcp`.

The low-level `mcp.server.Server` pattern (tools declared inside a
`@server.list_tools()` handler) is a v0.2 discovery target — it requires
following the list-tools handler's return value, which is harder to do
statically.
"""

from __future__ import annotations

import ast
from pathlib import Path

from .types import DiscoveredTool

# Directory fragments to skip when walking a tree (always present in dev
# environments; would dilute findings or pull in third-party code).
_SKIP_FRAGMENTS = (
    "/.venv/",
    "/venv/",
    "/site-packages/",
    "/.git/",
    "/__pycache__/",
    "/node_modules/",
    "/.tox/",
    "/build/",
)


def discover_tools_in_source(source: str, path: str) -> list[DiscoveredTool]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    tools: list[DiscoveredTool] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if any(_is_tool_decorator(d) for d in node.decorator_list):
                tools.append(
                    DiscoveredTool(
                        name=node.name,
                        description=ast.get_docstring(node) or "",
                        source_path=path,
                        line=node.lineno,
                        function_node=node,
                        parameters=[a.arg for a in node.args.args if a.arg != "self"],
                    )
                )
    return tools


def _is_tool_decorator(dec) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr == "tool"
    if isinstance(target, ast.Name):
        return target.id == "tool"
    return False


def discover_tools_from_captured(captured: dict | list) -> list[DiscoveredTool]:
    """Build DiscoveredTool objects from a captured tools/list payload.

    Rules that depend on `function_node` (S-006, S-007) will produce no
    findings on these tools — only description-based rules (S-001) apply.
    """
    if isinstance(captured, list):
        captured = {"tools": captured}
    tools: list[DiscoveredTool] = []
    for t in captured.get("tools", []):
        schema = t.get("inputSchema") or t.get("input_schema") or {}
        params = list((schema.get("properties") or {}).keys())
        tools.append(
            DiscoveredTool(
                name=t.get("name", ""),
                description=t.get("description") or "",
                source_path="<captured>",
                line=0,
                function_node=None,
                parameters=params,
                input_schema=schema or None,
            )
        )
    return tools


def discover_tools_in_path(path: Path) -> list[DiscoveredTool]:
    if path.is_file():
        return discover_tools_in_source(path.read_text(), str(path))
    tools: list[DiscoveredTool] = []
    for py_file in path.rglob("*.py"):
        s = str(py_file)
        if any(frag in s for frag in _SKIP_FRAGMENTS):
            continue
        try:
            text = py_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        tools.extend(discover_tools_in_source(text, s))
    return tools
