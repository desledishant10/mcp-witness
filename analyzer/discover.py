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
            tool_decorators = [d for d in node.decorator_list if _is_tool_decorator(d)]
            if tool_decorators:
                tools.append(
                    DiscoveredTool(
                        name=node.name,
                        description=ast.get_docstring(node) or "",
                        source_path=path,
                        line=node.lineno,
                        function_node=node,
                        parameters=[a.arg for a in node.args.args if a.arg != "self"],
                        annotations=_decorator_annotations(tool_decorators[0]),
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


# MCP annotation hint keys. Only these are lifted off the decorator; other
# decorator kwargs (name, description, ...) are ignored here.
_ANNOTATION_HINT_KEYS = {
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
}


def _decorator_annotations(dec) -> dict | None:
    """Extract MCP annotation hints declared on a `@...tool(...)` decorator.

    Handles the shapes a FastMCP server actually uses:
    - `@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))`
    - `@mcp.tool(annotations={"readOnlyHint": True})`
    - `@mcp.tool(readOnlyHint=True)` (hint passed directly)

    Only boolean-literal hint values are lifted; anything computed at
    runtime is left out (we can't resolve it statically, and guessing
    would risk a false annotation). Returns None when the decorator
    declares no hints, so S-004 stays silent exactly as if the server set
    no annotations.
    """
    if not isinstance(dec, ast.Call):
        return None
    hints: dict = {}
    for kw in dec.keywords:
        if kw.arg in _ANNOTATION_HINT_KEYS:
            val = _bool_literal(kw.value)
            if val is not None:
                hints[kw.arg] = val
        elif kw.arg == "annotations":
            hints.update(_annotations_kwarg(kw.value))
    return hints or None


def _annotations_kwarg(value) -> dict:
    """Pull boolean hint keys from an `annotations=` value that is either a
    dict literal or a `ToolAnnotations(...)` call."""
    hints: dict = {}
    if isinstance(value, ast.Dict):
        for k, v in zip(value.keys, value.values, strict=False):
            if isinstance(k, ast.Constant) and k.value in _ANNOTATION_HINT_KEYS:
                b = _bool_literal(v)
                if b is not None:
                    hints[k.value] = b
    elif isinstance(value, ast.Call):
        for kw in value.keywords:
            if kw.arg in _ANNOTATION_HINT_KEYS:
                b = _bool_literal(kw.value)
                if b is not None:
                    hints[kw.arg] = b
    return hints


def _bool_literal(node) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


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
        annotations = t.get("annotations")
        tools.append(
            DiscoveredTool(
                name=t.get("name", ""),
                description=t.get("description") or "",
                source_path="<captured>",
                line=0,
                function_node=None,
                parameters=params,
                input_schema=schema or None,
                annotations=annotations if isinstance(annotations, dict) else None,
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
