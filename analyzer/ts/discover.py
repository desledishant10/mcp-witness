"""Discover MCP tool registrations in TypeScript / JavaScript source.

The TS SDK registers tools by call, not by decorator: ``server.tool("name",
"desc"?, schema, handler)`` and the newer ``server.registerTool("name",
{ description, inputSchema }, handler)``. We find those calls, take the tool
name from the first string argument and the handler from the last function
argument. The low-level ``setRequestHandler(ListToolsRequestSchema, …)`` switch
pattern is a later target.
"""

from __future__ import annotations

from dataclasses import dataclass

from analyzer.ts import treesitter_utils as ts

_REGISTER_CALLS = {"tool", "registerTool"}


@dataclass
class TSTool:
    """A tool registration found in TS/JS source. ``handler`` is the tree-sitter
    node of the handler function; ``source`` is the file bytes it indexes into."""

    name: str
    description: str | None
    handler: object
    source: bytes
    path: str
    line: int


def discover_tools_in_ts(src: bytes, path: str, language: str) -> list[TSTool]:
    return discover_tools_from_tree(ts.parse(src, language), src, path)


def discover_tools_from_tree(tree, src: bytes, path: str) -> list[TSTool]:
    tools: list[TSTool] = []
    for node in ts.walk(tree.root_node):
        if node.type != "call_expression":
            continue
        if ts.call_base_name(node, src) not in _REGISTER_CALLS:
            continue
        args = ts.call_args(node)
        if not args:
            continue
        name = ts.string_value(args[0], src)
        handler = ts.last_handler_arg(args)
        if name is None or handler is None:
            continue
        description = ts.string_value(args[1], src) if len(args) > 1 else None
        tools.append(
            TSTool(
                name=name,
                description=description,
                handler=handler,
                source=src,
                path=path,
                line=node.start_point[0] + 1,
            )
        )
    return tools
