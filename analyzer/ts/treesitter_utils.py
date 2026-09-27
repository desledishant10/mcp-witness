"""tree-sitter helpers for the TS/JS front-end.

These are the language-neutral primitives the source rules need — the TS analogs
of the inline Python-AST helpers in `analyzer/rules.py`: node text, a walk, call
callee/argument extraction, string-literal reading, handler-parameter names, and
a lightweight "does this subtree reference a handler parameter" taint check.

Matching is syntactic (callee spelling, argument shape), not type- or
import-resolved — the same precision the Python analyzer already accepts.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

_EXT_TO_LANG = {
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".jsx": "tsx",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}
TS_EXTENSIONS = frozenset(_EXT_TO_LANG)

_HANDLER_TYPES = {"arrow_function", "function_expression", "function", "function_declaration"}


def language_for_path(path: str | Path) -> str | None:
    return _EXT_TO_LANG.get(Path(path).suffix.lower())


@cache
def _parser(language: str):
    from tree_sitter_language_pack import get_parser

    return get_parser(language)


def parse(src: bytes, language: str):
    return _parser(language).parse(src)


def node_text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def walk(node):
    """Pre-order depth-first traversal, root first."""
    stack = [node]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def call_function_text(call_node, src: bytes) -> str | None:
    fn = call_node.child_by_field_name("function")
    return node_text(fn, src) if fn is not None else None


def call_base_name(call_node, src: bytes) -> str | None:
    """Final callee segment: ``fs.readFileSync`` -> ``readFileSync``,
    ``require("fs").readFile`` -> ``readFile``, ``execSync`` -> ``execSync``."""
    fn = call_function_text(call_node, src)
    if fn is None:
        return None
    return fn.split(".")[-1].strip()


def call_args(call_node) -> list:
    args = call_node.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def string_value(node, src: bytes) -> str | None:
    if node.type in ("string", "template_string"):
        text = node_text(node, src)
        return text[1:-1] if len(text) >= 2 else text
    return None


def is_handler(node) -> bool:
    return node.type in _HANDLER_TYPES


def last_handler_arg(args: list):
    for arg in reversed(args):
        if is_handler(arg):
            return arg
    return None


def handler_param_names(handler, src: bytes) -> set[str]:
    """Names bound by a handler's parameter list, including destructured object
    patterns: ``async ({ url, path }) => …`` yields {"url", "path"}."""
    names: set[str] = set()
    for field in ("parameters", "parameter"):
        param = handler.child_by_field_name(field)
        if param is None:
            continue
        if param.type == "identifier":
            names.add(node_text(param, src))
            continue
        for node in walk(param):
            if node.type in ("identifier", "shorthand_property_identifier_pattern"):
                names.add(node_text(node, src))
    return names


def subtree_references(node, names: set[str], src: bytes) -> bool:
    """True if any identifier in the subtree is one of ``names`` (lightweight
    taint: does this expression use a handler parameter)."""
    return any(n.type == "identifier" and node_text(n, src) in names for n in walk(node))


def object_properties(obj_node, src: bytes) -> dict[str, object]:
    """Map an object literal's key names to their value nodes.
    ``{ role: "system", content: x }`` -> {"role": <node>, "content": <node>}."""
    props: dict[str, object] = {}
    for child in obj_node.named_children:
        if child.type == "pair":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            if key is not None and value is not None:
                props[node_text(key, src).strip("\"'")] = value
    return props


def binary_operator(node, src: bytes) -> str | None:
    op = node.child_by_field_name("operator")
    return node_text(op, src) if op is not None else None
