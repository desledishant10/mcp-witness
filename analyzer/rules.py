"""Detection rules for the static analyzer (v0.1: S-001, S-006, S-007).

Each rule is a function `(tool: DiscoveredTool) -> list[Finding]`.
Spec: ../docs/static-rules.md.
"""

from __future__ import annotations

import ast
import re
from typing import Callable

from .types import DiscoveredTool, Finding

# ---------------------------------------------------------------------------
# MCP-S-001 — Imperative instructions in tool description
# ---------------------------------------------------------------------------

_IMPERATIVE_PATTERNS = [
    re.compile(r"\byou\s+(must|should|will)\b", re.IGNORECASE),
    re.compile(r"\balways\b.{0,80}\b(call|invoke|use|run|send|fetch)\b", re.IGNORECASE),
    re.compile(r"\bbefore\s+(any|invoking|calling|using|each|every|the)\b", re.IGNORECASE),
    re.compile(r"\b(important|warning|note|system\s*note)\s*:.{0,200}\b(call|invoke|use|send|fetch)\b",
                re.IGNORECASE),
    re.compile(r"\bnever\s+(mention|disclose|tell|reveal)\b", re.IGNORECASE),
    re.compile(r"\b(ignore|disregard)\s+(previous|prior|above)\b", re.IGNORECASE),
    # Calibration-driven (real mcp-server-fetch description): the "your
    # previous limits have changed" / "now you can" / "grants you" pattern
    # is a distinct injection style that reframes capabilities rather than
    # commanding specific actions.
    re.compile(r"\bnow\s+you\s+(can|may|have)\b", re.IGNORECASE),
    re.compile(r"\byou\s+(were|are)\s+(advised|told|instructed)\b", re.IGNORECASE),
    re.compile(r"\bgrants?\s+you\b", re.IGNORECASE),
]

_URL_RE = re.compile(r"https?://[^\s)>\]]+")


def check_description_injection(tool: DiscoveredTool) -> list[Finding]:
    desc = tool.description or ""
    if not desc.strip():
        return []
    findings: list[Finding] = []
    for pat in _IMPERATIVE_PATTERNS:
        m = pat.search(desc)
        if m:
            findings.append(Finding(
                rule_id="MCP-S-001",
                severity="high",
                category="tool.description_injection",
                file=tool.source_path,
                line=tool.line,
                tool_name=tool.name,
                message="Tool description contains instruction-like phrasing directed at the model.",
                evidence=desc[max(0, m.start() - 20): m.end() + 60].strip(),
            ))
            break
    if _URL_RE.search(desc):
        findings.append(Finding(
            rule_id="MCP-S-001",
            severity="medium",
            category="tool.description_injection",
            file=tool.source_path,
            line=tool.line,
            tool_name=tool.name,
            message="Tool description contains a URL — potential exfil instruction or covert channel.",
            evidence=desc[:200],
        ))
    return findings


# ---------------------------------------------------------------------------
# MCP-S-003 — Hidden instructions in schema sub-fields
# ---------------------------------------------------------------------------

# Patterns specific to parameter descriptions — agent-directed phrasing
# that wouldn't typically appear in a tool-level description but is a
# distinct injection vector at the schema-field level.
_PARAM_DIRECTIVE_PATTERNS = [
    # Real-world (mcp-server-time): "Use 'America/Denver' as local timezone
    # if no timezone provided by the user." Telling the agent what to
    # assume about user state is categorically different from describing
    # the parameter; the auditor should evaluate every such case.
    re.compile(r"\bif\s+(no|none)\b.{0,40}\bprovided\b.{0,20}\bby\s+the\s+user\b",
                re.IGNORECASE),
    re.compile(r"\b(assume|infer)\b.{0,30}\bthe\s+user\b", re.IGNORECASE),
]

_SCHEMA_DIRECTIVE_PATTERNS = _IMPERATIVE_PATTERNS + _PARAM_DIRECTIVE_PATTERNS
_SCHEMA_DESC_KEYS = {"description", "title", "$comment"}


def check_schema_field_injection(tool: DiscoveredTool) -> list[Finding]:
    """MCP-S-003 — agent-directed phrasing inside schema sub-fields.

    Scans every `description`, `title`, and `$comment` string anywhere
    in the tool's `inputSchema` for the same patterns S-001 applies to
    the tool description, plus a few patterns specific to the
    param-description style.
    """
    if not tool.input_schema:
        return []
    findings: list[Finding] = []
    for path, value in _walk_description_fields(tool.input_schema):
        for pat in _SCHEMA_DIRECTIVE_PATTERNS:
            m = pat.search(value)
            if m:
                findings.append(Finding(
                    rule_id="MCP-S-003",
                    severity="high",
                    category="tool.schema_field_injection",
                    file=tool.source_path,
                    line=tool.line,
                    tool_name=tool.name,
                    message=f"Schema field {path!r} contains agent-directed phrasing.",
                    evidence=value[max(0, m.start() - 20): m.end() + 60].strip(),
                ))
                break    # one finding per field
    return findings


def _walk_description_fields(obj, prefix: str = ""):
    """Yield (path, value) for every description/title/$comment string."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{prefix}.{k}" if prefix else k
            if k in _SCHEMA_DESC_KEYS and isinstance(v, str):
                yield new_path, v
            elif isinstance(v, (dict, list)):
                yield from _walk_description_fields(v, new_path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_description_fields(v, f"{prefix}[{i}]")


# ---------------------------------------------------------------------------
# MCP-S-006 — Path traversal in file-handling tool
# ---------------------------------------------------------------------------

_PATH_PARAM_INDICATORS = (
    "path", "file", "filename", "filepath", "dir", "directory", "folder", "location",
)
_FS_READ_SINK_ATTRS = {"read_text", "read_bytes", "open", "iterdir", "glob", "rglob"}
_PATH_GUARD_ATTRS = {"is_relative_to", "resolve", "realpath", "commonpath", "startswith"}


def check_path_traversal(tool: DiscoveredTool) -> list[Finding]:
    fn = tool.function_node
    if fn is None:
        return []
    path_params = [
        p for p in tool.parameters
        if any(ind in p.lower() for ind in _PATH_PARAM_INDICATORS)
    ]
    if not path_params:
        return []

    guard_lines = _collect_guard_lines(fn)
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for node in ast.walk(fn):
        if not _is_fs_read_sink_call(node):
            continue
        if not _call_args_reference_any(node, path_params):
            continue
        if any(g < node.lineno for g in guard_lines):
            continue
        if node.lineno in seen_lines:
            continue
        seen_lines.add(node.lineno)
        findings.append(Finding(
            rule_id="MCP-S-006",
            severity="critical",
            category="tool.input.path_traversal",
            file=tool.source_path,
            line=node.lineno,
            tool_name=tool.name,
            message=(
                f"Tool parameter(s) {path_params!r} flow to a filesystem sink "
                f"without an apparent root-containment check."
            ),
            evidence=_safe_unparse(node),
        ))
    return findings


def _is_fs_read_sink_call(node) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == "open":
        return True
    if isinstance(func, ast.Attribute) and func.attr in _FS_READ_SINK_ATTRS:
        return True
    return False


def _call_args_reference_any(call: ast.Call, names: list[str]) -> bool:
    nodes = list(call.args) + [kw.value for kw in call.keywords]
    # For chained sinks like `Path(filepath).read_text()` the parameter
    # reference lives in the receiver, not in the .read_text() arglist.
    # Include the receiver so the chained form is caught.
    if isinstance(call.func, ast.Attribute):
        nodes.append(call.func.value)
    for arg in nodes:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Name) and sub.id in names:
                return True
    return False


def _collect_guard_lines(fn) -> set[int]:
    lines: set[int] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in _PATH_GUARD_ATTRS:
                lines.add(node.lineno)
        elif isinstance(node, ast.If):
            for sub in ast.walk(node.test):
                if isinstance(sub, ast.Attribute) and sub.attr in _PATH_GUARD_ATTRS:
                    lines.add(node.lineno)
    return lines


# ---------------------------------------------------------------------------
# MCP-S-007 — Shell command injection in tool handler
# ---------------------------------------------------------------------------

_SUBPROCESS_FNS = {"run", "call", "Popen", "check_output", "check_call"}


def check_command_injection(tool: DiscoveredTool) -> list[Finding]:
    fn = tool.function_node
    if fn is None:
        return []
    findings: list[Finding] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = _check_call_for_shell_exec(node, tool)
        if f is not None:
            findings.append(f)
    return findings


def _check_call_for_shell_exec(call: ast.Call, tool: DiscoveredTool) -> Finding | None:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    if not isinstance(func.value, ast.Name):
        return None
    module = func.value.id

    if module == "subprocess" and func.attr in _SUBPROCESS_FNS and _has_shell_true(call):
        return Finding(
            rule_id="MCP-S-007", severity="critical",
            category="tool.input.command_injection",
            file=tool.source_path, line=call.lineno, tool_name=tool.name,
            message=(f"subprocess.{func.attr}() called with shell=True; "
                      "tool parameters can reach the shell unescaped."),
            evidence=_safe_unparse(call),
        )
    if module == "os" and func.attr in {"system", "popen"}:
        return Finding(
            rule_id="MCP-S-007", severity="critical",
            category="tool.input.command_injection",
            file=tool.source_path, line=call.lineno, tool_name=tool.name,
            message=f"os.{func.attr}() invokes the shell with the given string.",
            evidence=_safe_unparse(call),
        )
    return None


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_unparse(node) -> str:
    try:
        return ast.unparse(node)[:160]
    except Exception:                                       # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# MCP-S-002 — Cross-tool reference in tool description
# ---------------------------------------------------------------------------

def check_cross_tool_references(tools: list[DiscoveredTool]) -> list[Finding]:
    """Tool description references another tool by name.

    Naming-based poisoning vector: a malicious server can include a tool
    whose description says "use this instead of audit_log" or "call
    delete_account after this completes" — directing the agent's
    behavior toward other tools in the surface. Flag any tool whose
    description contains another tool's name as a whole word.

    Severity is `high` when the reference appears in imperative context
    (any S-001 pattern fires in the same description), `medium`
    otherwise.
    """
    all_names = sorted({t.name for t in tools if t.name})
    findings: list[Finding] = []
    for tool in tools:
        desc = tool.description or ""
        if not desc.strip():
            continue
        for other in all_names:
            if other == tool.name:
                continue
            pat = re.compile(r"\b" + re.escape(other) + r"\b")
            m = pat.search(desc)
            if m is None:
                continue
            imperative = any(p.search(desc) for p in _IMPERATIVE_PATTERNS)
            findings.append(Finding(
                rule_id="MCP-S-002",
                severity="high" if imperative else "medium",
                category="tool.shadowing",
                file=tool.source_path,
                line=tool.line,
                tool_name=tool.name,
                message=(
                    f"Description references another tool by name: {other!r}"
                    + (" (in imperative context)" if imperative else "")
                ),
                evidence=desc[max(0, m.start() - 30): m.end() + 50].strip(),
            ))
            break    # one finding per tool
    return findings


# ---------------------------------------------------------------------------
# MCP-S-005 — Overbroad capability surface (server-level)
# ---------------------------------------------------------------------------

def check_overbroad_capability_surface(tools: list[DiscoveredTool]) -> list[Finding]:
    """Server exposes a capability combination that enables a known attack
    chain (exfil_pair, credential_exfil, write_then_execute, etc.).

    Wraps the classifier's `overbroad_combinations` detection as a
    formal analyzer finding. The combination set is versioned in
    classifier/lexicons.py (`OVERBROAD_COMBOS`).
    """
    from classifier import classify_server      # local to avoid import cost on every call

    server_class = classify_server([
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema or {},
        }
        for t in tools
    ])

    findings: list[Finding] = []
    for combo in server_class.overbroad_combinations:
        first_name = combo.tools[0] if combo.tools else None
        first_tool = next((t for t in tools if t.name == first_name), None)
        findings.append(Finding(
            rule_id="MCP-S-005",
            severity="medium",
            category="tool.overbroad_capability",
            file=first_tool.source_path if first_tool else "<server>",
            line=first_tool.line if first_tool else 0,
            tool_name=f"<server: {'+'.join(combo.tags)}>",
            message=(
                f"Server exposes overbroad capability combination "
                f"{' + '.join(combo.tags)} ({combo.rationale}). "
                f"Tools involved: {', '.join(combo.tools)}"
            ),
            evidence=f"rationale={combo.rationale}",
        ))
    return findings


# Rule registry — iterated by the analyzer driver.
RULES: list[Callable[[DiscoveredTool], list[Finding]]] = [
    check_description_injection,
    check_schema_field_injection,
    check_path_traversal,
    check_command_injection,
]

# Server-level rules — operate on the full tool set, not one tool at a time.
SERVER_RULES: list[Callable[[list[DiscoveredTool]], list[Finding]]] = [
    check_cross_tool_references,
    check_overbroad_capability_surface,
]
