"""TypeScript source rules. Same rule ids, severities and categories as their
Python counterparts, so an S-007 is an S-007 regardless of the server's
language.

Phase 1 ships the two highest-signal handler-body rules:
- MCP-S-007 command injection
- MCP-S-006 path traversal
"""

from __future__ import annotations

from analyzer.ts import treesitter_utils as ts
from analyzer.ts.discover import TSTool
from analyzer.types import Finding

# child_process.exec / execSync run through a shell by default: any tool input
# in the command string is injectable.
_EXEC_SHELL_SINKS = {"exec", "execSync"}
# spawn / execFile only reach a shell when explicitly told to.
_SPAWN_SINKS = {"spawn", "spawnSync", "execFile", "execFileSync"}
# fs read sinks that take a path.
_FS_READ_SINKS = {
    "readFileSync",
    "readFile",
    "createReadStream",
    "openSync",
    "open",
    "readdir",
    "readdirSync",
    "realpathSync",
}


def _finding(
    rule_id: str, severity: str, category: str, tool: TSTool, node, message: str
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=category,
        file=tool.path,
        line=node.start_point[0] + 1,
        tool_name=tool.name,
        message=message,
        evidence=ts.node_text(node, tool.source)[:160],
    )


def _has_shell_true(args, src: bytes) -> bool:
    for arg in args:
        if arg.type == "object" and "shell:true" in ts.node_text(arg, src).replace(" ", ""):
            return True
    return False


def check_command_injection_ts(tool: TSTool) -> list[Finding]:
    """MCP-S-007 — a tool handler builds a shell command from tool input."""
    params = ts.handler_param_names(tool.handler, tool.source)
    findings: list[Finding] = []
    for node in ts.walk(tool.handler):
        if node.type != "call_expression":
            continue
        base = ts.call_base_name(node, tool.source)
        args = ts.call_args(node)
        tainted = any(ts.subtree_references(a, params, tool.source) for a in args)
        if base in _EXEC_SHELL_SINKS and tainted:
            findings.append(
                _finding(
                    "MCP-S-007",
                    "critical",
                    "tool.input.command_injection",
                    tool,
                    node,
                    f"{ts.call_function_text(node, tool.source)}(...) runs a shell command built "
                    "from tool input (child_process.exec/execSync use a shell by default).",
                )
            )
        elif base in _SPAWN_SINKS and tainted and _has_shell_true(args, tool.source):
            findings.append(
                _finding(
                    "MCP-S-007",
                    "critical",
                    "tool.input.command_injection",
                    tool,
                    node,
                    f"{ts.call_function_text(node, tool.source)}(..., {{ shell: true }}) runs a "
                    "shell command built from tool input.",
                )
            )
    return findings


def _handler_has_containment_guard(handler, src: bytes) -> bool:
    """Coarse heuristic mirroring the Python rule: the handler resolves the path
    and checks containment (startsWith / path.relative)."""
    text = ts.node_text(handler, src).lower()
    return ("resolve" in text or "realpath" in text) and (
        "startswith" in text or "relative" in text
    )


def check_path_traversal_ts(tool: TSTool) -> list[Finding]:
    """MCP-S-006 — a path-like tool input reaches an fs read with no containment."""
    params = ts.handler_param_names(tool.handler, tool.source)
    if _handler_has_containment_guard(tool.handler, tool.source):
        return []
    findings: list[Finding] = []
    for node in ts.walk(tool.handler):
        if node.type != "call_expression":
            continue
        if ts.call_base_name(node, tool.source) not in _FS_READ_SINKS:
            continue
        args = ts.call_args(node)
        if any(ts.subtree_references(a, params, tool.source) for a in args):
            findings.append(
                _finding(
                    "MCP-S-006",
                    "critical",
                    "tool.input.path_traversal",
                    tool,
                    node,
                    f"{ts.call_function_text(node, tool.source)}(...) reads a path derived from "
                    "tool input with no root-containment guard.",
                )
            )
    return findings


TS_RULES = [check_command_injection_ts, check_path_traversal_ts]
