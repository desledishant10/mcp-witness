"""TypeScript source rules. Same rule ids, severities and categories as their
Python counterparts, so an S-007 is an S-007 regardless of the server's
language.

Per-tool rules (run on each handler body) are in ``TS_RULES``; file-level rules
(run once on the parsed tree) are in ``TS_FILE_RULES``.

- MCP-S-006 command path traversal   (per-tool)
- MCP-S-007 command injection         (per-tool)
- MCP-S-011 sensitive logging         (per-tool)
- MCP-S-014 transport Origin/Host     (file-level)
"""

from __future__ import annotations

import re

from analyzer.ts import treesitter_utils as ts
from analyzer.ts.discover import TSTool
from analyzer.types import Finding

# --- S-007 command injection ------------------------------------------------
_EXEC_SHELL_SINKS = {"exec", "execSync"}  # child_process: shell by default
_SPAWN_SINKS = {"spawn", "spawnSync", "execFile", "execFileSync"}  # need shell:true

# --- S-006 path traversal ---------------------------------------------------
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

# --- S-011 sensitive logging ------------------------------------------------
_LOG_METHODS = {
    "log",
    "info",
    "warn",
    "warning",
    "error",
    "debug",
    "critical",
    "exception",
    "trace",
}
_SENSITIVE_NAME_RE = re.compile(
    r"(?:^|_)(?:request|req|header|headers|auth|token|bearer|credential|cred|"
    r"secret|key|apikey|api_key|password|passwd|pwd|cookie|session)(?:_|$)",
    re.IGNORECASE,
)
_DEBUG_GATE_RE = re.compile(r"\b(debug|verbose|trace)\b", re.IGNORECASE)

# --- S-014 transport --------------------------------------------------------
_TRANSPORT_CLASSES = {"StreamableHTTPServerTransport", "SSEServerTransport"}
_REBIND_PROTECTION_KEYS = ("enableDnsRebindingProtection", "allowedHosts", "allowedOrigins")
_ORIGIN_READ_RE = re.compile(
    r"""headers\s*(\[\s*['"](?:origin|host)['"]\s*\]|\.\s*(?:origin|host)\b)"""
    r"""|\.\s*get\(\s*['"](?:origin|host)['"]""",
    re.IGNORECASE,
)


def _tool_finding(rule_id, severity, category, tool: TSTool, node, message) -> Finding:
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


def _file_finding(
    rule_id, severity, category, path, node, src, message, tool_name="<transport>"
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=category,
        file=path,
        line=node.start_point[0] + 1,
        tool_name=tool_name,
        message=message,
        evidence=ts.node_text(node, src)[:160],
    )


# --------------------------------------------------------------------------- #
# S-007 command injection
# --------------------------------------------------------------------------- #
def _has_shell_true(args, src: bytes) -> bool:
    return any(
        a.type == "object" and "shell:true" in ts.node_text(a, src).replace(" ", "") for a in args
    )


def check_command_injection_ts(tool: TSTool) -> list[Finding]:
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
                _tool_finding(
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
                _tool_finding(
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


# --------------------------------------------------------------------------- #
# S-006 path traversal
# --------------------------------------------------------------------------- #
def _handler_has_containment_guard(handler, src: bytes) -> bool:
    text = ts.node_text(handler, src).lower()
    return ("resolve" in text or "realpath" in text) and (
        "startswith" in text or "relative" in text
    )


def check_path_traversal_ts(tool: TSTool) -> list[Finding]:
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
                _tool_finding(
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


# --------------------------------------------------------------------------- #
# S-011 sensitive logging
# --------------------------------------------------------------------------- #
def _is_log_call(node, src: bytes) -> bool:
    fn = ts.call_function_text(node, src) or ""
    parts = fn.split(".")
    base = parts[-1]
    owner = ".".join(parts[:-1]).lower()
    if base in _LOG_METHODS and (
        owner in {"console", "logger"} or owner.endswith(".logger") or owner.endswith(".console")
    ):
        return True
    return base == "write" and (owner.endswith("stdout") or owner.endswith("stderr"))


def _args_are_sensitive(args, params: set[str], src: bytes) -> bool:
    for arg in args:
        if ts.subtree_references(arg, params, src):
            return True
        text = ts.node_text(arg, src)
        if "process.env" in text or ".headers" in text:
            return True
        for node in ts.walk(arg):
            if node.type in ("identifier", "property_identifier") and _SENSITIVE_NAME_RE.search(
                ts.node_text(node, src)
            ):
                return True
    return False


def _is_debug_gated(node, src: bytes) -> bool:
    cur = node.parent
    while cur is not None:
        if cur.type == "if_statement":
            cond = cur.child_by_field_name("condition")
            if cond is not None and _DEBUG_GATE_RE.search(ts.node_text(cond, src)):
                return True
        cur = cur.parent
    return False


def check_sensitive_logging_ts(tool: TSTool) -> list[Finding]:
    params = ts.handler_param_names(tool.handler, tool.source)
    findings: list[Finding] = []
    for node in ts.walk(tool.handler):
        if node.type != "call_expression" or not _is_log_call(node, tool.source):
            continue
        args = ts.call_args(node)
        if not _args_are_sensitive(args, params, tool.source):
            continue
        if _is_debug_gated(node, tool.source):
            continue
        findings.append(
            _tool_finding(
                "MCP-S-011",
                "medium",
                "tool.sensitive_logging",
                tool,
                node,
                f"{ts.call_function_text(node, tool.source)}(...) logs tool input, headers, or "
                "environment data — sensitive material lands in server logs.",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# S-014 transport Origin/Host (file-level)
# --------------------------------------------------------------------------- #
def _new_constructor_name(new_node, src: bytes) -> str | None:
    ctor = new_node.child_by_field_name("constructor")
    return ts.node_text(ctor, src).split(".")[-1] if ctor is not None else None


def _listen_host_literal(args, src: bytes) -> str | None:
    # app.listen(port, host?) — host is the second positional string, if present.
    if len(args) >= 2:
        return ts.string_value(args[1], src)
    return None


def check_transport_origin_ts(root, src: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    file_validates_origin = bool(_ORIGIN_READ_RE.search(src.decode("utf-8", "replace")))
    for node in ts.walk(root):
        if node.type == "new_expression":
            name = _new_constructor_name(node, src)
            if name in _TRANSPORT_CLASSES:
                opts = ts.node_text(node, src)
                if not any(key in opts for key in _REBIND_PROTECTION_KEYS):
                    findings.append(
                        _file_finding(
                            "MCP-S-014",
                            "high",
                            "transport.origin_unchecked",
                            path,
                            node,
                            src,
                            f"{name} is created without DNS-rebinding protection (no "
                            "enableDnsRebindingProtection / allowedHosts / allowedOrigins) — any "
                            "web origin can drive the local MCP server.",
                        )
                    )
        elif node.type == "call_expression":
            base = ts.call_base_name(node, src)
            if base == "cors":
                text = ts.node_text(node, src).replace(" ", "").replace("'", '"')
                if 'origin:"*"' in text and "credentials:true" in text:
                    findings.append(
                        _file_finding(
                            "MCP-S-014",
                            "high",
                            "transport.cors_wildcard_credentials",
                            path,
                            node,
                            src,
                            "CORS is configured with origin '*' and credentials true — any site "
                            "can make credentialed cross-origin requests to the server.",
                        )
                    )
            elif base == "listen":
                host = _listen_host_literal(ts.call_args(node), src)
                if host in ("0.0.0.0", "::") and not file_validates_origin:
                    findings.append(
                        _file_finding(
                            "MCP-S-014",
                            "high",
                            "transport.origin_unchecked",
                            path,
                            node,
                            src,
                            f'.listen(..., "{host}") binds all interfaces with no Origin/Host '
                            "validation in the file (DNS-rebinding exposure).",
                        )
                    )
    return findings


# --------------------------------------------------------------------------- #
# S-013 prompt template injection (per-prompt)
# --------------------------------------------------------------------------- #
_FLAGGED_PROMPT_ROLES = {"system", "assistant"}
_INTERP_CALLS = {"replace", "format", "concat", "join"}


def _content_interpolates_param(content, params: set[str], src: bytes) -> bool:
    """A prompt param reaches the content through a string construction:
    a template `${param}`, `+` concatenation, or a replace/format/concat/join."""
    for node in ts.walk(content):
        if node.type == "template_substitution" and ts.subtree_references(node, params, src):
            return True
        if (
            node.type == "binary_expression"
            and ts.binary_operator(node, src) == "+"
            and ts.subtree_references(node, params, src)
        ):
            return True
        if (
            node.type == "call_expression"
            and ts.call_base_name(node, src) in _INTERP_CALLS
            and ts.subtree_references(node, params, src)
        ):
            return True
    return False


def check_prompt_injection_ts(prompt: TSTool) -> list[Finding]:
    """MCP-S-013 — a prompt argument is interpolated into a non-user (system /
    assistant) message. High for system/assistant, medium for other non-user
    roles; user-role messages are skipped."""
    params = ts.handler_param_names(prompt.handler, prompt.source)
    findings: list[Finding] = []
    seen: set[int] = set()
    for node in ts.walk(prompt.handler):
        if node.type != "object":
            continue
        props = ts.object_properties(node, prompt.source)
        if "role" not in props or "content" not in props:
            continue
        role = ts.string_value(props["role"], prompt.source)
        if role == "user":
            continue
        content = props["content"]
        if content.type == "object":  # unwrap { type: "text", text: … }
            inner = ts.object_properties(content, prompt.source)
            content = inner.get("text", content)
        if not _content_interpolates_param(content, params, prompt.source):
            continue
        line = node.start_point[0] + 1
        if line in seen:
            continue
        seen.add(line)
        findings.append(
            _tool_finding(
                "MCP-S-013",
                "high" if role in _FLAGGED_PROMPT_ROLES else "medium",
                "prompt.template_injection",
                prompt,
                node,
                f"Prompt argument interpolated into a '{role or 'non-user'}' message — "
                "user-controlled text reaches an instruction-bearing role.",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# S-012 roots declared but never consulted (file-level)
# --------------------------------------------------------------------------- #
def _find_roots_capability_node(root, src: bytes):
    for node in ts.walk(root):
        if node.type != "pair":
            continue
        key = node.child_by_field_name("key")
        if key is None or ts.node_text(key, src).strip("\"'") != "capabilities":
            continue
        value = node.child_by_field_name("value")
        if (
            value is not None
            and value.type == "object"
            and "roots" in ts.object_properties(value, src)
        ):
            return node
    return None


def _file_calls_list_roots(root, src: bytes) -> bool:
    return any(
        node.type == "call_expression" and ts.call_base_name(node, src) == "listRoots"
        for node in ts.walk(root)
    )


def check_roots_declared_unused_ts(root, src: bytes, path: str) -> list[Finding]:
    node = _find_roots_capability_node(root, src)
    if node is None or _file_calls_list_roots(root, src):
        return []
    return [
        _file_finding(
            "MCP-S-012",
            "medium",
            "capability.roots_declared_unused",
            path,
            node,
            src,
            "The server declares the roots capability but never calls listRoots(), so the "
            "declared filesystem-containment guarantee is not enforced.",
            tool_name="<server>",
        )
    ]


TS_RULES = [check_command_injection_ts, check_path_traversal_ts, check_sensitive_logging_ts]
TS_PROMPT_RULES = [check_prompt_injection_ts]
TS_FILE_RULES = [check_transport_origin_ts, check_roots_declared_unused_ts]
