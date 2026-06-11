"""Detection rules for the static analyzer (v0.1: S-001..S-014).

Three rule shapes:
- `RULES`        — per-tool. Signature: `(tool: DiscoveredTool) -> list[Finding]`.
- `SERVER_RULES` — full tool set. Signature: `(tools: list[DiscoveredTool]) -> list[Finding]`.
- `REPO_RULES`   — source tree root. Signature: `(root: Path) -> list[Finding]`.
                   Used for rules that scan files outside individual tool handlers
                   (transport config, repo-wide secrets, server capability declarations).

Spec: ../docs/static-rules.md.
"""

from __future__ import annotations

import ast
import fnmatch
import re
from collections.abc import Callable
from pathlib import Path

from .discover import _SKIP_FRAGMENTS
from .types import DiscoveredTool, Finding

# ---------------------------------------------------------------------------
# MCP-S-001 — Imperative instructions in tool description
# ---------------------------------------------------------------------------

_IMPERATIVE_PATTERNS = [
    re.compile(r"\byou\s+(must|should|will)\b", re.IGNORECASE),
    re.compile(r"\balways\b.{0,80}\b(call|invoke|use|run|send|fetch)\b", re.IGNORECASE),
    re.compile(r"\bbefore\s+(any|invoking|calling|using|each|every|the)\b", re.IGNORECASE),
    re.compile(
        r"\b(important|warning|note|system\s*note)\s*:.{0,200}\b(call|invoke|use|send|fetch)\b",
        re.IGNORECASE,
    ),
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
            findings.append(
                Finding(
                    rule_id="MCP-S-001",
                    severity="high",
                    category="tool.description_injection",
                    file=tool.source_path,
                    line=tool.line,
                    tool_name=tool.name,
                    message="Tool description contains instruction-like phrasing directed at the model.",
                    evidence=desc[max(0, m.start() - 20) : m.end() + 60].strip(),
                )
            )
            break
    if _URL_RE.search(desc):
        findings.append(
            Finding(
                rule_id="MCP-S-001",
                severity="medium",
                category="tool.description_injection",
                file=tool.source_path,
                line=tool.line,
                tool_name=tool.name,
                message="Tool description contains a URL — potential exfil instruction or covert channel.",
                evidence=desc[:200],
            )
        )
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
    re.compile(r"\bif\s+(no|none)\b.{0,40}\bprovided\b.{0,20}\bby\s+the\s+user\b", re.IGNORECASE),
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
                findings.append(
                    Finding(
                        rule_id="MCP-S-003",
                        severity="high",
                        category="tool.schema_field_injection",
                        file=tool.source_path,
                        line=tool.line,
                        tool_name=tool.name,
                        message=f"Schema field {path!r} contains agent-directed phrasing.",
                        evidence=value[max(0, m.start() - 20) : m.end() + 60].strip(),
                    )
                )
                break  # one finding per field
    return findings


def _walk_description_fields(obj, prefix: str = ""):
    """Yield (path, value) for every description/title/$comment string."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{prefix}.{k}" if prefix else k
            if k in _SCHEMA_DESC_KEYS and isinstance(v, str):
                yield new_path, v
            elif isinstance(v, dict | list):
                yield from _walk_description_fields(v, new_path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_description_fields(v, f"{prefix}[{i}]")


# ---------------------------------------------------------------------------
# MCP-S-006 — Path traversal in file-handling tool
# ---------------------------------------------------------------------------

_PATH_PARAM_INDICATORS = (
    "path",
    "file",
    "filename",
    "filepath",
    "dir",
    "directory",
    "folder",
    "location",
)
_FS_READ_SINK_ATTRS = {"read_text", "read_bytes", "open", "iterdir", "glob", "rglob"}
_PATH_GUARD_ATTRS = {"is_relative_to", "resolve", "realpath", "commonpath", "startswith"}


def check_path_traversal(tool: DiscoveredTool) -> list[Finding]:
    fn = tool.function_node
    if fn is None:
        return []
    path_params = [
        p for p in tool.parameters if any(ind in p.lower() for ind in _PATH_PARAM_INDICATORS)
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
        findings.append(
            Finding(
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
            )
        )
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
            rule_id="MCP-S-007",
            severity="critical",
            category="tool.input.command_injection",
            file=tool.source_path,
            line=call.lineno,
            tool_name=tool.name,
            message=(
                f"subprocess.{func.attr}() called with shell=True; "
                "tool parameters can reach the shell unescaped."
            ),
            evidence=_safe_unparse(call),
        )
    if module == "os" and func.attr in {"system", "popen"}:
        return Finding(
            rule_id="MCP-S-007",
            severity="critical",
            category="tool.input.command_injection",
            file=tool.source_path,
            line=call.lineno,
            tool_name=tool.name,
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
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# MCP-S-009 — URL-fetching tool with no apparent allowlist
# ---------------------------------------------------------------------------

# Parameter names that indicate the tool takes a URL.
_URL_PARAM_NAMES = {"url", "uri", "link", "endpoint", "href", "address"}

# JSON Schema `format` values that indicate a URL-typed parameter.
_URL_FORMATS = {"uri", "iri", "url", "uri-reference"}

# Description phrases that suggest the maintainer has implemented URL
# validation (allowlist, denylist, scheme restriction). Presence in
# description does not prove the validation works — but absence is a
# strong signal it doesn't exist.
_URL_VALIDATION_KEYWORDS = (
    "allowlist",
    "allowlisted",
    "denylist",
    "blocklist",
    "validated",
    "restricted to",
    "limited to",
    "only http",
    "only https",
    "https only",
    "scheme is",
    "rejected if",
    "internal hosts",
    "metadata service",
    "link-local",
    "ssrf",
)


def check_url_fetch_unrestricted(tool: DiscoveredTool) -> list[Finding]:
    """MCP-S-009 — Heuristic SSRF flag for URL-fetching tools.

    Static counterpart to the dynamic D-003 SSRF probe. Fires when:
    - the tool has a parameter that looks like a URL (by name or by JSON
      Schema `format: uri`), AND
    - there is no JSON Schema `pattern`/`const`/`enum` constraint on that
      parameter (which would indicate an allowlist), AND
    - the description contains none of the URL-validation keywords that
      maintainers typically use when documenting allowlist/denylist
      behavior.

    This is necessary-but-not-sufficient — the validation might exist in
    code without being reflected in the schema or description. The
    finding is a high-severity "review this" prompt, not a vulnerability
    claim on its own. Auditor confirms by reading source.
    """
    if not tool.input_schema:
        return []
    properties = tool.input_schema.get("properties") or {}
    url_params: list[str] = []
    for pname, pdef in properties.items():
        if pname.lower() in _URL_PARAM_NAMES:
            url_params.append(pname)
        elif isinstance(pdef, dict) and (pdef.get("format") or "").lower() in _URL_FORMATS:
            url_params.append(pname)
    if not url_params:
        return []

    # Any schema-level URL constraint counts as evidence of intent to restrict.
    for pname in url_params:
        pdef = properties.get(pname) or {}
        if pdef.get("pattern") or pdef.get("const") or pdef.get("enum"):
            return []

    # Any validation keyword in the description counts as evidence of intent
    # — auditor still verifies the implementation, but the rule defers.
    desc_lower = (tool.description or "").lower()
    if any(kw in desc_lower for kw in _URL_VALIDATION_KEYWORDS):
        return []

    return [
        Finding(
            rule_id="MCP-S-009",
            severity="high",
            category="tool.input.ssrf",
            file=tool.source_path,
            line=tool.line,
            tool_name=tool.name,
            message=(
                f"Tool has URL parameter(s) {url_params!r} with no schema-level "
                f"constraint and no validation keywords in the description. "
                f"Likely no scheme allowlist or host denylist — verify against "
                f"SSRF to link-local / loopback / cloud-metadata addresses."
            ),
            evidence=f"url_params={url_params}",
        )
    ]


# ---------------------------------------------------------------------------
# MCP-S-004 — Tool annotation contradicts inferred capability
# ---------------------------------------------------------------------------

# Verb stems indicating write/destructive behavior. Stem-based with `\w*`
# tail to absorb suffixes (-s, -ed, -ing, -er) and snake_case continuations
# (e.g. `delete_record` matches via `\bdelet\w*\b`).
_WRITE_INDICATING_WORDS = re.compile(
    r"\b(writ|delet|remov|creat|drop|updat|modif|overwrit|"
    r"insert|patch|edit|append|truncat|renam|mov|chmod|chown|"
    r"send|sent|post|publish|commit|merg|push)\w*\b",
    re.IGNORECASE,
)


def check_annotation_lying(tool: DiscoveredTool) -> list[Finding]:
    """MCP-S-004 — Tool annotation declares read-only / non-destructive
    but name or description indicates the opposite.

    Reads `tool.input_schema` for annotations because the captured
    representation tools/list returns has annotations alongside
    description / inputSchema. Most servers in the wild don't set
    annotations (only newer SDK adopters do), so this rule will be
    silent on most corpora — but when it fires, it's high-signal: an
    explicit lie about safety means either a maintainer mistake or
    deliberate misdirection. Either deserves attention.
    """
    if not tool.input_schema:
        return []
    # In some captures the tool dict carries `annotations` as a sibling of
    # `inputSchema` — but our DiscoveredTool only carries the schema. The
    # MCP SDK puts annotations on the Tool object itself, accessible via
    # the JSON-RPC response. For now, look for annotations stored inside
    # the schema dict under a convention key, falling back to noop.
    annotations = tool.input_schema.get("__annotations__") or {}
    if not annotations:
        return []

    read_only = annotations.get("readOnlyHint") is True
    not_destructive = annotations.get("destructiveHint") is False
    if not (read_only or not_destructive):
        return []

    haystack = f"{tool.name} {tool.description or ''}"
    m = _WRITE_INDICATING_WORDS.search(haystack)
    if not m:
        return []

    lie = "readOnlyHint=true" if read_only else "destructiveHint=false"
    return [
        Finding(
            rule_id="MCP-S-004",
            severity="high",
            category="tool.annotation_lying",
            file=tool.source_path,
            line=tool.line,
            tool_name=tool.name,
            message=(
                f"Annotation {lie} contradicts inferred behavior. "
                f"Name/description contains write-indicating verb {m.group(0)!r}, "
                f"which suggests the tool is not read-only / not safe."
            ),
            evidence=f"matched={m.group(0)!r} annotation={lie}",
        )
    ]


# ---------------------------------------------------------------------------
# MCP-S-008 — Database-query tool with no apparent input constraint
# ---------------------------------------------------------------------------

_QUERY_PARAM_NAMES = {"query", "sql", "filter", "where", "search_query", "stmt", "statement"}

_SQL_VALIDATION_KEYWORDS = (
    "parameterized",
    "parameterised",
    "prepared statement",
    "prepared-statement",
    "bind parameters",
    "bound parameters",
    "escape",
    "escaped",
    "read-only",
    "select only",
    "select-only",
    "no ddl",
    "no dml",
    "sanitized",
    "sanitised",
    "validated",
    "allowlist",
    "sqlite_master",
)


def check_sql_injection_unrestricted(tool: DiscoveredTool) -> list[Finding]:
    """MCP-S-008 — Heuristic SQLi flag for database-query tools.

    Static counterpart to dynamic SQLi probing (no dynamic scenario exists
    yet for this — D-008 will pair with it). Fires when:
    - the tool has a parameter that looks like a SQL/query string (by name
      or by schema description), AND
    - there is no schema-level constraint (pattern/enum/const) on that
      parameter, AND
    - the description contains none of the SQLi-mitigation keywords that
      maintainers typically use.

    Necessary-but-not-sufficient — the validation might exist in code
    (parameterized queries at the cursor level) without being reflected
    in the tool's MCP surface. Finding is "review this" not
    "vulnerable for sure."
    """
    if not tool.input_schema:
        return []
    properties = tool.input_schema.get("properties") or {}
    query_params: list[str] = []
    for pname, pdef in properties.items():
        if pname.lower() in _QUERY_PARAM_NAMES:
            query_params.append(pname)
            continue
        if isinstance(pdef, dict):
            pdesc = (pdef.get("description") or "").lower()
            if "sql" in pdesc and ("query" in pdesc or "statement" in pdesc):
                query_params.append(pname)
    if not query_params:
        return []

    for pname in query_params:
        pdef = properties.get(pname) or {}
        if pdef.get("pattern") or pdef.get("const") or pdef.get("enum"):
            return []

    desc_lower = (tool.description or "").lower()
    if any(kw in desc_lower for kw in _SQL_VALIDATION_KEYWORDS):
        return []

    return [
        Finding(
            rule_id="MCP-S-008",
            severity="high",
            category="tool.input.sql_injection",
            file=tool.source_path,
            line=tool.line,
            tool_name=tool.name,
            message=(
                f"Tool accepts SQL-shaped input via {query_params!r} with no "
                f"schema-level constraint and no mention of parameterized "
                f"queries / sanitization / read-only mode in the description. "
                f"Verify the implementation uses parameterized queries; if not, "
                f"vulnerable to SQL injection via prompt-injected tool arguments."
            ),
            evidence=f"query_params={query_params}",
        )
    ]


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
            findings.append(
                Finding(
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
                    evidence=desc[max(0, m.start() - 30) : m.end() + 50].strip(),
                )
            )
            break  # one finding per tool
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
    from classifier import classify_server  # local to avoid import cost on every call

    server_class = classify_server(
        [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema or {},
            }
            for t in tools
        ]
    )

    findings: list[Finding] = []
    for combo in server_class.overbroad_combinations:
        first_name = combo.tools[0] if combo.tools else None
        first_tool = next((t for t in tools if t.name == first_name), None)
        findings.append(
            Finding(
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
            )
        )
    return findings


# ---------------------------------------------------------------------------
# MCP-S-011 — Sensitive data logged to stderr/stdout
# ---------------------------------------------------------------------------

# Log-call shapes. The rule flags any call whose function matches one of
# these AND whose arguments reference a sensitive-shaped name.
_LOG_BARE_FUNCS = {"print"}
_LOG_METHOD_NAMES = {
    "info",
    "debug",
    "warning",
    "warn",
    "error",
    "critical",
    "exception",
    "log",
    # sys.stderr.write / sys.stdout.write — caught via a separate path below.
}
_STD_STREAMS = {"stderr", "stdout"}

# Names that suggest sensitive payload content. Matched case-insensitively
# as whole words against argument identifiers and attribute names.
# Calibration-driven; pulled from real MCP server source review:
# - `request` / `req` — full HTTP request objects
# - `header(s)` — auth headers, cookies, bearer tokens
# - `token`, `auth`, `bearer`, `credential`, `cred` — credentials
# - `secret`, `key`, `api_key`, `apikey` — secrets
# - `password`, `passwd`, `pwd` — passwords
# - `cookie`, `session` — session material
_SENSITIVE_NAME_RE = re.compile(
    r"(?:^|_)(?:"
    r"request|req|header|headers|"
    r"auth|token|bearer|credential|cred|"
    r"secret|key|apikey|api_key|"
    r"password|passwd|pwd|"
    r"cookie|session"
    r")(?:_|$)",
    re.IGNORECASE,
)

# Conditional-test phrases that indicate debug-gated logging. When a log
# call lives inside `if debug:` / `if verbose:` / `if TRACE:` / etc., the
# rule suppresses the finding — the maintainer has explicitly gated it.
_DEBUG_GATE_RE = re.compile(r"\b(?:debug|verbose|trace)\b", re.IGNORECASE)


def check_sensitive_logging(tool: DiscoveredTool) -> list[Finding]:
    """MCP-S-011 — Tool/request data logged to stderr.

    MCP servers running via stdio have their stderr captured by the host
    process and frequently surfaced to the end user or written to host
    logs. Anything sensitive logged at INFO/DEBUG/ERROR level — request
    payloads, auth headers, env-var-derived secrets — is therefore
    user-visible or persisted.

    Detection: per-tool AST scan for log-shaped calls (`print`,
    `logging.X`, `logger.X`, `sys.stderr.write`, `console.error`) whose
    arguments reference (a) a tool parameter, (b) a sensitive-named
    identifier, or (c) `os.environ[...]` / `os.getenv(...)`. Calls inside
    `if debug:` / `if verbose:` blocks are skipped — that's the
    documented opt-in shape.
    """
    fn = tool.function_node
    if fn is None:
        return []
    gated_lines = _collect_debug_gated_lines(fn)

    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if not _is_log_call(node):
            continue
        if node.lineno in gated_lines or node.lineno in seen_lines:
            continue

        sensitive_signals = _collect_sensitive_signals(node, tool.parameters)
        if not sensitive_signals:
            continue

        seen_lines.add(node.lineno)
        findings.append(
            Finding(
                rule_id="MCP-S-011",
                severity="medium",
                category="tool.sensitive_logging",
                file=tool.source_path,
                line=node.lineno,
                tool_name=tool.name,
                message=(
                    f"Tool logs potentially sensitive data ({', '.join(sensitive_signals)}). "
                    f"MCP hosts typically capture stderr and may surface or persist it."
                ),
                evidence=_safe_unparse(node),
            )
        )
    return findings


def _is_log_call(call: ast.Call) -> bool:
    f = call.func
    if isinstance(f, ast.Name) and f.id in _LOG_BARE_FUNCS:
        return True
    if isinstance(f, ast.Attribute):
        # logging.info / logger.debug / log.error / console.error
        if f.attr in _LOG_METHOD_NAMES:
            return True
        # sys.stderr.write(...) / sys.stdout.write(...)
        if f.attr == "write" and isinstance(f.value, ast.Attribute):
            if f.value.attr in _STD_STREAMS:
                return True
    return False


def _collect_sensitive_signals(call: ast.Call, tool_params: list[str]) -> list[str]:
    """Return human-readable signal labels for a log call's args, or [].

    Distinguishes three categories so the finding message tells the
    auditor *what* triggered it: tool parameter, sensitive-named
    identifier, or environment-variable access.
    """
    signals: list[str] = []
    seen: set[str] = set()
    arg_nodes = list(call.args) + [kw.value for kw in call.keywords]

    for arg in arg_nodes:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Name):
                ident = sub.id
                if ident in tool_params and f"param:{ident}" not in seen:
                    signals.append(f"param:{ident}")
                    seen.add(f"param:{ident}")
                elif _SENSITIVE_NAME_RE.search(ident) and f"name:{ident}" not in seen:
                    signals.append(f"name:{ident}")
                    seen.add(f"name:{ident}")
            elif isinstance(sub, ast.Attribute):
                # request.headers, req.body, ctx.session, etc.
                if _SENSITIVE_NAME_RE.search(sub.attr) and f"attr:{sub.attr}" not in seen:
                    signals.append(f"attr:{sub.attr}")
                    seen.add(f"attr:{sub.attr}")
            elif isinstance(sub, ast.Subscript):
                # os.environ["..."] — flag as env access
                v = sub.value
                if isinstance(v, ast.Attribute) and v.attr == "environ":
                    if "env:os.environ" not in seen:
                        signals.append("env:os.environ")
                        seen.add("env:os.environ")
            elif isinstance(sub, ast.Call):
                f = sub.func
                if isinstance(f, ast.Attribute) and f.attr == "getenv":
                    if "env:os.getenv" not in seen:
                        signals.append("env:os.getenv")
                        seen.add("env:os.getenv")
    return signals


def _collect_debug_gated_lines(fn) -> set[int]:
    """Line numbers inside an `if <debug-shaped>:` body.

    Only the body branch is considered gated. The `else` branch is the
    production path and any log calls there still fire.
    """
    lines: set[int] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        try:
            test_src = ast.unparse(node.test)
        except Exception:  # noqa: BLE001
            continue
        if not _DEBUG_GATE_RE.search(test_src):
            continue
        for stmt in node.body:
            for child in ast.walk(stmt):
                if hasattr(child, "lineno"):
                    lines.add(child.lineno)
    return lines


# ---------------------------------------------------------------------------
# MCP-S-010 — Hardcoded secrets and committed .env files
# ---------------------------------------------------------------------------

# Named-format secrets only. Generic high-entropy detection (any string with
# Shannon entropy > N) is too FP-heavy without per-codebase tuning — every
# hash, UUID, and base64-encoded fingerprint trips it. The named patterns
# below are the ones maintainers actually leak: API keys, OAuth tokens,
# Stripe live keys, PEM private keys, JWTs.
# Order matters: more specific patterns must precede broader ones, because
# `check_hardcoded_secrets` breaks on the first match per line. The OpenAI
# pattern is intentionally broad (their key format has changed several
# times); anthropic / stripe / slack must appear first so their tokens
# aren't swallowed by it.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat_classic", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_pat_fine", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("github_oauth_token", re.compile(r"\bgh[ous]_[A-Za-z0-9]{36}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-(?:api|admin)\d*-[A-Za-z0-9_-]{20,}\b")),
    ("stripe_live_secret", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b")),
    ("slack_bot_token", re.compile(r"\bxox[bpaer]-[A-Za-z0-9-]{20,}\b")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "private_key_pem",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
]

# Extensions worth scanning for secrets. Skip binary formats, images,
# lockfiles, vendored bundles. The list intentionally errs on the side of
# scanning more text formats — false positives are cheap, false negatives
# are how secrets leak.
_SECRET_SCAN_EXTS = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".txt",
        ".md",
        ".cfg",
        ".ini",
        ".env",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".rs",
        ".go",
        ".rb",
        ".java",
        ".kt",
        ".scala",
        ".php",
        ".c",
        ".h",
        ".cpp",
        ".cs",
    }
)

# Cap individual file scan size — lockfiles, vendored bundles, generated
# code aren't where committed secrets live, and reading them slows scans.
_SECRET_LARGEST_FILE = 1024 * 1024  # 1 MiB
_SECRET_LONGEST_LINE = 1000  # skip minified content

# `.env` files commonly hold credentials. Flag presence in source tree.
# Sample/example/template variants are the documented-safe convention.
_DOTENV_RE = re.compile(r"^\.env(\..+)?$")
_DOTENV_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")

# Path-glob allowlist file at the scan root. One pattern per line, `#`
# comments ignored. Used to suppress known-safe matches without disabling
# the rule.
_SECRET_ALLOWLIST_FILENAME = ".mcpsentry-allowlist"


def check_hardcoded_secrets(root: Path) -> list[Finding]:
    """MCP-S-010 — committed secrets and `.env` files in the source tree.

    Scans for:
    1. Named-format secret strings (AWS, GitHub, OpenAI, Anthropic, Stripe,
       Slack, Google API, PEM private keys, JWTs).
    2. Presence of `.env*` files in the tree, excluding documented-safe
       variants (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`).

    Necessary-but-not-sufficient: a hit on a fixture file is a finding the
    auditor confirms by reading the file. Suppress known-safe matches by
    listing path globs in `.mcpsentry-allowlist` at the scan root.
    """
    findings: list[Finding] = []
    allowlist = _load_secret_allowlist(root)

    for f in _walk_repo_files(root):
        rel = _relpath(f, root)
        if _is_allowlisted(rel, allowlist):
            continue

        # .env-style files: flag presence (don't scan content — would
        # double-report every secret inside).
        if _DOTENV_RE.match(f.name) and not f.name.endswith(_DOTENV_SAFE_SUFFIXES):
            findings.append(
                Finding(
                    rule_id="MCP-S-010",
                    severity="high",
                    category="secret.dotenv_committed",
                    file=rel,
                    line=0,
                    tool_name="<repo>",
                    message=(
                        f"Environment file {f.name!r} present in source tree. "
                        f"`.env*` files commonly hold credentials — confirm "
                        f".gitignore covers it and it was never committed."
                    ),
                    evidence="",
                )
            )
            continue

        if f.suffix.lower() not in _SECRET_SCAN_EXTS:
            continue
        try:
            if f.stat().st_size > _SECRET_LARGEST_FILE:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > _SECRET_LONGEST_LINE:
                continue
            for kind, pat in _SECRET_PATTERNS:
                m = pat.search(line)
                if m is None:
                    continue
                tok = m.group(0)
                findings.append(
                    Finding(
                        rule_id="MCP-S-010",
                        severity="high",
                        category=f"secret.{kind}",
                        file=rel,
                        line=lineno,
                        tool_name="<repo>",
                        message=f"Possible {kind.replace('_', ' ')} hardcoded in source.",
                        evidence=_redact_secret(tok),
                    )
                )
                break  # one finding per line — first match wins

    return findings


def _walk_repo_files(root: Path):
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    for f in root.rglob("*"):
        # Check skip fragments against the path RELATIVE to root, so that
        # scanning a directory that itself lives inside e.g. /site-packages/
        # doesn't drop every file. The original substring-on-absolute-path
        # check broke when the scan root was rooted inside one of the
        # skip dirs (e.g. `mcpsentry-audit` pointing at an installed
        # package under /opt/anaconda3/lib/.../site-packages/<pkg>/).
        try:
            rel = "/" + str(f.relative_to(root)) + "/"
        except ValueError:
            rel = str(f)
        if any(frag in rel for frag in _SKIP_FRAGMENTS):
            continue
        if f.is_file():
            yield f


def _relpath(f: Path, root: Path) -> str:
    # Directory scan: paths reported relative to the scan root.
    # Single-file scan: report the path as given so REPO_RULES findings
    # match per-tool findings (which use `discover_tools_in_path`'s string
    # form of the user-supplied path).
    if root.is_dir():
        try:
            return str(f.relative_to(root))
        except ValueError:
            return str(f)
    return str(f)


def _load_secret_allowlist(root: Path) -> list[str]:
    base = root if root.is_dir() else root.parent
    p = base / _SECRET_ALLOWLIST_FILENAME
    if not p.exists():
        return []
    return [
        ln.strip()
        for ln in p.read_text().splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]


def _is_allowlisted(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in patterns)


def _redact_secret(tok: str) -> str:
    if len(tok) <= 8:
        return "***"
    return f"{tok[:4]}...{tok[-4:]}"


# ---------------------------------------------------------------------------
# MCP-S-014 — HTTP transport missing Origin/Host validation (DNS rebinding)
# ---------------------------------------------------------------------------

# Hosts whose binding makes the server reachable from the local browser
# context and therefore exploitable via DNS rebinding if Origin is not
# checked. `0.0.0.0` is the most dangerous (all interfaces), but loopback
# is also rebindable from the browser's perspective: an attacker-controlled
# domain that resolves to 127.0.0.1 after a TTL flip can issue requests.
_REBINDABLE_HOSTS = {
    "0.0.0.0",
    "127.0.0.1",
    "localhost",
    "::",
    "::1",
    "[::]",
    "[::1]",
}

_HOST_KW_NAMES = ("host", "bind", "address", "hostname")

# Bare `run` / `serve` without a module prefix is too ambiguous to act on
# (could be any user-defined function), so we require an attribute call.
# v0.3 (W3): added `run_app` and `TCPSite` so aiohttp.web bind shapes are
# recognized — previously `web.run_app(app, host=...)` and
# `web.TCPSite(runner, host, port)` slipped through the detector.
_SERVER_BIND_METHODS = {"run", "serve", "run_sync", "run_app", "TCPSite"}

# Owners we *do not* want to confuse with HTTP server binds. `asyncio.run`
# wraps a coroutine, not a server start.
_NOT_SERVER_BIND_OWNERS = {"asyncio", "trio", "anyio"}


def check_transport_origin_validation(root: Path) -> list[Finding]:
    """MCP-S-014 — HTTP transport without Origin/Host validation.

    MCP servers using SSE or Streamable HTTP transports are typically run
    behind a Starlette/FastAPI app via `uvicorn.run(...)`. When the bind
    address is loopback/`0.0.0.0` AND no middleware inspects the Origin
    header, the server is exploitable via DNS rebinding — a browser
    visiting an attacker-controlled domain can issue requests to the
    local MCP endpoint as if it were same-origin.

    Heuristic (necessary, not sufficient): for each .py file with a
    rebindable-host server bind, flag if the file contains no mention of
    "origin" (case-insensitive). Also flag the CORS wildcard-with-
    credentials antipattern regardless of bind host.
    """
    findings: list[Finding] = []
    for f in _walk_repo_files(root):
        if f.suffix != ".py":
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue

        rel = _relpath(f, root)
        binds = _find_rebindable_binds(tree)
        # v0.3 (W2): require actual Origin-reading code in the AST rather
        # than any case-insensitive "origin" substring. Comments like
        # `# CORS is handled by Traefik` and response-header strings like
        # `"Access-Control-Allow-Origin": "*"` no longer suppress the rule.
        validates_origin = _file_validates_origin(tree)

        if binds and not validates_origin:
            for bind_node, host_value in binds:
                findings.append(
                    Finding(
                        rule_id="MCP-S-014",
                        severity="high",
                        category="transport.origin_unchecked",
                        file=rel,
                        line=bind_node.lineno,
                        tool_name="<transport>",
                        message=(
                            f"HTTP transport binds to {host_value!r} but the source "
                            f"file contains no reference to 'Origin' header "
                            f"validation. Local MCP servers bound to loopback / "
                            f"0.0.0.0 are exploitable via DNS rebinding when "
                            f"Origin is not checked."
                        ),
                        evidence=_safe_unparse(bind_node)[:160],
                    )
                )

        # Wildcard CORS + credentials is wrong independent of bind host.
        for cors_node in _find_cors_wildcard_with_credentials(tree):
            findings.append(
                Finding(
                    rule_id="MCP-S-014",
                    severity="high",
                    category="transport.cors_wildcard_credentials",
                    file=rel,
                    line=cors_node.lineno,
                    tool_name="<transport>",
                    message=(
                        "CORS middleware combines allow_origins=['*'] with "
                        "allow_credentials=True. Browsers reject this "
                        "combination at runtime, but the intent suggests "
                        "credentialed cross-origin access — either restrict "
                        "origins to an explicit allowlist or remove credentials."
                    ),
                    evidence=_safe_unparse(cors_node)[:160],
                )
            )
    return findings


def _find_rebindable_binds(tree: ast.AST) -> list[tuple[ast.Call, str]]:
    # v0.3 (W1): pre-collect file-wide string bindings (assignments + function
    # param defaults) so `uvicorn.run(app, host=host)` where `host` is bound
    # earlier to "0.0.0.0" gets resolved. File-wide flat scope is a
    # deliberate heuristic — the rule is "review this" not "definitely vuln".
    bindings = _collect_string_bindings(tree)
    out: list[tuple[ast.Call, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_server_bind_call(node):
            continue
        host = _extract_host_value(node, bindings)
        if host is None:
            continue
        if host.lower() in _REBINDABLE_HOSTS:
            out.append((node, host))
    return out


def _collect_string_bindings(tree: ast.AST) -> dict[str, str]:
    """Map name → string-literal value for module/function-local assignments
    and function parameter defaults. Used by `_extract_host_value` to
    resolve `host=host_var` patterns where `host_var` was bound to a
    literal somewhere in the same file.

    Heuristic — file-wide flat scope, no lexical-scope precision. The risk
    is FPs when the same name binds differently in different scopes; for
    a "review this" static rule this is acceptable.
    """
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        # `foo = "value"` (assume single-target literal-string assignment).
        # Also (v0.3 W4) `foo = os.getenv("X", "default")` and
        # `foo = os.environ.get("X", "default")` — resolve to the default
        # since that's what the production runtime sees when the env var
        # is unset, which is the common case for "the package shipped a
        # default that's the actual deployed value".
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                val = node.value
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    bindings[node.targets[0].id] = val.value
                elif isinstance(val, ast.Call):
                    env_default = _extract_env_default(val)
                    if env_default is not None:
                        bindings[node.targets[0].id] = env_default
        # `def f(host="0.0.0.0", ...)` — positional defaults + kw-only defaults.
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            args = node.args
            n_def = len(args.defaults)
            if n_def > 0:
                for arg, dflt in zip(args.args[-n_def:], args.defaults, strict=False):
                    if isinstance(dflt, ast.Constant) and isinstance(dflt.value, str):
                        bindings[arg.arg] = dflt.value
            for arg, dflt in zip(args.kwonlyargs, args.kw_defaults, strict=False):
                if dflt is None:
                    continue
                if isinstance(dflt, ast.Constant) and isinstance(dflt.value, str):
                    bindings[arg.arg] = dflt.value
    return bindings


def _is_server_bind_call(call: ast.Call) -> bool:
    f = call.func
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr not in _SERVER_BIND_METHODS:
        return False
    if isinstance(f.value, ast.Name) and f.value.id in _NOT_SERVER_BIND_OWNERS:
        return False
    return True


def _extract_env_default(call: ast.Call) -> str | None:
    """If `call` is `os.getenv("X", "default")` or
    `os.environ.get("X", "default")` with a string-literal default,
    return that default. v0.3 (W4).

    Returns None for one-arg getenv (no default) and for non-string
    defaults. The surveyed evidence (mcp-fetch-streamablehttp-server) shows
    `host = os.getenv("HOST", "0.0.0.0")` is the common shape where the
    documented default IS the deployed bind in practice.
    """
    f = call.func
    if not isinstance(f, ast.Attribute):
        return None

    # os.getenv("X", "default")
    if isinstance(f.value, ast.Name) and f.value.id == "os" and f.attr == "getenv":
        # Positional default (2nd arg)
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            if isinstance(call.args[1].value, str):
                return call.args[1].value
        # Keyword default
        for kw in call.keywords:
            if kw.arg == "default" and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, str):
                    return kw.value.value
        return None

    # os.environ.get("X", "default")
    if (
        f.attr == "get"
        and isinstance(f.value, ast.Attribute)
        and f.value.attr == "environ"
        and isinstance(f.value.value, ast.Name)
        and f.value.value.id == "os"
    ):
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            if isinstance(call.args[1].value, str):
                return call.args[1].value
        return None

    return None


def _extract_host_value(call: ast.Call, bindings: dict[str, str] | None = None) -> str | None:
    """Extract the host string from a server-bind call.

    Handles literal strings directly, and resolves `ast.Name` arguments via
    the `bindings` map (collected by `_collect_string_bindings`). v0.3 (W1).
    """
    bindings = bindings or {}

    def _resolve(v: ast.expr) -> str | None:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            return v.value
        if isinstance(v, ast.Name) and v.id in bindings:
            return bindings[v.id]
        return None

    for kw in call.keywords:
        if kw.arg in _HOST_KW_NAMES:
            r = _resolve(kw.value)
            if r is not None:
                return r
    # Common positional form: uvicorn.run(app, "0.0.0.0", 3000) / web.TCPSite(runner, host, port)
    if len(call.args) >= 2:
        r = _resolve(call.args[1])
        if r is not None:
            return r
    return None


def _file_validates_origin(tree: ast.AST) -> bool:
    """True if the file's AST contains code that actually reads the Origin
    request header — `.headers["Origin"]` / `.headers["origin"]` or
    `.headers.get("Origin", ...)` style. v0.3 (W2).

    Designed to NOT match:
    - Comments mentioning Origin (e.g. `# CORS handled by Traefik`)
    - Response-header strings (e.g. `"Access-Control-Allow-Origin": "*"`)
    - Docstrings or module-level descriptions

    Those would all previously have silenced the rule under the old
    case-insensitive substring check.
    """
    for node in ast.walk(tree):
        # `something.headers["Origin"]` — subscript access
        if isinstance(node, ast.Subscript):
            v = node.value
            if isinstance(v, ast.Attribute) and v.attr == "headers":
                slc = node.slice
                if isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                    if slc.value.lower() == "origin":
                        return True
        # `something.headers.get("Origin", ...)` — method call
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "get":
                v = f.value
                if isinstance(v, ast.Attribute) and v.attr == "headers":
                    if node.args and isinstance(node.args[0], ast.Constant):
                        first = node.args[0].value
                        if isinstance(first, str) and first.lower() == "origin":
                            return True
    return False


def _find_cors_wildcard_with_credentials(tree: ast.AST) -> list[ast.Call]:
    """Calls that configure CORS with allow_origins=['*'] + allow_credentials=True."""
    out: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _looks_like_cors_setup(node):
            continue
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        ao, ac = kwargs.get("allow_origins"), kwargs.get("allow_credentials")
        if ao is None or ac is None:
            continue
        if not (isinstance(ac, ast.Constant) and ac.value is True):
            continue
        if not isinstance(ao, ast.List):
            continue
        if not any(isinstance(e, ast.Constant) and e.value == "*" for e in ao.elts):
            continue
        out.append(node)
    return out


def _looks_like_cors_setup(call: ast.Call) -> bool:
    f = call.func
    if isinstance(f, ast.Name) and f.id == "CORSMiddleware":
        return True
    if isinstance(f, ast.Attribute) and f.attr == "add_middleware":
        if call.args and isinstance(call.args[0], ast.Name):
            return call.args[0].id == "CORSMiddleware"
    return False


# ---------------------------------------------------------------------------
# MCP-S-012 — Roots capability declared but never consulted
# ---------------------------------------------------------------------------

# In the MCP Python SDK, `RootsCapability` is the named constructor a
# server uses to express it cares about (client-declared) roots; the
# server then enforces containment by calling `list_roots()` on the
# session and constraining filesystem paths to the returned set. A
# declaration without any `list_roots()` call means the server claims
# roots awareness but doesn't act on it.
_ROOTS_CAP_NAME = "RootsCapability"
_ROOTS_CONSULT_NAME = "list_roots"


def check_roots_declared_but_unused(root: Path) -> list[Finding]:
    """MCP-S-012 — `RootsCapability` referenced but `list_roots()` never called.

    Server-side, supporting the MCP `roots` capability is a two-step
    contract: declare you respect roots (via `RootsCapability` or an
    equivalent dict shape), and consult them at request time (via
    `session.list_roots()`). Code that does the first but not the second
    is either an oversight or a misleading capability advertisement —
    filesystem operations escape whatever scope the client thinks it
    declared.

    Detection (v0.1, narrow): cross-file scan. Collect every
    `RootsCapability(...)` constructor call as a declaration site, and
    every `list_roots()` call as a consultation. If any declarations
    exist and zero consultations exist, flag each declaration site. Dict
    literal forms (`{"roots": ...}`) and TS equivalents are out of scope
    for v0.1 — calibration data will guide expansion.
    """
    declared: list[tuple[str, int, str]] = []
    consulted = False

    for f in _walk_repo_files(root):
        if f.suffix != ".py":
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue

        rel = _relpath(f, root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _callable_simple_name(node.func)
            if name == _ROOTS_CAP_NAME:
                declared.append((rel, node.lineno, _safe_unparse(node)))
            elif name == _ROOTS_CONSULT_NAME:
                consulted = True

    if not declared or consulted:
        return []
    return [
        Finding(
            rule_id="MCP-S-012",
            severity="medium",
            category="capability.roots_declared_unused",
            file=rel,
            line=lineno,
            tool_name="<server>",
            message=(
                "Server references the `roots` capability but the source "
                "tree contains no call to `list_roots()`. Either consult "
                "roots when handling filesystem operations or drop the "
                "capability declaration — currently it advertises a "
                "containment guarantee that isn't enforced."
            ),
            evidence=ev[:160],
        )
        for rel, lineno, ev in declared
    ]


def _callable_simple_name(fn) -> str | None:
    """Return the simple name of a callable AST node (Name or Attribute)."""
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


# ---------------------------------------------------------------------------
# MCP-S-013 — Prompt template interpolation without sanitization
# ---------------------------------------------------------------------------

# Message-constructor names recognized by the rule. Covers the official
# MCP Python SDK (`PromptMessage`) plus the role-typed helpers some
# servers wrap around it.
_PROMPT_MSG_CTOR_NAMES = {
    "PromptMessage",
    "Message",
    "SystemMessage",
    "UserMessage",
    "AssistantMessage",
}

# Content-wrapping constructors. We unwrap one level of these so an
# interpolated f-string inside `TextContent(text=...)` is still seen.
_CONTENT_WRAPPER_CTOR_NAMES = {
    "TextContent",
    "ImageContent",
    "AudioContent",
    "EmbeddedResource",
}

# Roles that warrant a finding. `user` is intentionally excluded: every
# real-world prompt server interpolates user input into user-role
# messages — flagging that drowns the signal. System and assistant
# messages are the high-stakes injection targets (the model treats their
# content as authority).
_FLAGGED_PROMPT_ROLES = {"system", "assistant"}


def check_prompt_injection(root: Path) -> list[Finding]:
    """MCP-S-013 — User-controlled prompt arguments reach a system/assistant
    message via unescaped interpolation.

    Scans every Python file for functions decorated `@<x>.prompt()`. For
    each, inspects message constructors (`PromptMessage`, `Message`, role-
    typed helpers) and dict-literal messages (`{"role": ..., "content":
    ...}`). If the content is built by interpolating one of the prompt
    function's parameters (f-string, `.format`, `%`, or `+` concat), and
    the message role is `system` or `assistant`, emit a high-severity
    finding. Unknown/dynamic roles emit medium. User-role interpolation
    is silenced — too conventional to be useful signal.

    v0.1 limitations: no sanitizer/allowlist recognition (every flagged
    interpolation is reported; auditors confirm by reading code). One
    level of content-wrapper unwrapping (`TextContent(text=...)`) — deeper
    nesting is rare in practice.
    """
    findings: list[Finding] = []
    for f in _walk_repo_files(root):
        if f.suffix != ".py":
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue

        rel = _relpath(f, root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not any(_is_prompt_decorator(d) for d in node.decorator_list):
                continue
            findings.extend(_scan_prompt_handler(node, rel))
    return findings


def _is_prompt_decorator(dec: ast.expr) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr == "prompt"
    if isinstance(target, ast.Name):
        return target.id == "prompt"
    return False


def _scan_prompt_handler(fn: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[Finding]:
    params = [a.arg for a in fn.args.args if a.arg != "self"]
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for node in ast.walk(fn):
        role: str | None = None
        content_node: ast.expr | None = None
        report_line: int = 0

        if isinstance(node, ast.Call):
            name = _callable_simple_name(node.func)
            if name not in _PROMPT_MSG_CTOR_NAMES:
                continue
            kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            role_node = kwargs.get("role")
            content_node = kwargs.get("content")
            role = _extract_role_constant(role_node) or _role_from_ctor_name(name)
            report_line = node.lineno
        elif isinstance(node, ast.Dict):
            if not _looks_like_message_dict(node):
                continue
            role, content_node = _extract_dict_message(node)
            report_line = node.lineno
        else:
            continue

        if content_node is None:
            continue
        if role == "user":
            continue

        interpolated = _find_interpolated_params(content_node, params)
        if not interpolated:
            continue
        if report_line in seen_lines:
            continue
        seen_lines.add(report_line)

        severity = "high" if role in _FLAGGED_PROMPT_ROLES else "medium"
        role_desc = role if role else "<dynamic-or-unknown>"
        findings.append(
            Finding(
                rule_id="MCP-S-013",
                severity=severity,
                category="prompt.template_injection",
                file=rel,
                line=report_line,
                tool_name=fn.name,
                message=(
                    f"Prompt {role_desc!r}-role message interpolates parameter(s) "
                    f"{interpolated!r} without sanitization. User-controlled text "
                    f"reaches a message the model treats as authority — verify "
                    f"that input is escaped or restricted before this call."
                ),
                evidence=_safe_unparse(node)[:160],
            )
        )
    return findings


def _looks_like_message_dict(d: ast.Dict) -> bool:
    keys = {k.value for k in d.keys if isinstance(k, ast.Constant)}
    return "role" in keys and "content" in keys


def _extract_dict_message(d: ast.Dict) -> tuple[str | None, ast.expr | None]:
    role: str | None = None
    content: ast.expr | None = None
    for k, v in zip(d.keys, d.values, strict=False):
        if not isinstance(k, ast.Constant):
            continue
        if k.value == "role":
            role = _extract_role_constant(v)
        elif k.value == "content":
            content = v
    return role, content


def _extract_role_constant(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower()
    return None


def _role_from_ctor_name(name: str) -> str | None:
    if name == "SystemMessage":
        return "system"
    if name == "UserMessage":
        return "user"
    if name == "AssistantMessage":
        return "assistant"
    return None


def _find_interpolated_params(content: ast.expr, params: list[str]) -> list[str]:
    """Return ordered, deduplicated param names that flow into `content`.

    Recognizes: f-strings, `.format(...)`, `%`-format, `+`-concat. Unwraps
    one layer of MCP content wrappers (`TextContent(text=...)` etc.).
    """
    # Unwrap content-wrapper constructors one level.
    if isinstance(content, ast.Call):
        name = _callable_simple_name(content.func)
        if name in _CONTENT_WRAPPER_CTOR_NAMES:
            kwargs = {kw.arg: kw.value for kw in content.keywords if kw.arg}
            inner = kwargs.get("text") or kwargs.get("data")
            if inner is not None:
                return _find_interpolated_params(inner, params)
        if isinstance(content.func, ast.Attribute) and content.func.attr == "format":
            return _names_in_subtree(content, params)

    if isinstance(content, ast.JoinedStr):
        # f-string: scan the FormattedValue children only — string parts
        # are constants and can't carry param refs.
        found: list[str] = []
        for v in content.values:
            if isinstance(v, ast.FormattedValue):
                for sub in ast.walk(v.value):
                    if isinstance(sub, ast.Name) and sub.id in params:
                        found.append(sub.id)
        return list(dict.fromkeys(found))

    if isinstance(content, ast.BinOp) and isinstance(content.op, ast.Mod):
        return _names_in_subtree(content.right, params)

    if isinstance(content, ast.BinOp) and isinstance(content.op, ast.Add):
        return _names_in_subtree(content, params)

    return []


def _names_in_subtree(node: ast.AST, params: list[str]) -> list[str]:
    found: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in params:
            found.append(sub.id)
    return list(dict.fromkeys(found))


# ---------------------------------------------------------------------------
# Rule registries — iterated by the analyzer driver in analyze.py.
# ---------------------------------------------------------------------------

# Per-tool rules.
RULES: list[Callable[[DiscoveredTool], list[Finding]]] = [
    check_description_injection,
    check_schema_field_injection,
    check_annotation_lying,
    check_url_fetch_unrestricted,
    check_sql_injection_unrestricted,
    check_path_traversal,
    check_command_injection,
    check_sensitive_logging,
]

# Server-level rules — operate on the full tool set, not one tool at a time.
SERVER_RULES: list[Callable[[list[DiscoveredTool]], list[Finding]]] = [
    check_cross_tool_references,
    check_overbroad_capability_surface,
]

# Repo-level rules — operate on the scan root path. Used for findings that
# don't fit per-tool or per-server shapes: committed secrets, transport
# configuration, server-init code outside tool handlers.
REPO_RULES: list[Callable[[Path], list[Finding]]] = [
    check_hardcoded_secrets,
    check_transport_origin_validation,
    check_roots_declared_but_unused,
    check_prompt_injection,
]
