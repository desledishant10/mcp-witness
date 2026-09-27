"""Tests for the TypeScript source analyzer (Phase 1: S-006 + S-007).

Skipped entirely when the optional TS parser is not installed, so a bare `dev`
environment stays green; CI installs `mcp-witness[ts]`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_language_pack")

from analyzer.analyze import analyze_path  # noqa: E402
from analyzer.ts.analyze import analyze_ts_source  # noqa: E402
from analyzer.ts.discover import discover_tools_in_ts  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "example_server.ts"
TRANSPORT_FIXTURE = Path(__file__).parent / "fixtures" / "example_transport.ts"
PROMPT_FIXTURE = Path(__file__).parent / "fixtures" / "example_prompt.ts"
ROOTS_FIXTURE = Path(__file__).parent / "fixtures" / "example_roots.ts"


def _tools_for_rule(findings, rule_id):
    return {f.tool_name for f in findings if f.rule_id == rule_id}


def test_discovers_both_registration_forms():
    tools = {t.name for t in discover_tools_in_ts(FIXTURE.read_bytes(), str(FIXTURE), "typescript")}
    assert {"run_git", "read_doc", "list_root", "read_scoped"} <= tools


def test_command_injection_flagged_but_constant_command_clean():
    s007 = _tools_for_rule(analyze_path(FIXTURE), "MCP-S-007")
    assert "run_git" in s007
    assert "list_root" not in s007  # constant command, no tool input


def test_path_traversal_flagged_but_guarded_read_clean():
    s006 = _tools_for_rule(analyze_path(FIXTURE), "MCP-S-006")
    assert "read_doc" in s006
    assert "read_scoped" not in s006  # resolve + startsWith containment guard


def test_findings_match_the_python_rule_class():
    findings = analyze_path(FIXTURE)
    s007 = next(f for f in findings if f.rule_id == "MCP-S-007")
    assert s007.severity == "critical"
    assert s007.category == "tool.input.command_injection"
    assert s007.file.endswith("example_server.ts")
    assert s007.line > 0
    s006 = next(f for f in findings if f.rule_id == "MCP-S-006")
    assert s006.category == "tool.input.path_traversal"


def test_bare_imported_sink_and_javascript(tmp_path):
    # bare `execSync(...)` (imported, not child_process.execSync) in a .js file
    f = tmp_path / "srv.js"
    f.write_text(
        'server.tool("shell","d",{cmd:1}, async ({cmd}) => {'
        ' const { execSync } = require("child_process"); execSync("sh -c " + cmd); });'
    )
    assert any(x.rule_id == "MCP-S-007" and x.tool_name == "shell" for x in analyze_path(f))


def test_spawn_without_shell_is_not_flagged():
    src = (
        b'server.tool("t","d",{arg:1}, async ({arg}) => {'
        b' const cp = require("child_process"); cp.spawn("ls", [arg]); });'
    )
    assert not any(f.rule_id == "MCP-S-007" for f in analyze_ts_source(src, "t.ts", "typescript"))


def test_spawn_with_shell_true_and_input_is_flagged():
    src = (
        b'server.tool("t","d",{arg:1}, async ({arg}) => {'
        b' const cp = require("child_process"); cp.spawn("ls " + arg, { shell: true }); });'
    )
    assert any(f.rule_id == "MCP-S-007" for f in analyze_ts_source(src, "t.ts", "typescript"))


def test_no_tools_no_findings():
    assert analyze_ts_source(b"const x = 1;", "x.ts", "typescript") == []


# --- S-011 sensitive logging ------------------------------------------------
def test_sensitive_logging_flagged_but_debug_gated_clean():
    s011 = _tools_for_rule(analyze_path(FIXTURE), "MCP-S-011")
    assert "lookup" in s011  # logs a credential-shaped param
    assert "ping" not in s011  # log is debug-gated


def test_logging_flags_env_and_headers():
    src = (
        b'server.tool("t","d",{x:1}, async ({x}) => {'
        b' console.error("env", process.env.SECRET); logger.info(req.headers); });'
    )
    findings = analyze_ts_source(src, "t.ts", "typescript")
    assert sum(f.rule_id == "MCP-S-011" for f in findings) >= 1
    assert all(f.severity == "medium" for f in findings if f.rule_id == "MCP-S-011")


def test_logging_ignores_non_sensitive_and_non_log_calls():
    src = b'server.tool("t","d",{x:1}, async ({x}) => { console.log("temperature is 21C"); foo(x); });'
    assert not any(f.rule_id == "MCP-S-011" for f in analyze_ts_source(src, "t.ts", "typescript"))


# --- S-014 transport Origin/Host --------------------------------------------
def test_transport_origin_findings_and_safe_counterparts_clean():
    findings = [f for f in analyze_path(TRANSPORT_FIXTURE) if f.rule_id == "MCP-S-014"]
    cats = sorted(f.category for f in findings)
    assert cats == [
        "transport.cors_wildcard_credentials",
        "transport.origin_unchecked",
        "transport.origin_unchecked",
    ]
    assert all(f.severity == "high" and f.tool_name == "<transport>" for f in findings)
    # the safe transport (has protection) and safe cors (explicit origin) are not flagged
    assert not any("enableDnsRebindingProtection" in f.evidence for f in findings)
    assert not any("localhost:3000" in f.evidence for f in findings)


def test_transport_protection_and_header_read_suppress():
    src = (
        b'import {StreamableHTTPServerTransport} from "x";\n'
        b'const t = new StreamableHTTPServerTransport({ allowedHosts: ["127.0.0.1"] });\n'
        b'app.get("/", (req, res) => { const o = req.headers["origin"]; res.end(o); });\n'
        b'app.listen(3000, "0.0.0.0");\n'
    )
    assert not any(f.rule_id == "MCP-S-014" for f in analyze_ts_source(src, "t.ts", "typescript"))


def test_localhost_bind_not_flagged():
    src = b'app.listen(3000, "127.0.0.1");'
    assert not any(f.rule_id == "MCP-S-014" for f in analyze_ts_source(src, "t.ts", "typescript"))


# --- S-013 prompt template injection ----------------------------------------
def test_prompt_injection_flagged_system_only_once():
    findings = [f for f in analyze_path(PROMPT_FIXTURE) if f.rule_id == "MCP-S-013"]
    assert len(findings) == 1  # only the 'expert' system message; user-role + safe skipped
    finding = findings[0]
    assert finding.tool_name == "expert"
    assert finding.severity == "high"
    assert finding.category == "prompt.template_injection"


def test_prompt_concat_interpolation_into_assistant_is_high():
    src = (
        b'server.prompt("p", {name:1}, async ({name}) => ({ messages: ['
        b' { role: "assistant", content: "hi " + name } ] }));'
    )
    findings = analyze_ts_source(src, "p.ts", "typescript")
    assert any(f.rule_id == "MCP-S-013" and f.severity == "high" for f in findings)


def test_prompt_constant_and_user_role_not_flagged():
    src = (
        b'server.prompt("p", {name:1}, async ({name}) => ({ messages: ['
        b' { role: "system", content: "constant instructions" },'
        b' { role: "user", content: `hello ${name}` } ] }));'
    )
    assert not any(f.rule_id == "MCP-S-013" for f in analyze_ts_source(src, "p.ts", "typescript"))


# --- S-012 roots declared but unused ----------------------------------------
def test_roots_declared_unused_flagged():
    findings = [f for f in analyze_path(ROOTS_FIXTURE) if f.rule_id == "MCP-S-012"]
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].tool_name == "<server>"
    assert findings[0].category == "capability.roots_declared_unused"


def test_roots_consulted_not_flagged():
    src = b"const s = new Server({}, { capabilities: { roots: {} } }); s.listRoots();"
    assert not any(f.rule_id == "MCP-S-012" for f in analyze_ts_source(src, "s.ts", "typescript"))


def test_no_roots_capability_not_flagged():
    src = b"const s = new Server({}, { capabilities: { tools: {} } });"
    assert not any(f.rule_id == "MCP-S-012" for f in analyze_ts_source(src, "s.ts", "typescript"))
