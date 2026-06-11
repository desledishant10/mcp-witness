"""Tests for the mcpsentry-audit aggregate CLI."""

from __future__ import annotations

import pytest

from harness.audit import _format_text, audit_package


@pytest.mark.asyncio
async def test_audit_against_mock_server(mock_target):
    """End-to-end audit against the mock MCP server.

    Skips the pip install step (the mock isn't on PyPI) and passes the
    target launch command explicitly. Exercises capture + analyze +
    classify + report assembly.
    """
    target = mock_target(
        [
            {
                "name": "fetch_url",
                "description": "Makes an HTTP request to the given URL.",
                "input_schema": {
                    "type": "object",
                    "properties": {"url": {"type": "string", "format": "uri"}},
                },
                "behavior": "echo",
            },
            {
                "name": "read_file",
                "description": "Reads the contents of a file at the given path.",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
                "behavior": "echo",
            },
        ]
    )
    server_args = target.args
    server_cmd = target.command

    # audit_package uses os.environ for the subprocess by default, but the
    # mock server needs MCPSENTRY_MOCK_CONFIG which mock_target sets in
    # target.env. The current audit flow doesn't plumb env through to
    # capture — for this test, set it in os.environ via monkeypatch-style.
    import os

    saved = dict(os.environ)
    os.environ.update(target.env)
    try:
        report = await audit_package(
            package="mock-mcp-server",
            install=False,
            server_cmd=server_cmd,
            server_args=server_args,
        )
    finally:
        os.environ.clear()
        os.environ.update(saved)

    assert report["package"] == "mock-mcp-server"
    assert report["n_tools"] == 2
    assert set(report["tool_names"]) == {"fetch_url", "read_file"}
    # Classifier should pick up fs_read + net_egress
    assert "net_egress" in report["server_capability_set"]
    assert "fs_read" in report["server_capability_set"]
    # Overbroad combination: fs_read + net_egress = exfil_pair
    rationales = [c["rationale"] for c in report["overbroad_combinations"]]
    assert "exfil_pair" in rationales
    # Analyzer should fire S-009 on fetch_url (no allowlist) and S-005 server-level
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "MCP-S-009" in rule_ids
    assert "MCP-S-005" in rule_ids


def test_format_text_handles_clean_report():
    report = {
        "package": "test-pkg",
        "target_used": {"command": "python", "args": ["-m", "test_pkg"]},
        "capture_path": "/tmp/cap.json",
        "n_tools": 0,
        "tool_names": [],
        "server_capability_set": [],
        "overbroad_combinations": [],
        "findings": [],
    }
    text = _format_text(report)
    assert "test-pkg" in text
    assert "No analyzer findings." in text


def test_format_text_handles_findings():
    report = {
        "package": "test-pkg",
        "target_used": None,
        "capture_path": "/tmp/cap.json",
        "n_tools": 1,
        "tool_names": ["fetch"],
        "server_capability_set": ["net_egress"],
        "overbroad_combinations": [],
        "findings": [
            {
                "rule_id": "MCP-S-009",
                "severity": "high",
                "category": "tool.input.ssrf",
                "file": "<captured>",
                "line": 0,
                "tool_name": "fetch",
                "message": "Tool has URL parameter without allowlist.",
                "evidence": "url_params=['url']",
            }
        ],
    }
    text = _format_text(report)
    assert "1 analyzer finding" in text
    assert "MCP-S-009" in text
    assert "fetch" in text
