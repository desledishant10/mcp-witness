"""End-to-end tests for direct-mode scenarios against the mock server."""

from __future__ import annotations

import pytest

from harness.runner import run_scenario


@pytest.mark.asyncio
async def test_d002_path_traversal_detected(mock_target, project_root):
    """MCP-D-002: mock server with a vulnerable file-read tool should
    be flagged. The canary file's content surfaces in the trace."""
    scenario_path = project_root / "scenarios" / "MCP-D-002-path-traversal-fs-tool.yaml"
    target = mock_target([
        {
            "name": "read_file",
            "description": "Reads the contents of a file at the given path.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            "behavior": "vulnerable_file_read",
        }
    ])
    result = await run_scenario(scenario_path, target)
    assert result.error is None, f"scenario errored: {result.error}"
    assert result.passed is False, (
        f"expected vuln detection, got passed=True; evidence={result.oracle_evidence}"
    )
    assert any("MCP_SCAN_CANARY_" in e for e in result.oracle_evidence), result.oracle_evidence


@pytest.mark.asyncio
async def test_d003_ssrf_detected(mock_target, project_root):
    """MCP-D-003: mock server with a vulnerable URL-fetch tool should
    be flagged. The canary endpoint records the fetch."""
    scenario_path = project_root / "scenarios" / "MCP-D-003-ssrf-url-fetcher.yaml"
    target = mock_target([
        {
            "name": "fetch_url",
            "description": "Makes an HTTP GET request to the given URL and returns the response body.",
            "input_schema": {
                "type": "object",
                "properties": {"url": {"type": "string", "format": "uri"}},
                "required": ["url"],
            },
            "behavior": "vulnerable_http_fetch",
        }
    ])
    result = await run_scenario(scenario_path, target)
    assert result.error is None, f"scenario errored: {result.error}"
    assert result.passed is False, (
        f"expected SSRF detection, got passed=True; evidence={result.oracle_evidence}"
    )
    assert any("canary_hit" in e for e in result.oracle_evidence), result.oracle_evidence


@pytest.mark.asyncio
async def test_d003_passes_when_no_net_egress_tool(mock_target, project_root):
    """A server with no net_egress-tagged tool should skip the scenario
    cleanly (no matching tools → no calls → oracle empty → passed)."""
    scenario_path = project_root / "scenarios" / "MCP-D-003-ssrf-url-fetcher.yaml"
    target = mock_target([
        {
            "name": "do_nothing",
            "description": "An inert tool with no capability signature.",
            "input_schema": {"type": "object", "properties": {}},
            "behavior": "fixed:nothing",
        }
    ])
    result = await run_scenario(scenario_path, target)
    assert result.error is None
    assert result.passed is True, f"expected no findings; evidence={result.oracle_evidence}"
