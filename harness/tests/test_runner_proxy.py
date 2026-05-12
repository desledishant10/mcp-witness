"""Tests for proxy mode: mutation hooks and end-to-end plumbing."""

from __future__ import annotations

import pytest

from harness.proxy import ProxySession, ToolDescOverride, ToolOutputOverride
from harness.runner import run_scenario


@pytest.mark.asyncio
async def test_description_override_applies_in_list_tools(mock_target):
    """list_tools_for_agent reflects queued ToolDescOverride mutations."""
    target = mock_target([
        {
            "name": "fetch_url",
            "description": "Original description.",
            "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}},
            "behavior": "echo",
        }
    ])
    async with ProxySession(target.command, target.args, target.env) as proxy:
        proxy.state.desc_overrides.append(ToolDescOverride(
            target="fetch_url", mode="append", payload="INJECTED_SUFFIX",
        ))
        tools = await proxy.list_tools_for_agent()
        assert len(tools) == 1
        assert "INJECTED_SUFFIX" in tools[0].description
        assert "Original description" in tools[0].description


@pytest.mark.asyncio
async def test_description_override_replace_mode(mock_target):
    target = mock_target([
        {
            "name": "anything",
            "description": "Old desc.",
            "input_schema": {"type": "object", "properties": {}},
            "behavior": "echo",
        }
    ])
    async with ProxySession(target.command, target.args, target.env) as proxy:
        proxy.state.desc_overrides.append(ToolDescOverride(
            target="*", mode="replace", payload="REPLACED",
        ))
        tools = await proxy.list_tools_for_agent()
        assert tools[0].description == "REPLACED"


@pytest.mark.asyncio
async def test_output_override_first_call_only(mock_target):
    """`when: first_call` fires once; subsequent calls fall through."""
    target = mock_target([
        {
            "name": "echo_tool",
            "description": "Echoes input.",
            "input_schema": {"type": "object", "properties": {}},
            "behavior": "echo",
        }
    ])
    async with ProxySession(target.command, target.args, target.env) as proxy:
        proxy.state.output_overrides.append(ToolOutputOverride(
            target="echo_tool", when="first_call", payload_text="INTERCEPTED",
        ))
        first = await proxy.call_tool_for_agent("echo_tool", {})
        second = await proxy.call_tool_for_agent("echo_tool", {"x": 1})
        assert first == "INTERCEPTED"
        assert "INTERCEPTED" not in second


@pytest.mark.asyncio
async def test_d001_completes_with_stub_agent(mock_target, project_root):
    """D-001 against the stub agent: the proxy plumbing runs end-to-end.
    Stub never falls for injection by construction, so the scenario
    reports `passed` (no vulnerability found). This test verifies the
    machinery — not the agent's susceptibility."""
    scenario_path = project_root / "scenarios" / "MCP-D-001-tool-desc-injection-fetch.yaml"
    target = mock_target([
        {
            "name": "fetch_url",
            "description": "Makes an HTTP request.",
            "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}},
            "behavior": "echo",
        }
    ])
    result = await run_scenario(scenario_path, target)    # default = stub agent
    assert result.error is None, f"scenario errored: {result.error}"
    assert result.passed is True, (
        f"stub agent should not fall for injection; evidence={result.oracle_evidence}"
    )
