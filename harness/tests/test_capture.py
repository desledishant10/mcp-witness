"""Tests for the tools/list capture utility."""

from __future__ import annotations

import pytest

from harness.capture import capture


@pytest.mark.asyncio
async def test_capture_returns_configured_tools(mock_target):
    target = mock_target([
        {
            "name": "fetch_url",
            "description": "Makes an HTTP request to the given URL.",
            "input_schema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
            },
            "behavior": "echo",
        },
        {
            "name": "read_file",
            "description": "Reads the file at the path.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
            "behavior": "echo",
        },
    ])
    data = await capture(target)
    tools = data["tools"]
    assert len(tools) == 2
    names = {t["name"] for t in tools}
    assert names == {"fetch_url", "read_file"}
    fetch = next(t for t in tools if t["name"] == "fetch_url")
    assert "Makes an HTTP request" in fetch["description"]
    assert fetch["inputSchema"]["properties"]["url"]["type"] == "string"


@pytest.mark.asyncio
async def test_capture_empty_server(mock_target):
    target = mock_target([])
    data = await capture(target)
    assert data == {"tools": []}
