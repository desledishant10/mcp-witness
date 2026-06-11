"""Tests for the ground-truth scaffolder."""

from __future__ import annotations

import yaml

from calibration.scaffold import scaffold


def test_scaffold_produces_valid_gt_shape():
    captured = {
        "tools": [
            {
                "name": "tool_a",
                "description": "Does thing A.",
                "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
            }
        ]
    }
    gt = scaffold(
        captured,
        target_name="my-server",
        source="https://example.com",
        language="python",
    )
    assert gt["target_name"] == "my-server"
    assert gt["language"] == "python"
    assert gt["source"] == "https://example.com"
    assert len(gt["tools"]) == 1
    tool = gt["tools"][0]
    assert tool["name"] == "tool_a"
    assert tool["description"] == "Does thing A."
    assert tool["input_schema"]["properties"]["x"]["type"] == "string"
    # Hand-fill fields start empty.
    assert tool["capabilities"] == []
    assert tool["parameter_roles"] == {}
    assert tool["known_vulns"] == []


def test_scaffold_accepts_bare_list_input():
    captured = [{"name": "t", "description": "d", "inputSchema": {}}]
    gt = scaffold(captured, target_name="x")
    assert len(gt["tools"]) == 1
    assert gt["tools"][0]["name"] == "t"


def test_scaffold_handles_input_schema_alias():
    """`input_schema` (YAML) and `inputSchema` (JSON-RPC) should both work."""
    captured = {
        "tools": [
            {
                "name": "t1",
                "description": "",
                "inputSchema": {"type": "object", "properties": {"a": {}}},
            },
            {
                "name": "t2",
                "description": "",
                "input_schema": {"type": "object", "properties": {"b": {}}},
            },
        ]
    }
    gt = scaffold(captured, target_name="x")
    assert gt["tools"][0]["input_schema"]["properties"]["a"] == {}
    assert gt["tools"][1]["input_schema"]["properties"]["b"] == {}


def test_scaffold_round_trips_through_yaml():
    captured = {"tools": [{"name": "t", "description": "d", "inputSchema": {}}]}
    gt = scaffold(captured, target_name="t")
    text = yaml.dump(gt, sort_keys=False)
    parsed = yaml.safe_load(text)
    assert parsed["target_name"] == "t"
    assert parsed["tools"][0]["name"] == "t"


def test_scaffold_validates_against_scenario_like_consumers():
    """The scaffolded shape is consumed by the eval engine — ensure the
    top-level keys it expects are present."""
    gt = scaffold({"tools": []}, target_name="t")
    for key in (
        "target_name",
        "source",
        "language",
        "mcp_spec_version",
        "notes",
        "tools",
        "labeled",
    ):
        assert key in gt, f"missing key {key!r} in scaffold output"


def test_scaffold_marks_output_as_draft():
    """Scaffolds default to `labeled: false` so the eval skips them
    until the user has filled in the hand-label fields."""
    gt = scaffold({"tools": []}, target_name="t")
    assert gt["labeled"] is False
