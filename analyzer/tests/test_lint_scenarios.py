"""Tests for the scenario YAML linter."""

from __future__ import annotations

from pathlib import Path

from analyzer.lint_scenarios import lint_scenario

SCENARIOS_DIR = Path(__file__).parent.parent.parent / "scenarios"


def test_all_seed_scenarios_lint_clean():
    yaml_files = sorted(SCENARIOS_DIR.glob("MCP-D-*.yaml"))
    assert len(yaml_files) >= 5, f"expected at least 5 seed scenarios, found {len(yaml_files)}"
    for f in yaml_files:
        issues = lint_scenario(f)
        assert issues == [], f"{f.name}: {issues}"


def test_detects_embedded_null_byte(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(
        b"id: TEST\nname: t\ndescription: d\ncategory: tool.x\n"
        b'severity: low\nspec_versions: ["1"]\nattack: []\n'
        b"oracle: {}\nbad_field: a\x00b\n"
    )
    issues = lint_scenario(bad)
    assert any("non-printable" in i for i in issues), issues


def test_detects_invalid_yaml(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: TEST\nname: [unclosed")
    issues = lint_scenario(bad)
    assert any("YAML parse error" in i for i in issues), issues


def test_detects_schema_violation(tmp_path):
    """Missing required severity field should be caught."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "id: TEST\n"
        "name: t\n"
        "description: d\n"
        "category: tool.x\n"
        "spec_versions: ['1']\n"
        "attack: []\n"
        "oracle: {}\n"
    )
    issues = lint_scenario(bad)
    assert any("schema validation" in i for i in issues), issues


def test_passes_minimal_valid_scenario(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text(
        "id: TEST-001\n"
        "name: test scenario\n"
        "description: a description\n"
        "category: tool.description_injection\n"
        "severity: low\n"
        "spec_versions: ['2025-06-18']\n"
        "attack:\n"
        "  - step: tools_list\n"
        "oracle:\n"
        "  any_of: []\n"
    )
    issues = lint_scenario(good)
    assert issues == [], f"unexpected issues on minimal valid scenario: {issues}"
