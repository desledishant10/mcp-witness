"""Tests for the calibration eval engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from calibration.eval import evaluate_target, format_report_text

GT_PATH = Path(__file__).parent.parent / "ground_truth" / "example_server.yaml"


@pytest.fixture(scope="module")
def report():
    return evaluate_target(GT_PATH)


def test_eval_runs_and_returns_report(report):
    assert report.target_name == "example_server"
    assert report.n_tools == 9


def test_fs_read_has_meaningful_metrics(report):
    assert "fs_read" in report.by_tag
    m = report.by_tag["fs_read"]
    # The clear fs_read tools (path traversal × 2, safe path read) should be caught.
    assert m.true_pos >= 3, f"expected at least 3 TPs for fs_read, got {m}"


def test_exec_has_meaningful_metrics(report):
    assert "exec" in report.by_tag
    m = report.by_tag["exec"]
    # Clear exec tools (shell_true, os_system, os_popen) should be caught.
    assert m.true_pos >= 3, f"expected at least 3 TPs for exec, got {m}"


def test_param_role_accuracy_reported(report):
    assert report.param_role_total > 0
    assert report.param_role_correct >= report.param_role_total // 2


def test_no_high_severity_spurious_findings(report):
    """Sanity check: the safe tools and the normal greeting tool should
    not get *any* capability predictions outside their ground-truth set."""
    diff_by_tool = {d["tool"]: d for d in report.per_tool_diffs}
    # normal_tool is the clearest "no caps" case.
    if "normal_tool" in diff_by_tool:
        spurious = diff_by_tool["normal_tool"]["spurious"]
        assert spurious == [], f"spurious caps on normal_tool: {spurious}"


def test_text_formatter_produces_output(report):
    text = format_report_text(report)
    assert "example_server" in text
    assert "Per-tag capability metrics" in text


# Aggregate (--all) ----------------------------------------------------------


@pytest.fixture(scope="module")
def aggregate():
    from calibration.eval import evaluate_all

    return evaluate_all(GT_PATH.parent.parent)


def test_aggregate_includes_all_labeled_targets(aggregate):
    assert aggregate.n_targets >= 4
    assert "example_server" in aggregate.per_target
    assert "mcp-server-fetch" in aggregate.per_target
    assert "mcp-server-time" in aggregate.per_target
    assert "mcp-server-memory" in aggregate.per_target


def test_aggregate_net_egress_caught_in_fetch(aggregate):
    fetch = aggregate.per_target["mcp-server-fetch"]
    assert "net_egress" in fetch.by_tag
    assert fetch.by_tag["net_egress"].true_pos >= 1


def test_aggregate_negative_controls_clean(aggregate):
    """Time and memory have empty GT capability sets — they should not
    produce spurious capability findings at medium+ confidence."""
    for name in ("mcp-server-time", "mcp-server-memory"):
        r = aggregate.per_target[name]
        spurious_tags = {tag for tag, m in r.by_tag.items() if m.false_pos > 0}
        assert spurious_tags == set(), (
            f"{name} produced spurious caps: {spurious_tags}; per_tool_diffs: {r.per_tool_diffs}"
        )


def test_aggregate_text_format_works(aggregate):
    from calibration.eval import format_aggregate_text

    text = format_aggregate_text(aggregate)
    assert "Aggregate" in text
    assert "Per-target summary" in text


def test_aggregate_skips_drafts_by_default(tmp_path):
    """A `labeled: false` GT file must not be included in default aggregate."""
    from calibration.eval import evaluate_all

    # Set up a sibling ground_truth dir with one labeled + one draft target.
    gt_dir = tmp_path / "ground_truth"
    gt_dir.mkdir()
    (gt_dir / "good.yaml").write_text(
        "target_name: good\n"
        "source: ''\n"
        "language: python\n"
        "mcp_spec_version: '2025-06-18'\n"
        "notes: ''\n"
        "tools: []\n"
    )
    (gt_dir / "draft.yaml").write_text(
        "target_name: draft\n"
        "labeled: false\n"
        "source: ''\n"
        "language: python\n"
        "mcp_spec_version: '2025-06-18'\n"
        "notes: ''\n"
        "tools: []\n"
    )
    agg = evaluate_all(tmp_path)
    assert "good" in agg.per_target
    assert "draft" not in agg.per_target

    agg_with_drafts = evaluate_all(tmp_path, include_drafts=True)
    assert "draft" in agg_with_drafts.per_target
