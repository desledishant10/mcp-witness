"""Calibration eval — compare classifier predictions to hand-labeled
ground truth, report per-tag precision/recall plus per-tool diffs.

Run via:
    mcp-scan-eval-calibration example_server
    mcp-scan-eval-calibration --format json example_server

Ground-truth files live in `calibration/ground_truth/<target>.yaml`.
The schema is documented in `calibration/README.md`.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from classifier import classify_server

_CALIBRATION_DIR = Path(__file__).parent


@dataclass
class TagMetrics:
    tag: str
    true_pos: int = 0
    false_pos: int = 0
    false_neg: int = 0

    @property
    def precision(self) -> float | None:
        d = self.true_pos + self.false_pos
        return self.true_pos / d if d else None

    @property
    def recall(self) -> float | None:
        d = self.true_pos + self.false_neg
        return self.true_pos / d if d else None


@dataclass
class EvalReport:
    target_name: str
    n_tools: int = 0
    by_tag: dict[str, TagMetrics] = field(default_factory=dict)
    param_role_correct: int = 0
    param_role_total: int = 0
    per_tool_diffs: list[dict[str, Any]] = field(default_factory=list)

    @property
    def param_role_accuracy(self) -> float | None:
        if not self.param_role_total:
            return None
        return self.param_role_correct / self.param_role_total


def load_ground_truth(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text())


def evaluate_target(gt_path: Path) -> EvalReport:
    gt = load_ground_truth(gt_path)
    tools = gt.get("tools", [])

    classifier_input = [
        {
            "name": t["name"],
            "description": t.get("description", ""),
            "inputSchema": t.get(
                "input_schema",
                {"type": "object", "properties": {}},
            ),
        }
        for t in tools
    ]
    server_class = classify_server(classifier_input)
    pred_by_name = {tc.tool_name: tc for tc in server_class.tools}

    report = EvalReport(
        target_name=gt.get("target_name", gt_path.stem),
        n_tools=len(tools),
    )

    for tool in tools:
        name = tool["name"]
        pred = pred_by_name[name]
        gt_caps = set(tool.get("capabilities", []) or [])
        pred_caps = {
            c.tag for c in pred.capabilities
            if c.confidence in ("high", "medium")
        }

        for tag in gt_caps | pred_caps:
            m = report.by_tag.setdefault(tag, TagMetrics(tag=tag))
            if tag in gt_caps and tag in pred_caps:
                m.true_pos += 1
            elif tag in pred_caps:
                m.false_pos += 1
            else:
                m.false_neg += 1

        for pname, gt_role in (tool.get("parameter_roles") or {}).items():
            report.param_role_total += 1
            pred_role = pred.parameter_roles.get(pname)
            if pred_role is not None and pred_role.role == gt_role:
                report.param_role_correct += 1

        if gt_caps != pred_caps:
            report.per_tool_diffs.append({
                "tool": name,
                "expected_caps": sorted(gt_caps),
                "predicted_caps": sorted(pred_caps),
                "missing": sorted(gt_caps - pred_caps),
                "spurious": sorted(pred_caps - gt_caps),
            })

    return report


@dataclass
class AggregateReport:
    n_targets: int = 0
    n_tools: int = 0
    by_tag: dict[str, TagMetrics] = field(default_factory=dict)
    param_role_correct: int = 0
    param_role_total: int = 0
    per_target: dict[str, EvalReport] = field(default_factory=dict)

    @property
    def param_role_accuracy(self) -> float | None:
        if not self.param_role_total:
            return None
        return self.param_role_correct / self.param_role_total


def evaluate_all(calibration_dir: Path, include_drafts: bool = False) -> AggregateReport:
    """Evaluate every ground-truth YAML in `calibration_dir/ground_truth/`.

    Targets with `labeled: false` in their YAML are skipped by default —
    those are scaffolds whose hand-labels have not yet been filled in,
    and including them pollutes aggregate metrics.
    """
    gt_dir = calibration_dir / "ground_truth"
    reports: dict[str, EvalReport] = {}
    for gt_path in sorted(gt_dir.glob("*.yaml")):
        gt = load_ground_truth(gt_path)
        if not include_drafts and gt.get("labeled", True) is False:
            continue
        reports[gt_path.stem] = evaluate_target(gt_path)

    agg = AggregateReport(
        n_targets=len(reports),
        n_tools=sum(r.n_tools for r in reports.values()),
        per_target=reports,
    )
    for r in reports.values():
        agg.param_role_correct += r.param_role_correct
        agg.param_role_total += r.param_role_total
        for tag, m in r.by_tag.items():
            agg_m = agg.by_tag.setdefault(tag, TagMetrics(tag=tag))
            agg_m.true_pos += m.true_pos
            agg_m.false_pos += m.false_pos
            agg_m.false_neg += m.false_neg
    return agg


def format_aggregate_text(agg: AggregateReport) -> str:
    lines: list[str] = []
    lines.append(f"Aggregate ({agg.n_targets} targets, {agg.n_tools} tools)")
    lines.append("")
    lines.append("Per-tag capability metrics (aggregated):")
    lines.append(f"  {'Tag':<20} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec':>7} {'Recl':>7}")
    for tag in sorted(agg.by_tag):
        m = agg.by_tag[tag]
        p = f"{m.precision:.2f}" if m.precision is not None else "  -"
        rc = f"{m.recall:.2f}" if m.recall is not None else "  -"
        lines.append(
            f"  {tag:<20} {m.true_pos:>4} {m.false_pos:>4} {m.false_neg:>4} {p:>7} {rc:>7}"
        )
    lines.append("")
    if agg.param_role_total:
        lines.append(
            f"Parameter role accuracy: {agg.param_role_correct}/{agg.param_role_total} "
            f"({agg.param_role_accuracy:.2%})"
        )
    lines.append("")
    lines.append("Per-target summary:")
    for name, r in sorted(agg.per_target.items()):
        diffs = len(r.per_tool_diffs)
        tags_str = ", ".join(sorted(r.by_tag.keys())) or "-"
        marker = f"({diffs} diff{'s' if diffs != 1 else ''})" if diffs else "(clean)"
        lines.append(f"  {name:<32} {r.n_tools:>3} tools  tags={tags_str}  {marker}")
    return "\n".join(lines)


def format_report_text(r: EvalReport) -> str:
    lines: list[str] = []
    lines.append(f"Target: {r.target_name}  ({r.n_tools} tools)")
    lines.append("")
    lines.append("Per-tag capability metrics:")
    lines.append(f"  {'Tag':<20} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec':>7} {'Recl':>7}")
    for tag in sorted(r.by_tag):
        m = r.by_tag[tag]
        p = f"{m.precision:.2f}" if m.precision is not None else "  -"
        rc = f"{m.recall:.2f}" if m.recall is not None else "  -"
        lines.append(
            f"  {tag:<20} {m.true_pos:>4} {m.false_pos:>4} {m.false_neg:>4} {p:>7} {rc:>7}"
        )
    lines.append("")
    if r.param_role_total:
        lines.append(
            f"Parameter role accuracy: {r.param_role_correct}/{r.param_role_total} "
            f"({r.param_role_accuracy:.2%})"
        )
    if r.per_tool_diffs:
        lines.append("")
        lines.append("Per-tool diffs (predicted vs ground truth):")
        for d in r.per_tool_diffs:
            lines.append(f"  {d['tool']}:")
            if d["missing"]:
                lines.append(f"    missing:  {d['missing']}")
            if d["spurious"]:
                lines.append(f"    spurious: {d['spurious']}")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(prog="mcp-scan-eval-calibration")
    p.add_argument(
        "target",
        nargs="?",
        help="Ground-truth file basename (e.g. 'example_server') or a full path.",
    )
    p.add_argument("--all", action="store_true",
                   help="Evaluate every labeled target in ground_truth/ and report aggregate metrics.")
    p.add_argument("--include-drafts", action="store_true",
                   help="With --all: include targets marked `labeled: false`. "
                        "Default: skip drafts so aggregate metrics aren't polluted.")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument(
        "--calibration-dir",
        type=Path,
        default=_CALIBRATION_DIR,
        help="Directory containing ground_truth/ (default: alongside this script).",
    )
    args = p.parse_args()

    if args.all:
        agg = evaluate_all(args.calibration_dir, include_drafts=args.include_drafts)
        if args.format == "json":
            json.dump(_aggregate_to_dict(agg), sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print(format_aggregate_text(agg))
        return 0

    if not args.target:
        print("Error: provide a target name or use --all.", file=sys.stderr)
        return 2

    candidate = args.calibration_dir / "ground_truth" / (
        args.target if args.target.endswith(".yaml") else f"{args.target}.yaml"
    )
    if not candidate.exists():
        candidate = Path(args.target)
    if not candidate.exists():
        print(f"Ground truth file not found: {candidate}", file=sys.stderr)
        return 2

    report = evaluate_target(candidate)

    if args.format == "json":
        json.dump(_report_to_dict(report), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(format_report_text(report))
    return 0


def _aggregate_to_dict(agg: AggregateReport) -> dict[str, Any]:
    return {
        "n_targets": agg.n_targets,
        "n_tools": agg.n_tools,
        "by_tag": {
            t: {
                "tp": m.true_pos,
                "fp": m.false_pos,
                "fn": m.false_neg,
                "precision": m.precision,
                "recall": m.recall,
            }
            for t, m in agg.by_tag.items()
        },
        "param_role_accuracy": agg.param_role_accuracy,
        "param_role_correct": agg.param_role_correct,
        "param_role_total": agg.param_role_total,
        "per_target": {name: _report_to_dict(r) for name, r in agg.per_target.items()},
    }


def _report_to_dict(r: EvalReport) -> dict[str, Any]:
    return {
        "target_name": r.target_name,
        "n_tools": r.n_tools,
        "by_tag": {
            t: {
                "tp": m.true_pos,
                "fp": m.false_pos,
                "fn": m.false_neg,
                "precision": m.precision,
                "recall": m.recall,
            }
            for t, m in r.by_tag.items()
        },
        "param_role_accuracy": r.param_role_accuracy,
        "param_role_correct": r.param_role_correct,
        "param_role_total": r.param_role_total,
        "per_tool_diffs": r.per_tool_diffs,
    }


if __name__ == "__main__":
    sys.exit(main())
