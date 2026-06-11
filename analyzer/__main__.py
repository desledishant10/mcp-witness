"""CLI: `python -m analyzer <path>` or `mcpsentry-analyze <path>`."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .analyze import analyze_path

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main() -> int:
    p = argparse.ArgumentParser(prog="mcpsentry-analyze")
    p.add_argument("path", type=Path, help="File or directory to analyze.")
    p.add_argument("--format", choices=["json", "text"], default="text")
    p.add_argument(
        "--min-severity",
        choices=list(_SEV_ORDER.keys()),
        default="info",
        help="Skip findings below this severity.",
    )
    p.add_argument(
        "--fail-on",
        choices=list(_SEV_ORDER.keys()),
        default="high",
        help="Exit non-zero if any finding at or above this severity. Default: high.",
    )
    args = p.parse_args()

    findings = analyze_path(args.path)

    threshold = _SEV_ORDER[args.min_severity]
    findings = [f for f in findings if _SEV_ORDER[f.severity] >= threshold]

    if args.format == "json":
        json.dump([asdict(f) for f in findings], sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_text(findings)

    fail_threshold = _SEV_ORDER[args.fail_on]
    blocking = [f for f in findings if _SEV_ORDER[f.severity] >= fail_threshold]
    return 1 if blocking else 0


def _print_text(findings) -> None:
    if not findings:
        print("No findings.")
        return
    by_sev: dict = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)
    for sev in ("critical", "high", "medium", "low", "info"):
        for f in by_sev.get(sev, []):
            print(f"[{f.severity.upper()}] {f.rule_id}  {f.file}:{f.line}  {f.tool_name}")
            print(f"    {f.message}")
            if f.evidence:
                print(f"    | {f.evidence[:140]}")
    n = len(findings)
    print(f"\n{n} finding{'s' if n != 1 else ''}.")


if __name__ == "__main__":
    sys.exit(main())
