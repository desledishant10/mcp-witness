"""Validate the mcp-witness detection rules against event fixtures.

Runs every Sigma rule in ``sigma/`` against every event in
``fixtures/events.jsonl`` and checks the result against the ground truth in
``validation.yml``: each attack event must trigger exactly its expected rules,
and each benign event must trigger nothing. Also structurally lints the
Suricata rules. Exit code is 0 when everything passes, 1 otherwise.

    python -m detections.validate            # sigma validation + suricata lint
    python -m detections.validate --json     # machine-readable summary
    mcp-witness-detect                        # same, via the console script
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from detections import suricata_lint
from detections.sigma_lite import load_rules

_HERE = Path(__file__).resolve().parent
SIGMA_DIR = _HERE / "sigma"
FIXTURES = _HERE / "fixtures" / "events.jsonl"
MANIFEST = _HERE / "validation.yml"
SURICATA_RULES = _HERE / "suricata" / "mcp-witness.rules"


def load_events(path: Path = FIXTURES) -> list[dict]:
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def run_sigma_validation(
    sigma_dir: Path = SIGMA_DIR,
    fixtures: Path = FIXTURES,
    manifest: Path = MANIFEST,
) -> tuple[list[dict], bool]:
    """Return (rows, ok). Each row: {event, expected, fired, status}."""
    rules = {r.path.stem: r for r in load_rules(sigma_dir)}
    events = load_events(fixtures)
    expected_map = yaml.safe_load(manifest.read_text())["expected"]

    rows: list[dict] = []
    ok = True
    for event in events:
        eid = event["id"]
        fired = sorted(stem for stem, rule in rules.items() if rule.matches(event))
        expected = sorted(expected_map.get(eid, []))
        misses = [r for r in expected if r not in fired]
        false_positives = [r for r in fired if r not in expected]
        passed = not misses and not false_positives
        ok = ok and passed
        rows.append(
            {
                "event": eid,
                "expected": expected,
                "fired": fired,
                "misses": misses,
                "false_positives": false_positives,
                "status": "PASS" if passed else "FAIL",
            }
        )
    return rows, ok


def _print_report(rows: list[dict], rule_count: int, suricata_errors: list[str]) -> None:
    width = max((len(r["event"]) for r in rows), default=10)
    print(f"Sigma rules: {rule_count}   Fixtures: {len(rows)}\n")
    for r in rows:
        mark = "ok " if r["status"] == "PASS" else "XX "
        detail = ", ".join(r["fired"]) or "(no match)"
        print(f"  {mark}{r['event']:<{width}}  ->  {detail}")
        for miss in r["misses"]:
            print(f"      MISS: expected {miss} to fire")
        for fp in r["false_positives"]:
            print(f"      FALSE POSITIVE: {fp} fired unexpectedly")

    print(
        f"\nSuricata rules: {suricata_lint.count_rules(SURICATA_RULES)} "
        f"({'structurally valid' if not suricata_errors else 'INVALID'})"
    )
    for err in suricata_errors:
        print(f"      {err}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate mcp-witness detection rules.")
    parser.add_argument("--json", action="store_true", help="emit a JSON summary")
    parser.add_argument("--lint-suricata", action="store_true", help="only lint the Suricata rules")
    args = parser.parse_args(argv)

    suricata_errors = suricata_lint.lint_rules(SURICATA_RULES)
    if args.lint_suricata:
        for err in suricata_errors:
            print(err)
        print("Suricata rules OK" if not suricata_errors else "Suricata rules INVALID")
        return 1 if suricata_errors else 0

    rows, sigma_ok = run_sigma_validation()
    rule_count = len(list(SIGMA_DIR.glob("*.yml")))
    ok = sigma_ok and not suricata_errors

    if args.json:
        print(json.dumps({"ok": ok, "sigma": rows, "suricata_errors": suricata_errors}, indent=2))
    else:
        _print_report(rows, rule_count, suricata_errors)
        print(f"\n{'ALL DETECTIONS VALIDATED' if ok else 'VALIDATION FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
