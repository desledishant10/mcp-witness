"""Lint MCP-Scan scenario YAML files.

Catches three classes of bug:

1. Non-printable bytes in the raw file (e.g. embedded NULs from
   accidental escape-sequence smuggling — this actually happened to
   MCP-D-002 during initial authoring; the lint exists to make sure it
   never reaches CI).
2. YAML parse errors.
3. Schema-validation failures against the `harness.scenario.Scenario`
   pydantic model.

Usage:

    python -m analyzer.lint_scenarios scenarios/
    mcp-scan-lint-scenarios scenarios/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def lint_scenario(path: Path) -> list[str]:
    raw_bytes = path.read_bytes()

    # Pass 1: C0 control bytes (other than \t \n \r).
    for i, b in enumerate(raw_bytes):
        if b < 0x20 and b not in (0x09, 0x0A, 0x0D):
            return [f"non-printable byte 0x{b:02x} at offset {i}"]

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        return [f"file is not valid UTF-8: {e}"]

    # Pass 2: C1 control characters in the decoded string.
    for i, c in enumerate(text):
        o = ord(c)
        if 0x80 <= o <= 0x9F:
            return [f"C1 control character U+{o:04X} at char {i}"]

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if data is None:
        return ["empty document"]

    # Schema validation (deferred import so the lint can run with only PyYAML
    # available).
    try:
        from harness.scenario import Scenario
    except ImportError:
        return [
            "harness.scenario unavailable — schema validation skipped. "
            "Install the project (`pip install -e .`) to enable."
        ]
    try:
        Scenario.model_validate(data)
    except Exception as e:                                  # noqa: BLE001
        return [f"schema validation error: {type(e).__name__}: {e}"]
    return []


def main() -> int:
    p = argparse.ArgumentParser(prog="mcp-scan-lint-scenarios")
    p.add_argument("path", type=Path, nargs="?", default=Path("scenarios"),
                   help="YAML file or directory (default: ./scenarios).")
    args = p.parse_args()

    if args.path.is_file():
        files = [args.path]
    else:
        files = sorted(list(args.path.glob("*.yaml")) + list(args.path.glob("*.yml")))

    if not files:
        print(f"No YAML files found at {args.path}", file=sys.stderr)
        return 2

    failures = 0
    for f in files:
        issues = lint_scenario(f)
        if issues:
            failures += 1
            print(f"{f}: FAIL")
            for i in issues:
                print(f"  - {i}")
        else:
            print(f"{f}: ok")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
