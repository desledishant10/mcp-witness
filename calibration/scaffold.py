"""Generate a ground-truth YAML skeleton from a captured tools.json.

Workflow:

    mcpsentry-capture --server-cmd ... -o captured.json
    mcpsentry-scaffold-gt captured.json --name some_server \\
        --source https://... --language python > ground_truth/some_server.yaml

The scaffolded YAML carries every tool's name / description / inputSchema
already filled in, plus *empty* `capabilities`, `parameter_roles`, and
`known_vulns` fields for the human auditor to populate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml


def scaffold(
    captured: dict | list,
    target_name: str,
    source: str = "",
    language: str = "",
    spec_version: str = "2025-06-18",
    notes: str = "",
) -> dict[str, Any]:
    if isinstance(captured, list):
        captured = {"tools": captured}

    return {
        "target_name": target_name,
        "source": source,
        "language": language,
        "mcp_spec_version": spec_version,
        # `labeled: false` marks this as an unfilled scaffold. The eval
        # driver skips drafts by default so they do not pollute aggregate
        # precision/recall. Set to true (or remove) once you've filled in
        # capabilities / parameter_roles / known_vulns for each tool.
        "labeled": False,
        "notes": notes
        or (
            "Auto-scaffolded skeleton. Hand-fill `capabilities`, "
            "`parameter_roles`, and `known_vulns` for each tool, then set "
            "`labeled: true` (or delete the field)."
        ),
        "tools": [
            {
                "name": t.get("name", ""),
                "description": t.get("description", ""),
                "input_schema": t.get("inputSchema")
                or t.get("input_schema")
                or {
                    "type": "object",
                    "properties": {},
                },
                "capabilities": [],
                "parameter_roles": {},
                "known_vulns": [],
            }
            for t in captured.get("tools", [])
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser(prog="mcpsentry-scaffold-gt")
    p.add_argument(
        "captured", type=Path, help="Path to captured tools.json (from `mcpsentry-capture`)."
    )
    p.add_argument("--name", required=True, help="target_name for the ground-truth file.")
    p.add_argument("--source", default="", help="Server source URL or filesystem path.")
    p.add_argument(
        "--language", default="", help="Source language: python | typescript | rust | other."
    )
    p.add_argument(
        "--spec-version", default="2025-06-18", help="MCP spec version the server claims."
    )
    p.add_argument("--output", "-o", type=Path, help="Output YAML file. Default: stdout.")
    args = p.parse_args()

    raw = json.loads(args.captured.read_text())
    gt = scaffold(
        raw,
        target_name=args.name,
        source=args.source,
        language=args.language,
        spec_version=args.spec_version,
    )

    text = yaml.dump(gt, sort_keys=False, default_flow_style=False)
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
