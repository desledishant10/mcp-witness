"""Minimal CLI entry point — runs one scenario against one stdio target."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from .runner import Target, make_agent_factory, run_scenario


def main() -> int:
    p = argparse.ArgumentParser(prog="mcpsentry-test")
    p.add_argument("scenario", type=Path, help="Path to a scenario YAML file.")
    p.add_argument(
        "--server-cmd",
        required=True,
        help="Command to launch the MCP server under test (stdio transport).",
    )
    p.add_argument(
        "--server-arg",
        action="append",
        default=[],
        help="Argument to pass to the server command (repeatable).",
    )
    p.add_argument(
        "--agent",
        choices=["stub", "anthropic"],
        default="stub",
        help="Agent driver for proxy-mode scenarios. "
        "'stub' is deterministic (proxy plumbing tests only). "
        "'anthropic' runs a real Claude tool-use loop "
        "(requires ANTHROPIC_API_KEY).",
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    target = Target(command=args.server_cmd, args=args.server_arg)
    agent_factory = make_agent_factory(args.agent)
    result = asyncio.run(run_scenario(args.scenario, target, agent_factory=agent_factory))
    json.dump(
        {
            "scenario_id": result.scenario_id,
            "passed": result.passed,
            "oracle_evidence": result.oracle_evidence,
            "skipped_steps": result.skipped_steps,
            "error": result.error,
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
