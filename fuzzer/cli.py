"""mcp-witness-fuzz: fuzz a locally-run MCP server.

    mcp-witness-fuzz [options] -- <server command...>

Examples:
    mcp-witness-fuzz -- python -m mcp_server_fetch
    mcp-witness-fuzz --dry-run -- uvx some-mcp-server
    mcp-witness-fuzz --json --max-per-tool 32 -- python server.py

Fuzz servers you run yourself and disclose responsibly. Each finding is a
candidate that needs manual confirmation before it is a vulnerability.
"""

from __future__ import annotations

import argparse
import json
import sys

from fuzzer.payloads import generate_cases
from fuzzer.report import format_report, to_dict


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-witness-fuzz",
        description="Automated dynamic fuzzer for a locally-run MCP server.",
    )
    parser.add_argument("--max-per-tool", type=int, default=48, help="cap fuzz cases per tool")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-call timeout in seconds")
    parser.add_argument("--json", action="store_true", help="emit the campaign as JSON")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list the server's tools and the payloads that would be sent, without sending any",
    )
    return parser


def _dry_run(server_cmd: list[str], max_per_tool: int) -> int:
    from fuzzer.transport import fetch_tools

    tools = fetch_tools(server_cmd)
    total = 0
    for tool in tools:
        cases = generate_cases(tool, max_per_tool=max_per_tool)
        total += len(cases)
        cats: dict[str, int] = {}
        for c in cases:
            cats[c.category] = cats.get(c.category, 0) + 1
        summary = ", ".join(f"{k}:{v}" for k, v in sorted(cats.items()))
        print(f"{tool.get('name', '?')}: {len(cases)} cases  ({summary})")
    print(f"\n{len(tools)} tools, {total} cases would be sent. (dry run: nothing sent)")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" in argv:
        split = argv.index("--")
        options, server_cmd = argv[:split], argv[split + 1 :]
    else:
        options, server_cmd = argv, []

    parser = _build_parser()
    args = parser.parse_args(options)
    if not server_cmd:
        parser.error("provide the downstream server command after '--'")

    if args.dry_run:
        return _dry_run(server_cmd, args.max_per_tool)

    from fuzzer.transport import run_live

    campaign = run_live(server_cmd, max_per_tool=args.max_per_tool, per_call_timeout=args.timeout)
    if args.json:
        print(json.dumps(to_dict(campaign), indent=2, default=str))
    else:
        print(format_report(campaign))
    return 1 if campaign.findings else 0


if __name__ == "__main__":
    sys.exit(main())
