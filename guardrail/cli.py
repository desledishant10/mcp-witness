"""mcp-witness-guardrail: wrap a stdio MCP server with the runtime guardrail.

    mcp-witness-guardrail [options] -- <server command...>

Example, guarding the reference fetch server so a coerced IMDS fetch is refused
before it leaves the box:

    mcp-witness-guardrail --mode block -- python -m mcp_server_fetch
"""

from __future__ import annotations

import argparse
import sys

from guardrail.policy import GuardrailPolicy
from guardrail.proxy import StdioGuardrailProxy


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-witness-guardrail",
        description="Runtime guardrail proxy for a stdio MCP server.",
    )
    parser.add_argument(
        "--mode",
        choices=["block", "monitor"],
        default="block",
        help="block (refuse offending calls) or monitor (flag only, still forward)",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="exempt this host from the SSRF check (repeatable)",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="do not resolve hostnames for the SSRF check (literal IPs only)",
    )
    parser.add_argument("--server-name", default="mcp-server", help="name used in decision events")
    return parser


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

    policy = GuardrailPolicy(
        mode=args.mode,
        resolve_dns=not args.no_resolve,
        allow_hosts=set(args.allow_host),
        server_name=args.server_name,
    )
    return StdioGuardrailProxy(server_cmd, policy).run()


if __name__ == "__main__":
    sys.exit(main())
