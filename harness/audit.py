"""mcpsentry-audit — one-shot audit of a PyPI-installed MCP server.

Single command that:
  1. (optional) pip installs the package
  2. Captures its tools/list via stdio
  3. Runs the static analyzer rules
  4. Runs the capability classifier
  5. Prints a human-readable summary OR JSON

Designed for fast triage: `mcpsentry-audit mcp-server-fetch` should be
all that's needed to determine "is this server worth a deeper look?"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from .capture import capture
from .runner import Target


def _candidate_targets(package: str) -> list[Target]:
    """Possible ways to launch an installed MCP server package.

    Order matters — first one that succeeds wins. Each target inherits
    the current process environment so subprocesses can find their
    dependencies (PYTHONPATH, package config envs, etc.).
    """
    env = dict(os.environ)
    module = package.replace("-", "_")
    short_console = shutil.which(package)
    candidates: list[Target] = [
        # python -m <package_with_underscores> — most common pattern
        Target(command=sys.executable, args=["-m", module], env=env),
    ]
    # If a console script matching the package name exists on PATH, try it
    # (some servers ship as console scripts with custom non-module entry points).
    if short_console:
        candidates.append(Target(command=short_console, env=env))
    return candidates


def _pip_install(package: str) -> None:
    cmd = [sys.executable, "-m", "pip", "install", "--quiet", package]
    print(f"  $ {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"pip install failed (exit {result.returncode}):\n{result.stderr}")


async def audit_package(
    package: str,
    install: bool = True,
    server_cmd: str | None = None,
    server_args: list[str] | None = None,
) -> dict:
    """Audit a pip-installable MCP server. Returns a structured report."""
    if install:
        _pip_install(package)

    if server_cmd:
        targets = [Target(command=server_cmd, args=server_args or [], env=dict(os.environ))]
    else:
        targets = _candidate_targets(package)

    # Suppress stderr from the per-candidate attempts — the MCP SDK +
    # anyio interaction can dump alarming-looking task-group tracebacks
    # when stdio_client can't connect to a missing-entry-point binary.
    # Those tracebacks are not user-actionable; the actionable info is
    # the exception value, which we collect for the final error message.
    import contextlib
    import os as _os

    captured: dict | None = None
    target_used: Target | None = None
    attempt_log: list[str] = []
    for target in targets:
        cmd_str = " ".join([target.command] + (target.args or []))
        try:
            with open(_os.devnull, "w") as devnull, contextlib.redirect_stderr(devnull):
                captured = await capture(target)
            target_used = target
            break
        except Exception as e:  # noqa: BLE001
            attempt_log.append(f"  - {cmd_str}\n      {type(e).__name__}: {str(e)[:140]}")
            continue
    if captured is None:
        attempts = "\n".join(attempt_log) if attempt_log else "  (no candidates tried)"
        raise RuntimeError(
            f"Could not launch {package!r} as an MCP server. Attempts:\n"
            f"{attempts}\n"
            f"Hint: many community packages don't expose a `python -m <pkg>` "
            f"entry point. Try `--server-cmd <executable> --server-arg=<arg> ...` "
            f"with the entry point listed in the package's PyPI page or README."
        )

    # Persist the capture under calibration/reports/ for traceability.
    repo_root = Path(__file__).resolve().parent.parent
    reports_dir = repo_root / "calibration" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    capture_path = reports_dir / f"captured-{package}.json"
    capture_path.write_text(json.dumps(captured, indent=2))

    # Run analyzer
    from analyzer.analyze import analyze_path

    findings = analyze_path(capture_path)

    # Run classifier
    from classifier import classify_server

    classification = classify_server(captured["tools"])

    return {
        "package": package,
        "target_used": {"command": target_used.command, "args": target_used.args}
        if target_used
        else None,
        "capture_path": str(capture_path),
        "n_tools": len(captured["tools"]),
        "tool_names": [t["name"] for t in captured["tools"]],
        "server_capability_set": classification.server_capability_set,
        "overbroad_combinations": [asdict(c) for c in classification.overbroad_combinations],
        "findings": [asdict(f) for f in findings],
    }


def _format_text(report: dict) -> str:
    lines: list[str] = []
    pkg = report["package"]
    lines.append(f"=== {pkg} ===")
    target = report.get("target_used")
    if target:
        cmd = " ".join([target["command"]] + (target.get("args") or []))
        lines.append(f"Launched: {cmd}")
    lines.append(f"Tools:    {report['n_tools']}")
    if report["tool_names"]:
        names = ", ".join(report["tool_names"][:10])
        more = (
            f" (+{len(report['tool_names']) - 10} more)" if len(report["tool_names"]) > 10 else ""
        )
        lines.append(f"  {names}{more}")
    caps = report["server_capability_set"] or []
    lines.append(f"Capability tags: {', '.join(caps) if caps else '(none)'}")
    combos = report["overbroad_combinations"]
    if combos:
        for combo in combos:
            lines.append(
                f"  ⚠ overbroad combination: {' + '.join(combo['tags'])} ({combo['rationale']})"
            )
    findings = report["findings"]
    lines.append("")
    if not findings:
        lines.append("No analyzer findings.")
    else:
        n = len(findings)
        lines.append(f"{n} analyzer finding{'s' if n != 1 else ''}:")
        for f in findings:
            tag = f["tool_name"] or "<server>"
            lines.append(f"  [{f['severity'].upper():<8}] {f['rule_id']}  {tag}")
            lines.append(f"      {f['message']}")
    lines.append("")
    lines.append(f"Capture saved to: {report['capture_path']}")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(
        prog="mcpsentry-audit", description="One-shot audit of a PyPI-installed MCP server."
    )
    p.add_argument("package", help="PyPI package name (e.g. mcp-server-fetch)")
    p.add_argument(
        "--no-install",
        action="store_true",
        help="Skip pip install — assume the package is already installed.",
    )
    p.add_argument(
        "--server-cmd", help="Override entry-point detection. Specify the command to launch."
    )
    p.add_argument(
        "--server-arg", action="append", default=[], help="Argument for --server-cmd (repeatable)."
    )
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args()

    try:
        report = asyncio.run(
            audit_package(
                args.package,
                install=not args.no_install,
                server_cmd=args.server_cmd,
                server_args=args.server_arg or None,
            )
        )
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(_format_text(report))

    # CI-friendly exit code: non-zero if any high+ severity finding.
    high_or_above = {"high", "critical"}
    if any(f["severity"] in high_or_above for f in report["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
