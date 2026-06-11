"""Top-level entry points for the static analyzer."""

from __future__ import annotations

import json
from pathlib import Path

from .discover import discover_tools_from_captured, discover_tools_in_path
from .rules import REPO_RULES, RULES, SERVER_RULES
from .types import DiscoveredTool, Finding


def analyze_path(path: str | Path) -> list[Finding]:
    """Run every v0.1 rule. Auto-dispatches on path:

    - `.json` files are treated as captured tools/list payloads. Per-tool
      and server-level rules run; repo-level rules are skipped (no source
      tree to walk).
    - Anything else is treated as a Python source file or directory. All
      three rule registries run.
    """
    p = Path(path)
    if p.suffix == ".json":
        tools = discover_tools_from_captured(json.loads(p.read_text()))
        return _run_rules(tools, root=None)
    tools = discover_tools_in_path(p)
    return _run_rules(tools, root=p)


def analyze_captured(path: Path) -> list[Finding]:
    tools = discover_tools_from_captured(json.loads(path.read_text()))
    return _run_rules(tools, root=None)


def _run_rules(tools: list[DiscoveredTool], root: Path | None) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        for rule in RULES:
            findings.extend(rule(tool))
    for rule in SERVER_RULES:
        findings.extend(rule(tools))
    if root is not None:
        for rule in REPO_RULES:
            findings.extend(rule(root))
    return findings
