"""Top-level entry points for the static analyzer."""

from __future__ import annotations

from pathlib import Path

import json

from .discover import discover_tools_from_captured, discover_tools_in_path
from .rules import RULES, SERVER_RULES
from .types import DiscoveredTool, Finding


def analyze_path(path: str | Path) -> list[Finding]:
    """Run every v0.1 rule. Auto-dispatches on path:

    - `.json` files are treated as captured tools/list payloads (only
      description-based and server-level rules apply — S-006/S-007 need source).
    - Anything else is treated as a Python source file or directory.
    """
    p = Path(path)
    if p.suffix == ".json":
        tools = discover_tools_from_captured(json.loads(p.read_text()))
    else:
        tools = discover_tools_in_path(p)
    return _run_rules(tools)


def analyze_captured(path: Path) -> list[Finding]:
    tools = discover_tools_from_captured(json.loads(path.read_text()))
    return _run_rules(tools)


def _run_rules(tools: list[DiscoveredTool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        for rule in RULES:
            findings.extend(rule(tool))
    for rule in SERVER_RULES:
        findings.extend(rule(tools))
    return findings
