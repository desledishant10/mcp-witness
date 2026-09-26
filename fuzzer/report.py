"""Render a fuzzing campaign as text or JSON."""

from __future__ import annotations

from dataclasses import asdict

from fuzzer.models import Campaign


def format_report(campaign: Campaign) -> str:
    lines = [
        f"MCP fuzz campaign: {campaign.server}",
        f"tools fuzzed: {campaign.tools_fuzzed}   cases sent: {campaign.cases_sent}   "
        f"findings: {len(campaign.findings)}",
    ]
    if not campaign.findings:
        lines.append("\nNo findings. (Absence of a finding is not proof of safety.)")
        return "\n".join(lines)

    lines.append("")
    for f in campaign.by_severity():
        param = f.param if f.param is not None else "-"
        lines.append(
            f"[{f.severity.upper():>6}] {f.outcome:<18} {f.tool}({param})  via {f.category}"
        )
        lines.append(f"         {f.evidence}")
        if f.excerpt:
            lines.append(f"         excerpt: {f.excerpt[:160]!r}")
    lines.append("\nEach finding is a candidate; confirm manually before disclosure.")
    return "\n".join(lines)


def to_dict(campaign: Campaign) -> dict:
    return asdict(campaign)
