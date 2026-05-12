"""Layer 1 (lexical / heuristic) classification logic."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .lexicons import (
    CAPABILITY_LEXICONS,
    OVERBROAD_COMBOS,
    PARAM_ROLE_DICT,
    SCHEMA_FORMAT_ROLES,
)
from .types import (
    CapabilityFinding,
    Confidence,
    OverbroadCombination,
    ParameterRole,
    ServerClassification,
    ToolClassification,
)


def tokenize(name: str) -> set[str]:
    """Split snake_case and camelCase, lowercase, return a set of tokens."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return {t for t in re.split(r"[_\s\-]+", s.lower()) if t}


def classify_parameter(name: str, defn: dict[str, Any]) -> ParameterRole:
    name_l = name.lower()
    defn = defn or {}
    schema_fmt = (defn.get("format") or "").lower()
    schema_type = defn.get("type") or ""

    if schema_fmt in SCHEMA_FORMAT_ROLES:
        return ParameterRole(
            role=SCHEMA_FORMAT_ROLES[schema_fmt],
            confidence="high",
            evidence=[f"schema_format:{schema_fmt}"],
        )

    for role, hints in PARAM_ROLE_DICT.items():
        if name_l in hints:
            return ParameterRole(role=role, confidence="high",
                                  evidence=[f"param_name:{name_l}"])

    for role, hints in PARAM_ROLE_DICT.items():
        if any(h in name_l for h in hints):
            return ParameterRole(role=role, confidence="medium",
                                  evidence=[f"param_name_partial:{name_l}"])

    fallback = "text" if schema_type == "string" else "id"
    return ParameterRole(role=fallback, confidence="low",
                          evidence=[f"fallback:type={schema_type or 'unknown'}"])


def classify_tool(tool: dict[str, Any]) -> ToolClassification:
    name = tool.get("name", "")
    desc = (tool.get("description") or "").lower()
    schema = tool.get("inputSchema") or {}

    tokens = tokenize(name)

    parameter_roles: dict[str, ParameterRole] = {}
    for pname, pdefn in (schema.get("properties") or {}).items():
        parameter_roles[pname] = classify_parameter(pname, pdefn or {})

    capabilities: list[CapabilityFinding] = []
    for tag, lex in CAPABILITY_LEXICONS.items():
        evidence: list[str] = []
        signal_kinds: set[str] = set()

        for combo in lex["name_combos"]:
            if all(c in tokens for c in combo):
                evidence.append(f"name_combo:{'+'.join(combo)}")
                signal_kinds.add("strong")
                break

        for tok in lex["name_tokens"]:
            if tok in tokens:
                evidence.append(f"name_token:{tok}")
                signal_kinds.add("weak_name")
                break

        for pat in lex["desc_patterns"]:
            if re.search(pat, desc):
                evidence.append(f"desc_pattern:{pat[:60]}")
                signal_kinds.add("strong")
                break

        want = lex.get("param_role")
        if want:
            for pname, prole in parameter_roles.items():
                if prole.role == want and prole.confidence in ("high", "medium"):
                    evidence.append(f"param:{pname}={want}")
                    signal_kinds.add("weak_param")
                    break

        if evidence:
            capabilities.append(CapabilityFinding(
                tag=tag,
                confidence=_score(signal_kinds),
                evidence=evidence,
            ))

    return ToolClassification(
        tool_name=name,
        capabilities=capabilities,
        parameter_roles=parameter_roles,
    )


def _score(signal_kinds: set[str]) -> Confidence:
    """Combine signal kinds into a confidence level.

    Two or more distinct signal kinds → high (independent agreement).
    One strong signal (name_combo or desc_pattern) → medium.
    Single weak signal only → low.
    """
    if len(signal_kinds) >= 2:
        return "high"
    if "strong" in signal_kinds:
        return "medium"
    return "low"


def classify_server(tools: list[dict[str, Any]]) -> ServerClassification:
    classifications = [classify_tool(t) for t in tools]

    cap_to_tools: dict[str, list[str]] = defaultdict(list)
    for tc in classifications:
        for cap in tc.capabilities:
            if cap.confidence in ("high", "medium"):
                cap_to_tools[cap.tag].append(tc.tool_name)

    overbroad: list[OverbroadCombination] = []
    for required_tags, rationale in OVERBROAD_COMBOS:
        if all(t in cap_to_tools for t in required_tags):
            involved = sorted({tool for t in required_tags for tool in cap_to_tools[t]})
            overbroad.append(OverbroadCombination(
                tags=list(required_tags),
                tools=involved,
                rationale=rationale,
            ))

    return ServerClassification(
        tools=classifications,
        server_capability_set=sorted(cap_to_tools.keys()),
        overbroad_combinations=overbroad,
    )
