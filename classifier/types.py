"""Output types for the capability classifier."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Confidence = Literal["high", "medium", "low", "inferred"]

_CONFIDENCE_ORDER = {"low": 0, "inferred": 1, "medium": 1, "high": 2}


@dataclass
class ParameterRole:
    role: str
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)


@dataclass
class CapabilityFinding:
    tag: str
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)


@dataclass
class ToolClassification:
    tool_name: str
    capabilities: list[CapabilityFinding] = field(default_factory=list)
    parameter_roles: dict[str, ParameterRole] = field(default_factory=dict)
    classification_mode: str = "A"          # A = tool def only, B = + handler AST

    def has_capability(self, tag: str, min_confidence: Confidence = "medium") -> bool:
        threshold = _CONFIDENCE_ORDER[min_confidence]
        return any(
            c.tag == tag and _CONFIDENCE_ORDER[c.confidence] >= threshold
            for c in self.capabilities
        )


@dataclass
class OverbroadCombination:
    tags: list[str]
    tools: list[str]
    rationale: str


@dataclass
class ServerClassification:
    tools: list[ToolClassification] = field(default_factory=list)
    server_capability_set: list[str] = field(default_factory=list)
    overbroad_combinations: list[OverbroadCombination] = field(default_factory=list)
