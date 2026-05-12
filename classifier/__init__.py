"""MCP-Scan capability classifier (Layer 1).

Labels MCP tools with capability tags (`fs_read`, `net_egress`, etc.) and
parameter roles (`path`, `url`, etc.). Spec: ../docs/capability-classifier.md.

v0.1 ships Layer 1 (lexical / heuristic) only. Layer 2 (AST sink-call
detection) and Layer 3 (LLM fallback) are future work.
"""

from .classify import classify_server, classify_tool
from .types import (
    CapabilityFinding,
    OverbroadCombination,
    ParameterRole,
    ServerClassification,
    ToolClassification,
)

__all__ = [
    "classify_tool",
    "classify_server",
    "CapabilityFinding",
    "OverbroadCombination",
    "ParameterRole",
    "ServerClassification",
    "ToolClassification",
]
