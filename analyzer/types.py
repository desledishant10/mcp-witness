"""Finding and discovery types for the static analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    tool_name: str
    message: str
    evidence: str = ""
    category: str = ""


@dataclass
class DiscoveredTool:
    """A tool discovered by inspecting source or a captured tools/list.

    `function_node` is the AST node of the decorated function (for
    source-discovered tools; None for captured tools). `input_schema` is
    the JSON Schema dict (for captured tools; possibly None for
    source-discovered tools where we haven't extracted it).

    `annotations` holds the MCP tool annotation hints (`readOnlyHint`,
    `destructiveHint`, `idempotentHint`, `openWorldHint`) when the server
    declares them — carried through from `tools/list` for captured tools
    and from the `@tool(...)` decorator for source tools. None/absent when
    the server sets no annotations, which is the common case. Consumed by
    MCP-S-004.
    """

    name: str
    description: str = ""
    source_path: str = ""
    line: int = 0
    function_node: Any = None
    parameters: list[str] = field(default_factory=list)
    input_schema: dict | None = None
    annotations: dict | None = None
