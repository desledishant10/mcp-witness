"""MCP-Scan static analyzer (Phase 1).

v0.1 ships three rules:

- MCP-S-001 — imperative instructions in tool description
- MCP-S-006 — path traversal in file-handling tool
- MCP-S-007 — shell command injection in tool handler

Spec: ../docs/static-rules.md.

Python sources via the stdlib `ast` module. TypeScript support and the
remaining 11 rules from the spec are v0.2 items.
"""

from .analyze import analyze_path
from .types import DiscoveredTool, Finding

__all__ = ["analyze_path", "DiscoveredTool", "Finding"]
