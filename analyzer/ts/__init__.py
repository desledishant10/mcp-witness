"""TypeScript / JavaScript front-end for the static analyzer.

The definition-based rules (S-001..S-005, S-008, S-009, S-015) already work on
a TS server through the captured `tools/list` JSON, and S-010 scans source
files by extension. This package adds the source-analysis half: discovering
tool registrations from TS/JS source and running the handler-body rules
(S-006 path traversal, S-007 command injection to start) against them.

Parsing uses tree-sitter (`tree-sitter-language-pack`), an optional dependency
installed via `pip install mcp-witness[ts]`. Everything here imports lazily so
the core install does not require it.
"""
