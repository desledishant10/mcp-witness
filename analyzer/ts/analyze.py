"""Run the TS source rules over a file or directory."""

from __future__ import annotations

from pathlib import Path

from analyzer.ts import treesitter_utils as ts
from analyzer.ts.discover import discover_prompts_from_tree, discover_tools_from_tree
from analyzer.ts.rules import TS_FILE_RULES, TS_PROMPT_RULES, TS_RULES
from analyzer.types import Finding

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".venv", "coverage", ".next"}


def analyze_ts_source(src: bytes, path: str, language: str) -> list[Finding]:
    tree = ts.parse(src, language)
    findings: list[Finding] = []
    for rule in TS_FILE_RULES:
        findings.extend(rule(tree.root_node, src, path))
    for tool in discover_tools_from_tree(tree, src, path):
        for rule in TS_RULES:
            findings.extend(rule(tool))
    for prompt in discover_prompts_from_tree(tree, src, path):
        for rule in TS_PROMPT_RULES:
            findings.extend(rule(prompt))
    return findings


def analyze_ts_path(path: str | Path) -> list[Finding]:
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = [
            f
            for f in p.rglob("*")
            if f.suffix.lower() in ts.TS_EXTENSIONS and not _SKIP_DIRS.intersection(f.parts)
        ]
    findings: list[Finding] = []
    for f in files:
        language = ts.language_for_path(f)
        if language is None:
            continue
        try:
            src = f.read_bytes()
        except OSError:
            continue
        findings.extend(analyze_ts_source(src, str(f), language))
    return findings
