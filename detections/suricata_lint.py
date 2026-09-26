"""A minimal structural linter for the Suricata/Snort-style rules file.

It does not replace ``suricata -T`` (full engine validation). It checks the
things we can verify without the engine so a malformed rule cannot land in the
repo: a valid action and header, a body in parentheses, required ``msg:`` and
``sid:`` options, numeric and unique SIDs, and balanced quotes. Full
traffic-level validation is ``make validate-suricata`` (needs Suricata).
"""

from __future__ import annotations

import re
from pathlib import Path

_ACTIONS = {"alert", "drop", "pass", "reject", "rejectsrc", "rejectdst", "rejectboth"}


def lint_rules(path: str | Path) -> list[str]:
    """Return a list of human-readable problems. Empty list means the file is
    structurally valid."""
    path = Path(path)
    errors: list[str] = []
    seen_sids: dict[str, int] = {}

    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.count('"') % 2 != 0:
            errors.append(f"line {lineno}: unbalanced double-quotes")
            continue

        open_paren = line.find("(")
        if open_paren == -1 or not line.rstrip().endswith(")"):
            errors.append(f"line {lineno}: rule body must be wrapped in (...)")
            continue

        header = line[:open_paren].split()
        if not header or header[0] not in _ACTIONS:
            errors.append(f"line {lineno}: invalid or missing action {header[:1]}")
            continue
        # action proto src sport direction dst dport  => 7 header tokens
        if len(header) != 7:
            errors.append(
                f"line {lineno}: header should have 7 tokens "
                f"(action proto src sport dir dst dport), got {len(header)}"
            )
            continue

        body = line[open_paren + 1 : line.rstrip().rfind(")")]
        if "msg:" not in body:
            errors.append(f"line {lineno}: rule has no msg:")
        sid_match = re.search(r"\bsid:\s*(\d+)\s*;", body)
        if not sid_match:
            errors.append(f"line {lineno}: rule has no numeric sid:")
            continue
        sid = sid_match.group(1)
        if sid in seen_sids:
            errors.append(f"line {lineno}: duplicate sid {sid} (first seen line {seen_sids[sid]})")
        else:
            seen_sids[sid] = lineno

    return errors


def count_rules(path: str | Path) -> int:
    path = Path(path)
    return sum(
        1
        for raw in path.read_text().splitlines()
        if raw.strip() and not raw.strip().startswith("#")
    )
