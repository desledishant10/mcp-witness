"""A small, dependency-free evaluator for the subset of Sigma that the
mcp-witness detection rules use.

This is deliberately not a full Sigma implementation. It exists so the rules
in ``detections/sigma/`` can be validated against event fixtures in CI without
pulling in a Sigma toolchain or a SIEM backend. The rules themselves are
standard Sigma and convert cleanly with ``sigma-cli`` / pySigma if you want to
target a real backend; this module just lets us prove, on every commit, that
each rule fires on the attack it is meant to catch and stays quiet on benign
traffic.

Supported detection features:

* ``selection`` blocks that are a field map, or a list of field maps (OR).
* Field modifiers: ``contains``, ``startswith``, ``endswith``, ``re``,
  ``cidr`` (IP-in-range), and the numeric comparisons ``lt``/``lte``/``gt``/
  ``gte``. No modifier means case-insensitive equality.
* List values inside a field (OR within the field). A value of ``null`` matches
  an absent field.
* ``condition`` expressions over selection names using ``and`` / ``or`` /
  ``not`` / parentheses and the ``1 of <pattern>`` / ``all of <pattern>`` /
  ``... of them`` quantifiers.

String comparisons are case-insensitive, matching Sigma's default.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

Event = dict[str, Any]


# --------------------------------------------------------------------------- #
# Field-level matching
# --------------------------------------------------------------------------- #
def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _match_scalar(event_value: Any, modifier: str, target: Any) -> bool:
    """Match a single event value against a single target under one modifier."""
    if target is None:
        return event_value is None
    if event_value is None:
        return False

    if modifier == "cidr":
        try:
            return ipaddress.ip_address(str(event_value)) in ipaddress.ip_network(
                str(target), strict=False
            )
        except ValueError:
            return False

    if modifier in ("lt", "lte", "gt", "gte"):
        try:
            a, b = float(event_value), float(target)
        except (TypeError, ValueError):
            return False
        return {"lt": a < b, "lte": a <= b, "gt": a > b, "gte": a >= b}[modifier]

    if modifier == "re":
        return re.search(str(target), str(event_value), re.IGNORECASE) is not None

    haystack, needle = str(event_value).lower(), str(target).lower()
    if modifier == "contains":
        return needle in haystack
    if modifier == "startswith":
        return haystack.startswith(needle)
    if modifier == "endswith":
        return haystack.endswith(needle)
    # No (recognised) modifier: equality.
    return haystack == needle


def _match_field(event: Event, key: str, value: Any) -> bool:
    field, _, modifier = key.partition("|")
    event_value = event.get(field)
    return any(_match_scalar(event_value, modifier, t) for t in _as_list(value))


def _match_map(event: Event, spec: dict[str, Any]) -> bool:
    """All field constraints in a selection map must hold (AND)."""
    return all(_match_field(event, key, value) for key, value in spec.items())


def _match_selection(event: Event, spec: Any) -> bool:
    if isinstance(spec, list):  # list of maps => OR
        return any(_match_selection(event, sub) for sub in spec)
    if isinstance(spec, dict):
        return _match_map(event, spec)
    raise ValueError(f"unsupported selection shape: {type(spec).__name__}")


# --------------------------------------------------------------------------- #
# Condition expression parsing
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"\(|\)|\ball\b|\b1\b|\bof\b|\bthem\b|\band\b|\bor\b|\bnot\b|[\w*]+")


def _tokenize(condition: str) -> list[str]:
    return _TOKEN.findall(condition)


class _Parser:
    """Recursive-descent parser for the Sigma condition subset we support."""

    def __init__(self, tokens: list[str], names: list[str]):
        self.tokens = tokens
        self.pos = 0
        self.names = names

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self):
        node = self._parse_or()
        if self.pos != len(self.tokens):
            raise ValueError(f"unexpected token in condition: {self._peek()!r}")
        return node

    def _parse_or(self):
        node = self._parse_and()
        while self._peek() == "or":
            self._next()
            right = self._parse_and()
            node = ("or", node, right)
        return node

    def _parse_and(self):
        node = self._parse_unary()
        while self._peek() == "and":
            self._next()
            right = self._parse_unary()
            node = ("and", node, right)
        return node

    def _parse_unary(self):
        if self._peek() == "not":
            self._next()
            return ("not", self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self):
        tok = self._peek()
        if tok == "(":
            self._next()
            node = self._parse_or()
            if self._next() != ")":
                raise ValueError("unbalanced parentheses in condition")
            return node
        if tok in ("1", "all"):
            return self._parse_quantifier()
        # A bare selection name.
        return ("name", self._next())

    def _parse_quantifier(self):
        quant = self._next()  # "1" or "all"
        if self._next() != "of":
            raise ValueError("expected 'of' after quantifier")
        pattern = self._next()  # "them" or a glob like "selection*"
        matched = self.names if pattern == "them" else fnmatch.filter(self.names, pattern)
        return ("quant", quant, matched)


def _eval(node, event: Event, detection: dict[str, Any]) -> bool:
    op = node[0]
    if op == "name":
        return _match_selection(event, detection[node[1]])
    if op == "not":
        return not _eval(node[1], event, detection)
    if op == "and":
        return _eval(node[1], event, detection) and _eval(node[2], event, detection)
    if op == "or":
        return _eval(node[1], event, detection) or _eval(node[2], event, detection)
    if op == "quant":
        _, quant, names = node
        results = (_match_selection(event, detection[n]) for n in names)
        return (
            any(results)
            if quant == "1"
            else all(_match_selection(event, detection[n]) for n in names)
        )
    raise ValueError(f"unknown node: {op}")


# --------------------------------------------------------------------------- #
# Public rule object
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    id: str
    title: str
    level: str
    logsource: dict[str, Any]
    detection: dict[str, Any]
    path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], path: Path | None = None) -> Rule:
        detection = data["detection"]
        if "condition" not in detection:
            raise ValueError(f"rule {data.get('id', '?')} has no detection.condition")
        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            level=data.get("level", ""),
            logsource=data.get("logsource", {}),
            detection=detection,
            path=path,
        )

    @classmethod
    def load(cls, path: str | Path) -> Rule:
        path = Path(path)
        with path.open() as fh:
            return cls.from_dict(yaml.safe_load(fh), path)

    def matches(self, event: Event) -> bool:
        names = [k for k in self.detection if k not in ("condition", "timeframe")]
        ast = _Parser(_tokenize(self.detection["condition"]), names).parse()
        return _eval(ast, event, self.detection)


def load_rules(directory: str | Path) -> list[Rule]:
    directory = Path(directory)
    return [Rule.load(p) for p in sorted(directory.glob("*.yml"))]
