"""Data types for the MCP fuzzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Outcomes the oracle can assign to a single fuzz call.
CRASH = "crash"
HANG = "hang"
ERROR_LEAK = "error-leak"
SENSITIVE_READ = "sensitive-read"
SSRF_HIT = "ssrf-hit"
COMMAND_INJECTION = "command-injection"
SQL_ERROR = "sql-error"
OUTPUT_INJECTION = "output-injection"
REJECTED = "rejected"
OK = "ok"

# Outcomes that are NOT bugs: a clean validation rejection, or a normal result.
NON_FINDINGS = frozenset({REJECTED, OK})

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class FuzzCase:
    """One payload aimed at one tool."""

    tool: str
    arguments: dict[str, Any]
    category: str  # ssrf | path-traversal | command-injection | sql-injection | type-confusion | boundary | protocol
    param: str | None
    rationale: str


@dataclass
class CallResult:
    """The observable result of sending one FuzzCase to the server."""

    text: str = ""  # flattened response text (or error text)
    is_error: bool = False  # server returned an error result
    timed_out: bool = False
    crashed: bool = False  # server process died / transport unrecoverable
    elapsed: float = 0.0


@dataclass
class FuzzFinding:
    tool: str
    param: str | None
    category: str
    outcome: str
    severity: str
    payload: Any
    evidence: str
    excerpt: str = ""


@dataclass
class Campaign:
    """The result of a full fuzzing run."""

    server: str
    tools_fuzzed: int
    cases_sent: int
    findings: list[FuzzFinding] = field(default_factory=list)

    def by_severity(self) -> list[FuzzFinding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
