"""The fuzzing engine: drive payloads through a transport and collect findings.

The engine is transport-agnostic. It takes a ``call_fn(tool, arguments) ->
CallResult`` so the live MCP transport and the in-process test server share one
loop. Findings are deduplicated by (tool, category, outcome) so one systemic
bug does not flood the report with near-identical hits.
"""

from __future__ import annotations

from collections.abc import Callable

from fuzzer.models import CRASH, NON_FINDINGS, CallResult, Campaign, FuzzFinding
from fuzzer.oracle import classify_outcome
from fuzzer.payloads import generate_cases

CallFn = Callable[[str, dict], CallResult]
FindingSink = Callable[[FuzzFinding], None] | None


def run_campaign(
    server: str,
    tools: list[dict],
    call_fn: CallFn,
    *,
    max_per_tool: int = 48,
    on_finding: FindingSink = None,
) -> Campaign:
    findings: list[FuzzFinding] = []
    seen: set[tuple] = set()
    cases_sent = 0

    for tool in tools:
        for case in generate_cases(tool, max_per_tool=max_per_tool):
            result = call_fn(case.tool, case.arguments)
            cases_sent += 1
            outcome, severity, evidence = classify_outcome(result)
            if outcome in NON_FINDINGS:
                continue
            key = (case.tool, case.category, outcome)
            if key in seen:
                # Still stop the tool on a crash even if we already logged one.
                if outcome == CRASH:
                    break
                continue
            seen.add(key)
            finding = FuzzFinding(
                tool=case.tool,
                param=case.param,
                category=case.category,
                outcome=outcome,
                severity=severity,
                payload=case.arguments,
                evidence=evidence,
                excerpt=(result.text or "")[:300],
            )
            findings.append(finding)
            if on_finding is not None:
                on_finding(finding)
            if outcome == CRASH:
                # The server died; the transport must recover before the next
                # tool. Move on rather than hammering a dead process.
                break

    return Campaign(
        server=server, tools_fuzzed=len(tools), cases_sent=cases_sent, findings=findings
    )
