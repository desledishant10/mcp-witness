"""Tests for the MCP fuzzer: payloads, oracle, and the engine end to end."""

from __future__ import annotations

from fuzzer.engine import run_campaign
from fuzzer.models import CallResult
from fuzzer.oracle import classify_outcome
from fuzzer.payloads import generate_cases
from fuzzer.tests import vulnerable_server as vuln

URL_TOOL = {
    "name": "fetch",
    "description": "Fetch a URL",
    "inputSchema": {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    },
}
PATH_TOOL = {
    "name": "read",
    "description": "Read a file",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}


# --------------------------------------------------------------------------- #
# Payload generation
# --------------------------------------------------------------------------- #
def test_url_param_gets_ssrf_payloads():
    cats = {c.category for c in generate_cases(URL_TOOL)}
    assert "ssrf" in cats
    values = [c.arguments["url"] for c in generate_cases(URL_TOOL) if c.category == "ssrf"]
    assert any("169.254.169.254" in str(v) for v in values)


def test_path_param_gets_traversal_payloads():
    cats = {c.category for c in generate_cases(PATH_TOOL)}
    assert "path-traversal" in cats


def test_mutations_and_protocol_cases_present_and_capped():
    cases = generate_cases(URL_TOOL, max_per_tool=20)
    cats = {c.category for c in cases}
    assert {"type-confusion", "boundary", "protocol"} <= cats
    assert len(cases) <= 20


# --------------------------------------------------------------------------- #
# Oracle
# --------------------------------------------------------------------------- #
def test_oracle_classifications():
    assert classify_outcome(CallResult(crashed=True))[0] == "crash"
    assert classify_outcome(CallResult(timed_out=True))[0] == "hang"
    assert (
        classify_outcome(CallResult(text="root:x:0:0:root:/root:/bin/bash"))[0] == "sensitive-read"
    )
    assert classify_outcome(CallResult(text='"AccessKeyId":"ASIA"'))[0] == "ssrf-hit"
    assert classify_outcome(CallResult(text="uid=0(root) gid=0(root)"))[0] == "command-injection"
    assert (
        classify_outcome(CallResult(text="Traceback (most recent call last):"))[0] == "error-leak"
    )
    assert classify_outcome(CallResult(text="sqlite3.OperationalError: bad"))[0] == "sql-error"
    assert classify_outcome(CallResult(text="ok"))[0] == "ok"
    assert classify_outcome(CallResult(text="nope", is_error=True))[0] == "rejected"


def test_clean_rejection_is_not_a_finding():
    outcome, severity, _ = classify_outcome(CallResult(text="invalid input", is_error=True))
    assert outcome == "rejected" and severity == "info"


# --------------------------------------------------------------------------- #
# Engine end to end against the in-process vulnerable server
# --------------------------------------------------------------------------- #
def test_engine_finds_every_bug_class_and_no_false_positive():
    campaign = run_campaign("vulnerable-server", vuln.TOOLS, vuln.call)
    found = {(f.tool, f.outcome) for f in campaign.findings}

    assert ("read_file", "sensitive-read") in found
    assert ("fetch", "ssrf-hit") in found
    assert ("run", "command-injection") in found
    assert ("query_db", "sql-error") in found
    assert ("parse", "error-leak") in found
    assert ("explode", "crash") in found

    # The well-behaved tool must never produce a finding.
    assert not any(f.tool == "safe_echo" for f in campaign.findings)
    assert campaign.cases_sent > 0
    assert campaign.tools_fuzzed == len(vuln.TOOLS)


def test_findings_are_deduplicated():
    campaign = run_campaign("s", vuln.TOOLS, vuln.call)
    keys = [(f.tool, f.category, f.outcome) for f in campaign.findings]
    assert len(keys) == len(set(keys))


def test_high_severity_sorts_first():
    campaign = run_campaign("s", vuln.TOOLS, vuln.call)
    severities = [f.severity for f in campaign.by_severity()]
    assert severities == sorted(
        severities, key={"info": 0, "low": 1, "medium": 2, "high": 3}.get, reverse=True
    )
