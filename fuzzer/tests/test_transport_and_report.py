"""Tests for the transport parsing helpers and the report formatter.

The live transport itself needs a real MCP server, exercised via the CLI; here
we cover the pure pieces: flattening an MCP result, tool-dict coercion, and the
text/JSON report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from fuzzer import report, transport
from fuzzer.engine import run_campaign
from fuzzer.tests import vulnerable_server as vuln


@dataclass
class _FakeModel:
    """Stands in for a pydantic model with .model_dump()."""

    data: dict

    def model_dump(self, mode: str = "json") -> dict:
        return self.data


def test_flatten_joins_text_content():
    result = _FakeModel(
        {
            "content": [{"type": "text", "text": "hello"}, {"type": "text", "text": "world"}],
            "isError": False,
        }
    )
    text, is_error = transport._flatten(result)
    assert text == "hello\nworld" and is_error is False


def test_flatten_marks_error():
    result = _FakeModel({"content": [{"type": "text", "text": "boom"}], "isError": True})
    text, is_error = transport._flatten(result)
    assert text == "boom" and is_error is True


def test_tool_to_dict_uses_model_dump():
    tool = _FakeModel({"name": "t", "description": "d", "inputSchema": {}})
    assert transport._tool_to_dict(tool)["name"] == "t"


def test_report_text_lists_findings():
    campaign = run_campaign("s", vuln.TOOLS, vuln.call)
    text = report.format_report(campaign)
    assert "MCP fuzz campaign" in text
    assert "HIGH" in text
    assert "sensitive-read" in text


def test_report_json_serializes():
    campaign = run_campaign("s", vuln.TOOLS, vuln.call)
    blob = json.dumps(report.to_dict(campaign), default=str)
    assert '"findings"' in blob


def test_empty_campaign_report():
    @dataclass
    class _Empty:
        server: str = "s"
        tools_fuzzed: int = 0
        cases_sent: int = 0
        findings: list = field(default_factory=list)

    text = report.format_report(_Empty())
    assert "No findings" in text
