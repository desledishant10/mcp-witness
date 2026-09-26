"""End-to-end test: the guardrail proxy in front of a real server subprocess.

Proves the SSRF tool call is refused by the guardrail before it can reach the
downstream server, while a safe call round-trips normally.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from guardrail.policy import GuardrailPolicy
from guardrail.proxy import StdioGuardrailProxy

FAKE_SERVER = str(Path(__file__).parent / "fake_server.py")
IMDS = "http://169.254.169.254/latest/meta-data/iam/security-credentials/role/"


def _line(**msg) -> bytes:
    return (json.dumps(msg) + "\n").encode()


def test_guardrail_blocks_ssrf_before_it_reaches_the_server():
    requests = _line(
        jsonrpc="2.0",
        id=1,
        method="tools/call",
        params={"name": "fetch", "arguments": {"url": "https://example.com"}},
    ) + _line(
        jsonrpc="2.0",
        id=2,
        method="tools/call",
        params={"name": "fetch", "arguments": {"url": IMDS}},
    )
    client_in = io.BytesIO(requests)
    client_out = io.BytesIO()

    proxy = StdioGuardrailProxy(
        [sys.executable, FAKE_SERVER],
        GuardrailPolicy(resolve_dns=False),
        on_event=None,
    )
    returncode = proxy.run(client_in=client_in, client_out=client_out)
    out = client_out.getvalue().decode()

    assert returncode == 0
    # The safe call round-tripped to the server and back.
    assert "fetched https://example.com" in out
    # The SSRF call was refused by the guardrail; the server never leaked.
    assert "LEAKED-CREDENTIALS" not in out
    assert "blocked by mcp-witness guardrail" in out
