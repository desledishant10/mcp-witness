"""stdio transport for the guardrail.

MCP's stdio transport is newline-delimited JSON-RPC: one JSON object per line.
The proxy launches the downstream server as a subprocess and sits between it and
the client, running each message through the interceptor. The two directions are
implemented as ``pump_*`` functions over plain byte-line iterators so they can be
tested without spawning a process.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable
from typing import IO

from guardrail.interceptor import intercept_client_request, intercept_server_response
from guardrail.policy import Decision, GuardrailPolicy

EventSink = Callable[[Decision], None] | None


def _encode(message: dict) -> bytes:
    return (json.dumps(message) + "\n").encode()


def _emit(sink: EventSink, decision: Decision) -> None:
    if sink is not None:
        sink(decision)


def pump_client_to_server(
    lines: Iterable[bytes],
    forward_write: Callable[[bytes], None],
    reply_write: Callable[[bytes], None],
    policy: GuardrailPolicy,
    on_event: EventSink = None,
) -> None:
    """Client -> server: forward safe messages, short-circuit blocked calls."""
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError:
            forward_write(raw if raw.endswith(b"\n") else raw + b"\n")
            continue
        result = intercept_client_request(policy, message)
        for decision in result.decisions:
            _emit(on_event, decision)
        if result.forward is not None:
            forward_write(_encode(result.forward))
        if result.reply is not None:
            reply_write(_encode(result.reply))


def pump_server_to_client(
    lines: Iterable[bytes],
    client_write: Callable[[bytes], None],
    policy: GuardrailPolicy,
    on_event: EventSink = None,
) -> None:
    """Server -> client: forward everything, record tool-definition changes."""
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError:
            client_write(raw if raw.endswith(b"\n") else raw + b"\n")
            continue
        result = intercept_server_response(policy, message)
        for decision in result.decisions:
            _emit(on_event, decision)
        if result.forward is not None:
            client_write(_encode(result.forward))


def default_event_sink(decision: Decision) -> None:
    """Log a guardrail decision as a JSON line on stderr."""
    record = {
        "guardrail": decision.action,
        "rule": decision.rule,
        "reason": decision.reason,
        "event": decision.event,
    }
    sys.stderr.write(json.dumps(record) + "\n")
    sys.stderr.flush()


def _locked_writer(stream: IO[bytes], lock: threading.Lock) -> Callable[[bytes], None]:
    def write(data: bytes) -> None:
        with lock:
            stream.write(data)
            stream.flush()

    return write


class StdioGuardrailProxy:
    """Wrap a downstream stdio MCP server with the guardrail."""

    def __init__(
        self,
        server_cmd: list[str],
        policy: GuardrailPolicy | None = None,
        on_event: EventSink = default_event_sink,
    ):
        self.server_cmd = server_cmd
        self.policy = policy or GuardrailPolicy()
        self.on_event = on_event

    def run(self, client_in: IO[bytes] | None = None, client_out: IO[bytes] | None = None) -> int:
        client_in = client_in or sys.stdin.buffer
        client_out = client_out or sys.stdout.buffer
        proc = subprocess.Popen(self.server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out_lock = threading.Lock()
        to_client = _locked_writer(client_out, out_lock)
        to_server = _locked_writer(proc.stdin, threading.Lock())

        def upstream() -> None:
            pump_client_to_server(
                iter(client_in.readline, b""), to_server, to_client, self.policy, self.on_event
            )
            # Client disconnected: close the server's stdin so it can exit.
            try:
                proc.stdin.close()
            except OSError:
                pass

        def downstream() -> None:
            pump_server_to_client(
                iter(proc.stdout.readline, b""), to_client, self.policy, self.on_event
            )

        up = threading.Thread(target=upstream, daemon=True)
        down = threading.Thread(target=downstream, daemon=True)
        up.start()
        down.start()
        returncode = proc.wait()
        down.join(timeout=2)
        return returncode
