"""Unit tests for payload macro substitution."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass

from harness.macros import substitute


@dataclass
class _FakeCanary:
    url: str
    token: str


def _ctx(**overrides):
    base = {"run_id": "RUN", "canaries": {}, "fixtures": {}}
    base.update(overrides)
    return base


def test_no_macros_passthrough():
    assert substitute("plain text", _ctx()) == "plain text"


def test_run_id_substitution():
    assert substitute("run-{run_id}-end", _ctx(run_id="abc")) == "run-abc-end"


def test_tmp_substitution():
    assert substitute("{tmp}/foo", _ctx()) == f"{tempfile.gettempdir()}/foo"


def test_canary_url_substitution():
    canaries = {"exfil": _FakeCanary("http://127.0.0.1:5000/tok", "tok")}
    out = substitute("{canary:exfil}/?d=", _ctx(canaries=canaries))
    assert out == "http://127.0.0.1:5000/tok/?d="


def test_canary_token_substitution():
    canaries = {"x": _FakeCanary("u", "TOKEN")}
    out = substitute("token={canary_token:x}", _ctx(canaries=canaries))
    assert out == "token=TOKEN"


def test_path_substitution():
    fixtures = {"file1": "/tmp/foo.txt"}
    out = substitute("read {path:file1}", _ctx(fixtures=fixtures))
    assert out == "read /tmp/foo.txt"


def test_payload_substitution():
    out = substitute("payload={payload}", _ctx(payload="ABC"))
    assert out == "payload=ABC"


def test_unicode_tags_encodes_printable_ascii():
    out = substitute("{unicode_tags:hi}", _ctx())
    # 'h' = 0x68, 'i' = 0x69 → U+E0068, U+E0069
    assert out == chr(0xE0000 + 0x68) + chr(0xE0000 + 0x69)
    assert len(out) == 2


def test_unicode_tags_drops_non_printable():
    out = substitute("{unicode_tags:a\nb}", _ctx())
    # Newline (0x0A) is dropped; 'a' and 'b' encoded.
    assert out == chr(0xE0000 + 0x61) + chr(0xE0000 + 0x62)


def test_unicode_tags_wraps_already_expanded_canary():
    """Two-pass substitution: canary expands first, then unicode_tags wraps."""
    canaries = {"x": _FakeCanary("https://canary.example/abc", "abc")}
    out = substitute("{unicode_tags:fetch {canary:x}}", _ctx(canaries=canaries))
    inner = "fetch https://canary.example/abc"
    expected = "".join(chr(0xE0000 + ord(c)) for c in inner if 0x20 <= ord(c) <= 0x7E)
    assert out == expected


def test_unknown_macro_left_alone():
    out = substitute("hello {unknown:foo} world", _ctx())
    assert out == "hello {unknown:foo} world"


def test_multiple_macros_in_one_string():
    canaries = {"a": _FakeCanary("URL_A", "T_A")}
    out = substitute(
        "run={run_id} url={canary:a} token={canary_token:a}",
        _ctx(run_id="R1", canaries=canaries),
    )
    assert out == "run=R1 url=URL_A token=T_A"
