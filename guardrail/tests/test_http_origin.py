"""Tests for the inbound HTTP Origin/Host guardrail."""

from __future__ import annotations

import pytest

from guardrail.http_origin import (
    OriginGuardASGI,
    OriginGuardWSGI,
    OriginHostPolicy,
    aiohttp_origin_guard,
)


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
def test_policy_allows_localhost_and_absent_headers():
    p = OriginHostPolicy()
    assert p.check(None, "localhost:3000").clean
    assert p.check("http://localhost:3000", "localhost:3000").clean
    assert p.check("http://127.0.0.1", "127.0.0.1:8000").clean
    assert p.check(None, None).clean


def test_policy_blocks_external_origin_and_host():
    p = OriginHostPolicy()
    blocked_origin = p.check("https://evil.example", "localhost:3000")
    assert blocked_origin.blocked and blocked_origin.rule == "http-origin-mismatch"
    blocked_host = p.check("http://localhost:3000", "evil.example")
    assert blocked_host.blocked and blocked_host.rule == "http-host-mismatch"


def test_policy_allowlist_exempts():
    p = OriginHostPolicy(allowed_origins={"https://app.local"}, allowed_hosts={"app.local"})
    assert p.check("https://app.local", "app.local").clean


def test_policy_monitor_mode_flags():
    d = OriginHostPolicy(mode="monitor").check("https://evil.example", "localhost:3000")
    assert d.action == "flag" and not d.blocked


def test_policy_event_matches_detections_schema():
    d = OriginHostPolicy().check("https://evil.example", "localhost:3000")
    assert d.event["logsource"] == "webserver"
    assert d.event["origin"] == "https://evil.example"


# --------------------------------------------------------------------------- #
# ASGI middleware
# --------------------------------------------------------------------------- #
def _asgi_scope(origin=None, host="localhost:3000", scope_type="http"):
    headers = []
    if host is not None:
        headers.append((b"host", host.encode()))
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    return {"type": scope_type, "headers": headers}


@pytest.mark.asyncio
async def test_asgi_blocks_external_origin_with_403():
    downstream_called = False

    async def app(scope, receive, send):
        nonlocal downstream_called
        downstream_called = True

    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {}

    guard = OriginGuardASGI(app, OriginHostPolicy())
    await guard(_asgi_scope(origin="https://evil.example"), receive, send)

    assert downstream_called is False
    assert sent[0]["status"] == 403
    assert b"not allowed" in sent[1]["body"]


@pytest.mark.asyncio
async def test_asgi_allows_localhost_and_passes_through():
    downstream_called = False

    async def app(scope, receive, send):
        nonlocal downstream_called
        downstream_called = True

    async def send(msg):
        pass

    async def receive():
        return {}

    guard = OriginGuardASGI(app, OriginHostPolicy())
    await guard(_asgi_scope(origin="http://localhost:3000"), receive, send)
    assert downstream_called is True


@pytest.mark.asyncio
async def test_asgi_ignores_non_http_scopes():
    downstream_called = False

    async def app(scope, receive, send):
        nonlocal downstream_called
        downstream_called = True

    guard = OriginGuardASGI(app, OriginHostPolicy())
    await guard({"type": "websocket", "headers": []}, None, None)
    assert downstream_called is True


# --------------------------------------------------------------------------- #
# WSGI middleware
# --------------------------------------------------------------------------- #
def test_wsgi_blocks_external_host_with_403():
    def app(environ, start_response):
        start_response("200 OK", [])
        return [b"ok"]

    captured = {}

    def start_response(status, headers):
        captured["status"] = status

    guard = OriginGuardWSGI(app, OriginHostPolicy())
    body = guard(
        {"HTTP_HOST": "evil.example", "HTTP_ORIGIN": "http://localhost:3000"}, start_response
    )
    assert captured["status"].startswith("403")
    assert b"not allowed" in b"".join(body)


def test_wsgi_allows_localhost():
    downstream_called = False

    def app(environ, start_response):
        nonlocal downstream_called
        downstream_called = True
        start_response("200 OK", [])
        return [b"ok"]

    guard = OriginGuardWSGI(app, OriginHostPolicy())
    guard({"HTTP_HOST": "localhost:3000"}, lambda status, headers: None)
    assert downstream_called is True


# --------------------------------------------------------------------------- #
# aiohttp factory
# --------------------------------------------------------------------------- #
def test_aiohttp_middleware_factory_is_callable():
    middleware = aiohttp_origin_guard(OriginHostPolicy())
    assert callable(middleware)
