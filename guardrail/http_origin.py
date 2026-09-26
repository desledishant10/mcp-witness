"""Inbound Origin/Host enforcement for HTTP-transport MCP servers.

This is the defensive counterpart to the DNS-rebinding class: an HTTP-transport
MCP server that does not validate the inbound ``Origin`` and ``Host`` headers
will process a request from any web origin, so any page an operator visits can
drive their local MCP tools. The fix, per the disclosure writeup, is a few
lines of middleware that reject requests whose Origin/Host are not allowlisted.

``OriginHostPolicy`` is the pure decision. The middleware wrappers below apply
it to the three server stacks the disclosed packages use: ASGI (Starlette /
FastAPI), WSGI (Flask), and aiohttp. Decisions reuse the guardrail ``Decision``
type and emit events in the detections webserver schema, so a runtime block and
the ``mcp_dns_rebind_origin_host_mismatch`` detection describe the same event.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from guardrail.policy import Decision

_LOCAL_HOST = re.compile(r"^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$", re.IGNORECASE)
_LOCAL_ORIGIN = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?/?$", re.IGNORECASE)


@dataclass
class OriginHostPolicy:
    """Reject inbound requests whose Origin/Host are not allowlisted.

    Localhost origins and hosts are allowed by default (``allow_localhost``),
    which is the safe posture for a locally-bound MCP server. Add explicit
    entries for a legitimate cross-origin local app. mode="monitor" flags
    without blocking.
    """

    allowed_origins: set[str] = field(default_factory=set)
    allowed_hosts: set[str] = field(default_factory=set)
    allow_localhost: bool = True
    mode: str = "block"

    def _host_ok(self, host: str) -> bool:
        if host in self.allowed_hosts:
            return True
        return self.allow_localhost and bool(_LOCAL_HOST.match(host))

    def _origin_ok(self, origin: str) -> bool:
        if origin in self.allowed_origins:
            return True
        return self.allow_localhost and bool(_LOCAL_ORIGIN.match(origin))

    def check(self, origin: str | None, host: str | None) -> Decision:
        if host is not None and host != "" and not self._host_ok(host):
            return self._stop(
                f"Host header '{host}' is not allowed", "http-host-mismatch", origin, host
            )
        if origin is not None and origin != "" and not self._origin_ok(origin):
            return self._stop(
                f"Origin '{origin}' is not allowed", "http-origin-mismatch", origin, host
            )
        return Decision("allow")

    def _stop(self, reason: str, rule: str, origin: str | None, host: str | None) -> Decision:
        event = {
            "logsource": "webserver",
            "origin": origin,
            "http_host": host,
            "rule": rule,
        }
        return Decision("deny" if self.mode == "block" else "flag", reason, rule, event)


def _headers_from_asgi(scope) -> tuple[str | None, str | None]:
    origin = host = None
    for key, value in scope.get("headers", []):
        name = key.decode("latin-1").lower()
        if name == "origin":
            origin = value.decode("latin-1")
        elif name == "host":
            host = value.decode("latin-1")
    return origin, host


class OriginGuardASGI:
    """ASGI middleware (Starlette / FastAPI). Wrap your app:

    ``app = OriginGuardASGI(app, OriginHostPolicy())``
    """

    def __init__(self, app, policy: OriginHostPolicy | None = None, on_event=None):
        self.app = app
        self.policy = policy or OriginHostPolicy()
        self.on_event = on_event

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        origin, host = _headers_from_asgi(scope)
        decision = self.policy.check(origin, host)
        if decision.blocked:
            if self.on_event:
                self.on_event(decision)
            body = json.dumps({"error": decision.reason, "rule": decision.rule}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


class OriginGuardWSGI:
    """WSGI middleware (Flask and friends). Wrap your app:

    ``app.wsgi_app = OriginGuardWSGI(app.wsgi_app, OriginHostPolicy())``
    """

    def __init__(self, app, policy: OriginHostPolicy | None = None, on_event=None):
        self.app = app
        self.policy = policy or OriginHostPolicy()
        self.on_event = on_event

    def __call__(self, environ, start_response):
        origin = environ.get("HTTP_ORIGIN")
        host = environ.get("HTTP_HOST")
        decision = self.policy.check(origin, host)
        if decision.blocked:
            if self.on_event:
                self.on_event(decision)
            body = json.dumps({"error": decision.reason, "rule": decision.rule}).encode()
            start_response(
                "403 Forbidden",
                [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
            )
            return [body]
        return self.app(environ, start_response)


def aiohttp_origin_guard(policy: OriginHostPolicy | None = None, on_event=None):
    """Return an aiohttp middleware enforcing the policy."""
    from aiohttp import web

    policy = policy or OriginHostPolicy()

    @web.middleware
    async def middleware(request, handler):
        decision = policy.check(request.headers.get("Origin"), request.headers.get("Host"))
        if decision.blocked:
            if on_event:
                on_event(decision)
            return web.json_response({"error": decision.reason, "rule": decision.rule}, status=403)
        return await handler(request)

    return middleware
