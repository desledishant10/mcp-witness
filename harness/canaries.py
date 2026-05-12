"""Canary HTTP server for detecting exfil attempts in dynamic scenarios.

Allocates per-run endpoints under unique tokens, records every hit, and
exposes them for oracle evaluation. DNS and filesystem canaries are TODO
for v0.2.
"""

from __future__ import annotations

import secrets
import socket
import time
from dataclasses import dataclass, field

from aiohttp import web


@dataclass
class CanaryHit:
    ts: float
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes


@dataclass
class Canary:
    id: str
    token: str
    url: str = ""
    hits: list[CanaryHit] = field(default_factory=list)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CanaryServer:
    """HTTP server that records hits to allocated canary endpoints.

    Each canary is reachable at http://<host>:<port>/<token>/... — any
    method, any subpath, any query string, any body is captured.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self.canaries: dict[str, Canary] = {}    # token -> Canary
        self._by_id: dict[str, Canary] = {}      # canary id -> Canary
        self._runner: web.AppRunner | None = None

    async def start(self) -> None:
        if self.port == 0:
            self.port = _free_port()
        app = web.Application()
        app.router.add_route("*", "/{token}", self._handle)
        app.router.add_route("*", "/{token}/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    def allocate(self, canary_id: str) -> Canary:
        token = secrets.token_urlsafe(12)
        c = Canary(id=canary_id, token=token,
                   url=f"http://{self.host}:{self.port}/{token}")
        self.canaries[token] = c
        self._by_id[canary_id] = c
        return c

    def by_id(self, canary_id: str) -> Canary | None:
        return self._by_id.get(canary_id)

    async def _handle(self, req: web.Request) -> web.Response:
        token = req.match_info["token"]
        canary = self.canaries.get(token)
        if not canary:
            return web.Response(status=404)
        body = await req.read()
        canary.hits.append(CanaryHit(
            ts=time.time(),
            method=req.method,
            path=req.path,
            query=req.query_string,
            headers=dict(req.headers),
            body=body,
        ))
        return web.Response(status=204)
