"""W3 fixture: aiohttp `web.TCPSite` bind shape with positional host arg.

Models the pattern from `mcp-server-fetch-sse`. aiohttp's `web.TCPSite`
takes the host as a positional argument (not a keyword), and the v0.1
detector only knew about `uvicorn.run` and `app.run` shapes. W3 extends
`_SERVER_BIND_METHODS` to include `web.TCPSite` (and `web.run_app` for the
keyword-host pattern).

Expected: MCP-S-014 fires on this file.
"""

import asyncio

from aiohttp import web


async def start_server(host: str = "localhost", port: int = 3001) -> None:
    app = web.Application()
    app.router.add_get("/sse", lambda request: web.Response(text="ok"))
    app.router.add_post("/message", lambda request: web.json_response({}))

    runner = web.AppRunner(app)
    await runner.setup()

    # W3 case: positional host arg via TCPSite. localhost bind is still
    # rebindable from a browser tab — the rebind primitive is the
    # attacker's *domain*, not the resolved IP.
    site = web.TCPSite(runner, host, port)
    await site.start()

    print(f"Server running on http://{host}:{port}")
    await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(start_server())
