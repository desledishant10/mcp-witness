"""W4 fixture: host bound from os.getenv with a string-literal default.

Models the pattern from `mcp-fetch-streamablehttp-server`. The bind host is
read from an environment variable with a literal default — the env-var
fallback IS the deployed bind in production. v0.1 detector resolved
`ast.Assign` to literal strings but didn't unpack `os.getenv(name, default)`
calls. W4 adds `_extract_env_default(call)` that handles both `os.getenv`
and `os.environ.get` shapes.

Expected: MCP-S-014 fires on this file (host resolves to "0.0.0.0").
"""

import os

import uvicorn
from fastapi import FastAPI

# W4 case: the literal default value of the env var is what gets used in
# the typical deployment. Bandit-S104 noqa is exactly the kind of marker
# that indicates the author KNEW it was a 0.0.0.0 bind and chose to keep it.
host = os.getenv("HOST", "0.0.0.0")  # noqa: S104
port = int(os.getenv("PORT", "3000"))

app = FastAPI()


@app.post("/mcp")
async def handle_mcp(request):
    body = await request.json()
    return {"echo": body}


# No middleware, no Origin check, no auth — and the bind is 0.0.0.0 by
# default. Every network interface, every browser on every device on the
# LAN can hit /mcp directly.
uvicorn.run(app, host=host, port=port)
