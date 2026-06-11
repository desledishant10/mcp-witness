"""W2 fixture: the word "origin" appears in a comment but the file does NOT
actually validate the Origin header anywhere.

The v0.1 detector substring-matched `origin` anywhere in the file and
suppressed S-014 — comments, docstrings, and response-header string
literals all qualified. W2 replaces the substring check with an AST walk
for actual request-header reads: `request.headers["Origin"]` (subscript)
or `request.headers.get("Origin", ...)` (method call).

Expected: MCP-S-014 fires on this file (comment is not a real Origin check).
"""

import uvicorn
from fastapi import FastAPI

app = FastAPI()

# CORS is handled by Traefik upstream — no need to configure here.
# (This comment is the W2 trap: the word "Origin" appears nowhere in
# Python code that actually inspects request headers, but the v0.1
# detector would have keyword-matched the "CORS" / "Origin"-adjacent
# language and silenced the rule.)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/mcp")
async def handle_mcp(request):
    # No Origin/Host validation anywhere in this handler. Comment above
    # gestures at "Traefik handles it" but the standalone pip-install +
    # console-script path does not have Traefik in front.
    body = await request.json()
    return {"echo": body}


uvicorn.run(app, host="127.0.0.1", port=3000)
