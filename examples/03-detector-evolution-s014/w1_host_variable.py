"""W1 fixture: host variable bound to string literal earlier in the file.

Models the pattern from `mcp-streamablehttp-proxy` and `fastmcp-http`. The
host parameter is bound to a string literal via function-parameter default,
then passed through to the bind call. v0.1 detector required `ast.Constant`
at the call site and silently missed this shape. W1 resolves the binding
via `_collect_string_bindings` and threads it through `_extract_host_value`.

Expected: MCP-S-014 fires on this file.
"""
from typing import Optional


def run_server(
    server_command: list,
    host: str = "127.0.0.1",
    port: int = 3000,
    log_level: str = "info",
):
    """Standalone run-server function with host bound to a parameter default."""
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()

    # No Origin middleware, no auth — DNS rebind reaches this server from
    # any browser tab the operator visits.
    uvicorn.run(app, host=host, port=port, log_level=log_level)


if __name__ == "__main__":
    run_server(["python", "-m", "mcp_server_time"])
