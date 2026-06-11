#!/bin/sh
# Launch mcp-streamablehttp-proxy wrapping mcp-server-time over stdio.
#
# v0.2.0 binds to 0.0.0.0:3000 with no Origin/Host validation. The wrapped
# server (mcp-server-time) is innocuous — `get_current_time` is the only
# tool we need to invoke for the PoC to land. The vulnerability is in the
# *proxy*, not the time server.
#
# In a real-world exploitation, the same proxy could be wrapping
# mcp-server-shell (→ RCE) or mcp-server-aidd (→ fs read/write + exec).
# We use mcp-server-time here to keep the demo benign.

exec mcp-streamablehttp-proxy --host 0.0.0.0 --port 3000 \
    python3 -m mcp_server_time
