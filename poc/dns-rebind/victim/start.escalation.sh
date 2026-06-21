#!/bin/sh
# Launch mcp-streamablehttp-proxy wrapping mcp-server-shell over stdio.
#
# mcp-server-shell exposes a single tool: execute_command(command: str).
# When the post-rebind playwright test calls tools/call with this tool,
# the shell command runs INSIDE this container — the host filesystem,
# host processes, and any other container on the lab network are not
# reachable. Cleanup is `docker compose down -v --rmi local`.
#
# Real-world variants of this exploit would target the operator's
# workstation. This demo confines it to a container so the same attack
# sequence is observable end-to-end without putting any real system at
# risk.

exec mcp-streamablehttp-proxy --host 0.0.0.0 --port 3000 \
    python3 -m mcp_server_shell
