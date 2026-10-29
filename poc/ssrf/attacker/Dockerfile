FROM python:3.11-slim

# git is needed when MCP_FETCH_SPEC points at a git URL (e.g. the
# never-merged PR #4226 branch used by the historical demo-fixed target).
# The shipped fix is on PyPI (2026.10.10+); demo-fixed-release installs it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Default: install the pre-fix release pinned at the version disclosed in
# modelcontextprotocol/servers#4143. demo-fixed-release overrides this with
# the fixed PyPI release; demo-fixed with the PR #4226 branch. Any
# pip-installable spec works.
ARG MCP_FETCH_SPEC="mcp-server-fetch==2025.4.7"
RUN pip install --no-cache-dir "${MCP_FETCH_SPEC}"

COPY attack.py /app/attack.py
WORKDIR /app

CMD ["python", "attack.py"]
