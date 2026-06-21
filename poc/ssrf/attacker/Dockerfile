FROM python:3.11-slim

# Pre-fix mcp-server-fetch is the default. Swap MCP_FETCH_VERSION at
# build time to verify the fix:
#   docker build --build-arg MCP_FETCH_VERSION=<post-fix-version> ./attacker
# or via the docker-compose top-level env var (see ../docker-compose.yml).
ARG MCP_FETCH_VERSION=2025.4.7
RUN pip install --no-cache-dir "mcp-server-fetch==${MCP_FETCH_VERSION}"

COPY attack.py /app/attack.py
WORKDIR /app

CMD ["python", "attack.py"]
