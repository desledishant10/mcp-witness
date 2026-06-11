FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Pin the vulnerable version explicitly. mcp-streamablehttp-proxy v0.2.0
# is the version under coordinated disclosure (atrawog/mcp-oauth-gateway
# monorepo) — binds 0.0.0.0:3000 with no Origin/Host validation.
RUN pip install --no-cache-dir mcp-streamablehttp-proxy==0.2.0 mcp-server-time

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 3000
CMD ["/app/start.sh"]
