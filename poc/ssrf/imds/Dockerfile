FROM python:3.11-slim

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 80

# Healthcheck: confirm the IMDS endpoint is serving fake credentials.
# Used by docker-compose so the attacker only starts after IMDS is ready.
HEALTHCHECK --interval=1s --timeout=2s --retries=15 --start-period=1s \
    CMD python -c "import urllib.request; r = urllib.request.urlopen('http://127.0.0.1:80/latest/meta-data/instance-id', timeout=1); assert b'poc-demo' in r.read()" || exit 1

CMD ["python", "server.py"]
