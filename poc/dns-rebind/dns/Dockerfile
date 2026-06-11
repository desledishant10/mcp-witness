FROM python:3.12-slim

WORKDIR /app
COPY rebind_server.py /app/
COPY healthcheck.py /app/

EXPOSE 53/udp 53/tcp
HEALTHCHECK --interval=2s --timeout=2s --retries=5 --start-period=2s \
    CMD python3 /app/healthcheck.py
CMD ["python3", "rebind_server.py"]
