FROM python:3.12-slim

WORKDIR /app
COPY rebind_server.py /app/

EXPOSE 53/udp 53/tcp
CMD ["python3", "rebind_server.py"]
