"""Mock cloud metadata service (IMDSv1-style) for the SSRF PoC harness.

Mimics the EC2 Instance Metadata Service that mcp-server-fetch's SSRF
disclosure (modelcontextprotocol/servers#4143) targeted. Listens on the
link-local cloud-metadata IP 169.254.169.254:80 inside a custom Docker
network.

CREDENTIAL VALUES BELOW ARE FAKE. They are obviously fake on purpose
("AKIA-FAKE-NEVER-USE-..."). Nobody should mistake them for real
credentials. The harness confirms vulnerability by observing whether
the AKIA prefix string flows back through the mcp-server-fetch JSON-RPC
response; it does not need (or use) real cloud credentials.

The endpoints implemented are the minimum subset that mcp-server-fetch
would hit when an agent tool-call is coerced into reading IAM
credentials via prompt injection. This is also the subset that AWS's
IMDSv1 implementation responds to without an X-aws-ec2-metadata-token
header, matching the original disclosure's IMDSv2-Optional / IMDSv1
exposure model.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ROLE_NAME = "poc-demo-role"

# Fake credentials. The literal strings "FAKE" and "DO-NOT-USE" appear
# multiple times so anyone reading the harness output cannot plausibly
# mistake them for real values.
FAKE_CREDENTIALS = {
    "Code": "Success",
    "LastUpdated": "2026-06-20T12:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "AKIA-FAKE-NEVER-USE-DEMO",
    "SecretAccessKey": "FAKE-SECRET-KEY-DO-NOT-USE-IN-REAL-CODE",
    "Token": "FAKE-SESSION-TOKEN-POC-DEMO-ONLY-NEVER-USE",
    "Expiration": "2026-12-31T23:59:59Z",
}


class IMDSHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.rstrip("/")

        if path == "/latest/meta-data":
            self._respond_text(
                "ami-id\nhostname\niam/\ninstance-id\ninstance-type\nlocal-ipv4\n"
            )
        elif path == "/latest/meta-data/iam":
            self._respond_text("security-credentials/\n")
        elif path == "/latest/meta-data/iam/security-credentials":
            self._respond_text(ROLE_NAME + "\n")
        elif path == f"/latest/meta-data/iam/security-credentials/{ROLE_NAME}":
            self._respond_json(FAKE_CREDENTIALS)
        elif path == "/latest/meta-data/instance-id":
            self._respond_text("i-poc-demo-instance-id")
        elif path == "/latest/meta-data/ami-id":
            self._respond_text("ami-poc-demo")
        elif path == "/latest/meta-data/local-ipv4":
            self._respond_text("169.254.169.254")
        elif path == "/latest/meta-data/instance-type":
            self._respond_text("t3.micro")
        elif path == "/latest/meta-data/hostname":
            self._respond_text("ip-poc-demo.compute.internal")
        elif path == "/":
            self._respond_text("latest/\n")
        elif path == "/latest":
            self._respond_text("meta-data/\nuser-data/\n")
        else:
            self._respond_text("Not Found\n", status=404)

    def _respond_text(self, body: str, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Server", "EC2ws")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _respond_json(self, obj: dict, status: int = 200) -> None:
        body = json.dumps(obj, indent=2)
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "EC2ws")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"IMDS: {self.address_string()} - {fmt % args}\n")
        sys.stderr.flush()


def main() -> None:
    import os

    port = int(os.environ.get("IMDS_PORT", "80"))
    bind = ("0.0.0.0", port)
    server = HTTPServer(bind, IMDSHandler)
    print(f"IMDS mock listening on {bind[0]}:{bind[1]}", flush=True)
    print(f"Serving fake credentials for role: {ROLE_NAME}", flush=True)
    print("All credential values are obviously fake. Not for real use.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
