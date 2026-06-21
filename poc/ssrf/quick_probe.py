"""Pure-Python no-docker probe demonstrating the SSRF vulnerability shape.

Runs in seconds. No Docker, no mcp-server-fetch install required.

Spins up the IMDS mock on a random local port (cannot use 169.254.169.254
in a regular process; loopback stands in for link-local since both are
RFC-reserved addresses that post-PR-#4226 mcp-server-fetch refuses) and
demonstrates two side-by-side fetches:

1. Pre-fix behavior: bare urllib.request.urlopen with no validation
   fetches the IMDS endpoint and the fake AKIA token comes back.

2. Post-fix behavior (PR #4226 shape): the same fetch passes through
   a scheme allowlist + RFC-reserved-range denylist and is refused.

The full containerized harness (`make demo-full`) uses the actual
mcp-server-fetch package and the actual link-local metadata IP. This
quick probe is for fast triage and CI smoke-checking.

Exit codes:
    0 = vulnerability shape demonstrated (default mode)
    1 = vulnerability shape demonstrated AND --exit-nonzero-on-vuln set
    2 = infrastructure failure (IMDS mock didn't start)
    3 = vulnerability shape did NOT reproduce (probe broken)
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import HTTPServer

# Make the IMDS handler importable regardless of cwd when this script is invoked.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "imds"))
from server import IMDSHandler  # noqa: E402

VULN_MARKER = "AKIA-FAKE"


def find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_imds_mock(port: int) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), IMDSHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # Wait until the server is actually accepting requests.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/latest/meta-data/instance-id", timeout=0.5
            ) as r:
                r.read()
            return server
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.05)
    server.shutdown()
    raise RuntimeError(f"IMDS mock failed to start on port {port}")


def fetch_unvalidated(url: str) -> str:
    """Pre-fix mcp-server-fetch behavior distilled: fetch with no validation."""
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.read().decode("utf-8", errors="replace")


def fetch_validated(url: str) -> str:
    """Post-fix (PR #4226) mcp-server-fetch behavior distilled.

    Scheme allowlist + RFC-reserved-range denylist applied to the URL's
    host. Returns the refusal message instead of fetching when blocked.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "Refused: only http/https schemes are allowed."
    host = parsed.hostname or ""
    try:
        host_ip = ipaddress.ip_address(host)
        if (
            host_ip.is_private
            or host_ip.is_loopback
            or host_ip.is_link_local
            or host_ip.is_reserved
            or host_ip.is_multicast
            or host_ip.is_unspecified
        ):
            return "Fetching private or non-public IP addresses is not allowed."
    except ValueError:
        # Not an IP literal. Real PR #4226 also resolves DNS and re-checks.
        pass
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.read().decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--exit-nonzero-on-vuln",
        action="store_true",
        help="for monitoring / CI: exit 1 if vulnerability shape is confirmed",
    )
    args = parser.parse_args()

    print("=" * 65)
    print(" SSRF PoC quick probe (no Docker, no mcp-server-fetch install)")
    print("=" * 65)
    print()
    print(" disclosure: modelcontextprotocol/servers#4143")
    print(" fix:        modelcontextprotocol/servers PR #4226 (kgarg2468)")
    print(" embargo:    not embargoed; vulnerability publicly disclosed 2026-05-12.")
    print()

    port = find_free_port()
    print(f"[1/4] starting IMDS mock on 127.0.0.1:{port} ...")
    try:
        server = start_imds_mock(port)
    except RuntimeError as e:
        print(f"INFRA: {e}", file=sys.stderr)
        return 2
    print("        ready (loopback stands in for link-local 169.254.169.254)")
    print()

    target_url = f"http://127.0.0.1:{port}/latest/meta-data/iam/security-credentials/poc-demo-role"

    print(f"[2/4] simulating pre-fix fetch({target_url}) ...")
    pre_body = fetch_unvalidated(target_url)
    print(f"        response body: {pre_body.strip()[:200]}")
    vuln_confirmed = VULN_MARKER in pre_body
    print(f"        vulnerable (AKIA-FAKE token in response): {vuln_confirmed}")
    print()

    print(f"[3/4] simulating post-fix (PR #4226) fetch({target_url}) ...")
    post_body = fetch_validated(target_url)
    print(f"        response: {post_body.strip()[:200]}")
    fix_confirmed = "not allowed" in post_body.lower() or "refused" in post_body.lower()
    print(f"        refused: {fix_confirmed}")
    print()

    print("[4/4] shutdown mock ...")
    server.shutdown()
    print()

    if vuln_confirmed and fix_confirmed:
        print("=" * 65)
        print(" QUICK PROBE RESULT: vulnerability shape demonstrated.")
        print("=" * 65)
        print(" Pre-fix mcp-server-fetch's lack of scheme/host validation lets")
        print(" any URL through, including link-local cloud-metadata addresses.")
        print(" The PR #4226 fix shape refuses the same URL via reserved-range")
        print(" denylist.")
        print()
        print(" Run 'make demo-full' for the full containerized reproduction")
        print(" against the actual mcp-server-fetch v2025.4.7 package.")
        return 1 if args.exit_nonzero_on_vuln else 0

    print("=" * 65)
    print(" QUICK PROBE RESULT: shape did NOT reproduce as expected.")
    print("=" * 65)
    print(f" vuln_confirmed={vuln_confirmed}, fix_confirmed={fix_confirmed}")
    return 3


if __name__ == "__main__":
    sys.exit(main())
