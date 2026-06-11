#!/usr/bin/env python3
"""Healthcheck for the rebind DNS server.

Sends a DNS A query for `evil.example` to 127.0.0.1:53 (our own listener)
and verifies a response comes back. The Docker default healthcheck path
of `socket.gethostbyname` would route via the container's /etc/resolv.conf
(Docker's embedded 127.0.0.11) which doesn't know about evil.example, so
we have to query our own server directly.

Exits 0 on healthy, 1 on unhealthy.
"""

from __future__ import annotations

import socket
import struct
import sys


def query_evil_example(timeout: float = 1.0) -> bool:
    """Send a DNS A query for evil.example to 127.0.0.1:53. True iff a response with at least one answer comes back."""
    # Construct the DNS query packet by hand — same wire format used in the server.
    #   header: txn_id=0xabcd, flags=0x0100 (standard query, recursion desired),
    #           qdcount=1, ancount=0, nscount=0, arcount=0
    header = struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    # qname: length-prefixed labels for "evil.example" + null terminator
    qname = b"\x04evil\x07example\x00"
    # qtype=A (1), qclass=IN (1)
    qtail = struct.pack(">HH", 1, 1)
    packet = header + qname + qtail

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, ("127.0.0.1", 53))
        data, _ = sock.recvfrom(512)
    except (OSError, socket.timeout):
        return False
    finally:
        sock.close()

    # Minimum well-formed response: 12-byte header + question + at least one
    # answer (10 bytes minimum for an A record's fixed fields + 4 bytes rdata).
    # We're not parsing the answer in detail; the presence of >=1 answer in
    # the header is enough to confirm the server is responding to evil.example.
    if len(data) < 12:
        return False
    ancount = struct.unpack(">H", data[6:8])[0]
    return ancount >= 1


if __name__ == "__main__":
    sys.exit(0 if query_evil_example() else 1)
