"""Classify a URL destination as reserved (SSRF-relevant) or public.

Shared by the guardrail's SSRF policy. A destination is reserved if its host is
a literal IP in a reserved range, or a hostname that resolves to one. Resolving
the hostname is what catches ``metadata.google.internal`` and any attacker
domain pointed at 169.254.169.254 or a loopback address (the DNS-rebind flip).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

# Explicit belt-and-suspenders list on top of the ipaddress properties below,
# so the intent is legible and CGNAT / all-zeros are covered on every version.
RESERVED_NETWORKS = [
    ipaddress.ip_network(c)
    for c in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_reserved_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(addr in net for net in RESERVED_NETWORKS):
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({info[4][0] for info in infos})


def url_targets_reserved(url: str, *, resolve: bool = True) -> tuple[bool, str | None]:
    """Return (is_reserved, offending_ip_or_host).

    A literal-IP host is checked directly. A hostname is resolved (when
    ``resolve`` is set) and flagged if any resolved address is reserved.
    """
    host = urlsplit(url if "://" in url else f"//{url}").hostname
    if not host:
        return (False, None)
    try:
        ipaddress.ip_address(host)
        return (True, host) if is_reserved_ip(host) else (False, None)
    except ValueError:
        pass
    if resolve:
        for ip in resolve_host(host):
            if is_reserved_ip(ip):
                return (True, ip)
    return (False, None)
