"""Turn live PoC output into normalized detection events.

The fixtures in ``fixtures/events.jsonl`` are modeled on PoC output so the rules
can be validated offline in CI. These adapters close the loop the other way:
they parse the actual stdout of the ``poc/`` quick probes into the same event
shape, so ``make validate-live`` can run a real attack and feed its evidence
through the same rules. Event schema (all fields optional except where a rule
needs them):

  proxy/egress : app, http_method, dst_ip, dst_host, uri, url
  dns          : query, answer_ip, ttl
  webserver    : dst_ip, dst_port, http_host, origin, method, uri
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit


# --------------------------------------------------------------------------- #
# Event constructors
# --------------------------------------------------------------------------- #
def egress_event(app: str, url: str, dst_ip: str | None = None, method: str = "GET") -> dict:
    parts = urlsplit(url)
    host = parts.hostname or ""
    is_ip = bool(re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+", host))
    event: dict = {
        "logsource": "proxy",
        "app": app,
        "http_method": method,
        "uri": parts.path or "/",
        "url": url,
    }
    if dst_ip:
        event["dst_ip"] = dst_ip
    elif is_ip:
        event["dst_ip"] = host
    if host and not is_ip:
        event["dst_host"] = host
    return event


def inbound_event(
    dst_ip: str,
    *,
    origin: str | None = None,
    http_host: str | None = None,
    uri: str = "/",
    method: str = "POST",
    dst_port: int | None = None,
) -> dict:
    event: dict = {"logsource": "webserver", "dst_ip": dst_ip, "uri": uri, "method": method}
    if origin is not None:
        event["origin"] = origin
    if http_host is not None:
        event["http_host"] = http_host
    if dst_port is not None:
        event["dst_port"] = dst_port
    return event


def dns_event(query: str, answer_ip: str, ttl: int) -> dict:
    return {"logsource": "dns", "query": query, "answer_ip": answer_ip, "ttl": ttl}


# --------------------------------------------------------------------------- #
# PoC stdout parsers
# --------------------------------------------------------------------------- #
_FETCH = re.compile(r"fetch\((https?://[^)\s]+)\)")


def parse_ssrf_probe(text: str, app: str = "mcp-server-fetch") -> list[dict]:
    """Extract egress events from poc/ssrf/quick_probe.py output.

    The probe prints ``simulating pre-fix fetch(<url>) ...`` for the credential
    fetch. The URL carries the cloud-credential path, which is what the egress
    rules key on.
    """
    return [egress_event(app, m.group(1)) for m in _FETCH.finditer(text)]


_PROBE = re.compile(r"probe\s+\d+:.*?hostile\s+(Origin|Host):\s*(\S+)", re.IGNORECASE)


def parse_dns_rebind_probe(
    text: str, dst_ip: str = "127.0.0.1", dst_port: int = 3000
) -> list[dict]:
    """Extract inbound events from poc/dns-rebind/quick_probe.py output.

    Each ``probe N`` line names the hostile header it sent (Origin or Host). We
    reconstruct the request the local MCP server accepted. The legitimate
    control probe (probe 1) has no hostile header and is intentionally not
    emitted, mirroring the benign fixture.
    """
    events = []
    for kind, value in _PROBE.findall(text):
        if kind.lower() == "origin":
            events.append(
                inbound_event(
                    dst_ip,
                    origin=value,
                    http_host=f"localhost:{dst_port}",
                    uri="/mcp",
                    dst_port=dst_port,
                )
            )
        else:
            events.append(
                inbound_event(
                    dst_ip,
                    origin=f"http://localhost:{dst_port}",
                    http_host=value,
                    uri="/mcp",
                    dst_port=dst_port,
                )
            )
    return events
