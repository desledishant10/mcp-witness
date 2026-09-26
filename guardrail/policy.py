"""The guardrail policy engine: pure decisions over MCP messages.

``GuardrailPolicy`` holds no I/O. It is fed tool calls and tool lists and
returns a ``Decision``. The stdio proxy wires it to real streams; the tests
drive it directly.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from guardrail import netcheck

# Parameter names that conventionally carry a URL in MCP fetch-family tools.
URL_PARAM_NAMES = {"url", "uri", "endpoint", "link", "target", "address", "href"}


@dataclass
class Decision:
    action: str  # "allow" | "deny" | "flag"
    reason: str = ""
    rule: str = ""
    event: dict | None = None

    @property
    def blocked(self) -> bool:
        return self.action == "deny"

    @property
    def clean(self) -> bool:
        return self.action == "allow"


@dataclass
class GuardrailPolicy:
    """Runtime policy for MCP traffic.

    mode="block" refuses offending calls; mode="monitor" only flags them (the
    proxy still forwards). ``allow_hosts`` exempts explicit internal hosts an
    operator legitimately fetches. ``resolve_dns`` controls whether hostnames
    are resolved for the SSRF check.
    """

    mode: str = "block"
    resolve_dns: bool = True
    allow_hosts: set[str] = field(default_factory=set)
    server_name: str = "mcp-server"
    _pinned: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _changed: set[str] = field(default_factory=set, init=False, repr=False)

    # -- SSRF on tool calls -------------------------------------------------- #
    def check_tool_call(self, name: str | None, arguments: dict | None) -> Decision:
        # A call to a tool whose definition was mutated after first sight.
        if name in self._changed:
            return self._stop(
                f"tool '{name}' was called after its definition changed (rug pull)",
                "tool-rug-pull",
                {
                    "logsource": "mcp",
                    "server": self.server_name,
                    "tool": name,
                    "kind": "rug_pull_call",
                },
            )

        for key, value in (arguments or {}).items():
            if not isinstance(value, str):
                continue
            if not (key.lower() in URL_PARAM_NAMES or value.startswith(("http://", "https://"))):
                continue
            host = urlsplit(value if "://" in value else f"//{value}").hostname
            if host and host in self.allow_hosts:
                continue
            reserved, offender = netcheck.url_targets_reserved(value, resolve=self.resolve_dns)
            if reserved:
                return self._stop(
                    f"tool '{name}' argument '{key}' targets reserved address {offender}",
                    "ssrf-reserved-egress",
                    {
                        "logsource": "proxy",
                        "app": self.server_name,
                        "http_method": "GET",
                        "dst_ip": offender,
                        "uri": urlsplit(value).path or "/",
                        "url": value,
                    },
                )
        return Decision("allow")

    # -- tools/list rug-pull detection --------------------------------------- #
    def observe_tools(self, tools: list[dict]) -> list[Decision]:
        """Pin tool definitions on first sight; flag any that change afterward.

        Returns a Decision for every tool whose definition changed since it was
        first observed. The first observation of each tool always pins and
        allows.
        """
        decisions: list[Decision] = []
        for tool in tools:
            tname = tool.get("name")
            if tname is None:
                continue
            digest = self._hash(tool)
            pinned = self._pinned.get(tname)
            if pinned is None:
                self._pinned[tname] = digest
                continue
            if pinned != digest:
                self._changed.add(tname)
                decisions.append(
                    self._stop(
                        f"tool '{tname}' definition changed since first approval",
                        "tool-rug-pull",
                        {
                            "logsource": "mcp",
                            "server": self.server_name,
                            "tool": tname,
                            "kind": "rug_pull_list",
                        },
                    )
                )
        return decisions

    # -- helpers ------------------------------------------------------------- #
    def _stop(self, reason: str, rule: str, event: dict) -> Decision:
        return Decision("deny" if self.mode == "block" else "flag", reason, rule, event)

    @staticmethod
    def _hash(tool: dict) -> str:
        return hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest()
