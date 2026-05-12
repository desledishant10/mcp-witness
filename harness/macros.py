"""Payload macro substitution for scenario steps.

Implements the macro vocabulary defined in docs/scenario-schema.md
§Payload macros: {run_id}, {canary:<id>}, {canary_token:<id>},
{path:<fixture_id>}, {tmp}, {unicode_tags:<text>}, {payload}.

Substitution is two-pass: ordinary macros resolve to a fixed point first,
then `unicode_tags` is applied last so the inner content (which may
contain other macros) is already expanded before encoding.
"""

from __future__ import annotations

import re
import tempfile
from typing import Any

# `[^{}]+` for `arg` makes nested macros work naturally: the inner
# `{canary:X}` matches before the outer `{unicode_tags:foo {canary:X}}`
# because the outer cannot match while the inner braces are still present.
_MACRO_RX = re.compile(r"\{(?P<name>[a-z_]+)(?::(?P<arg>[^{}]+))?\}")


def substitute(template: str, ctx: dict[str, Any]) -> str:
    """Resolve {macro:arg} placeholders against the run context."""
    cur, prev = template, None
    while prev != cur:
        prev = cur
        cur = _MACRO_RX.sub(lambda m: _resolve(m, ctx, defer_tags=True), cur)
    return _MACRO_RX.sub(lambda m: _resolve(m, ctx, defer_tags=False), cur)


def _resolve(m: re.Match[str], ctx: dict[str, Any], defer_tags: bool) -> str:
    name, arg = m.group("name"), m.group("arg")
    if name == "unicode_tags":
        if defer_tags:
            return m.group(0)
        return "".join(
            chr(0xE0000 + ord(c)) for c in (arg or "") if 0x20 <= ord(c) <= 0x7E
        )
    if name == "run_id":
        return str(ctx["run_id"])
    if name == "tmp":
        return tempfile.gettempdir()
    if name == "payload":
        return str(ctx.get("payload", ""))
    if name == "canary" and arg:
        return ctx["canaries"][arg].url
    if name == "canary_token" and arg:
        return ctx["canaries"][arg].token
    if name == "path" and arg:
        return ctx["fixtures"][arg]
    return m.group(0)
