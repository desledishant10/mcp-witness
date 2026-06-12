"""Message-body templates rendered by `disclose ping` and `disclose new`.

These are not hardcoded prose — they're the day-appropriate skeletons that
the user fills in. The templating contract: every variable goes through
`{name}` substitution, every template is plain text (no Markdown unless the
target channel is Markdown), and a missing field is rendered as `<missing
field>` rather than a Python KeyError.
"""

from __future__ import annotations

from datetime import date
from string import Template


class _SafeTemplate(Template):
    """Template variant that renders unknown keys as `<missing field>`."""

    def safe_substitute_marked(self, mapping: dict[str, str]) -> str:
        class _Marked(dict):
            def __missing__(self, key: str) -> str:  # pragma: no cover - trivial
                return "<missing field>"

        return self.safe_substitute(_Marked(mapping))


PING_DAY_14 = _SafeTemplate(
    """Subject: Re: [Coordinated security disclosure] $title

Hi $recipient,

Quick follow-up on the coordinated security disclosure I sent on
$filed_date (day +$day today). Just confirming the original mail
reached you. Sometimes security mail ends up in spam.

Affected: $affected
Embargo: $embargo

Happy to coordinate timeline or discuss the suggested fix shape on
any channel that works for you. No urgency; just confirming visibility.

Thanks,
Dishant Desle
didesle7@gmail.com
github.com/desledishant10/mcp-witness
"""
)


PING_DAY_21 = _SafeTemplate(
    """Subject: Re: [Coordinated security disclosure] $title

Hi $recipient,

Second follow-up on the disclosure sent $filed_date (day +$day today).
The day +14 ping on this thread didn't get a response so I'm checking
again in case the earlier mail was filtered.

Affected: $affected
Embargo: $embargo

If a different channel works better (GitHub Security Advisory, Signal,
anything), happy to switch. The disclosure record is at
https://github.com/desledishant10/mcp-witness/blob/main/disclosures/$slug.md.

Thanks,
Dishant Desle
didesle7@gmail.com
"""
)


PING_DAY_30 = _SafeTemplate(
    """Subject: Re: [Coordinated security disclosure] $title

Hi $recipient,

Day +$day from the original disclosure today. The email channel has
been silent through the day +14 and day +21 follow-ups, so I'm
escalating to other channels in parallel. See options below.

Affected: $affected
Embargo: $embargo
Record: https://github.com/desledishant10/mcp-witness/blob/main/disclosures/$slug.md

If I haven't heard back by day +45, I'll file a non-exploitative
pointer issue on the upstream repo so the issue thread reflects an
active disclosure (no PoC details in that issue; full disclosure
stays embargoed until $embargo).

Soft channels I'll try in parallel today (in order of preference):
1. LinkedIn DM (lowest-friction)
2. Twitter / Bluesky DM if available
3. Contact form on the project site if one exists
4. This third email on the thread

If any of those reach you first, just reply on whichever channel.

Thanks,
Dishant Desle
didesle7@gmail.com
"""
)


PING_DAY_45 = _SafeTemplate(
    """### Title
Awaiting acknowledgement on coordinated security disclosure sent $filed_date

### Body

Filing this as a non-exploitative pointer since the private channels
have been silent for 45 days.

A coordinated security disclosure covering $affected was sent on
$filed_date. Day +14, +21, and +30 follow-ups received no response.
Day +30 escalation attempts via soft channels (LinkedIn / contact
form / additional email) also received no response.

**No exploit details in this issue.** The full disclosure record
(suggested fix, file references, embargo timeline) is at
https://github.com/desledishant10/mcp-witness/blob/main/disclosures/$slug.md
and remains under embargo until $embargo.

Please reply on this issue or directly on the original email thread
if any of the prior messages reached you. Happy to switch to any
private channel you prefer.
"""
)


PING_DAY_60 = _SafeTemplate(
    """Subject: Re: [Coordinated security disclosure] $title (final notice before publish)

Hi $recipient,

Day +$day today. The disclosure record at
https://github.com/desledishant10/mcp-witness/blob/main/disclosures/$slug.md
remains in 'awaiting maintainer ack' state through every channel
attempted.

Embargo expires $embargo. Per the coordinated-disclosure policy
published at the top of the disclosure record, on $embargo the
full report will be published, including source-level evidence
and reproduction details, regardless of whether a fix has shipped.

This is the final notice. If you want any input on the public
writeup (scope, framing, timing-coordination with a planned fix),
the next 30 days are the window.

Thanks,
Dishant Desle
"""
)


NEW_DISCLOSURE_TEMPLATE = """# $title

**Filed:** $filed_date
**Filed by:** Dishant Desle, didesle7@gmail.com
**Filed to:** $filed_to
**Affected:** $affected
**Embargo:** $embargo_date (90 days from filing)
**Status:** drafted

---

## Channel decision audit

<!--
Why this channel? What private channels were checked first?
For email: confirmed via PyPI METADATA / maintainer profile / GHSA enablement.
For public issue: only when GHSA disabled + maintainer profile contactless + PyPI noreply.
For HackerOne / corporate disclosure intake: document the routing decision.
-->

## Body of the filed report

<!--
The verbatim text sent to the maintainer (or queued for sending).
For public-issue disclosures, the verbatim issue body.
-->

## Updates

<!-- Append-only, newest first. -->
"""


def _format_date(d: date) -> str:
    """ISO format used consistently throughout the disclosure track."""
    return d.isoformat()


def render_ping(
    *,
    day: int,
    title: str,
    recipient: str,
    filed: date,
    embargo: date | None,
    affected: str,
    slug: str,
) -> str:
    """Render a day-appropriate ping body.

    The template is chosen from the milestone closest to (but not exceeding)
    `day`: day=14..20 → day-14 template, 21..29 → day-21, etc.
    """
    if day >= 60:
        tpl = PING_DAY_60
    elif day >= 45:
        tpl = PING_DAY_45
    elif day >= 30:
        tpl = PING_DAY_30
    elif day >= 21:
        tpl = PING_DAY_21
    else:
        tpl = PING_DAY_14

    return tpl.safe_substitute_marked(
        {
            "day": str(day),
            "title": title,
            "recipient": recipient,
            "filed_date": _format_date(filed),
            "embargo": _format_date(embargo) if embargo else "<embargo not set>",
            "affected": affected,
            "slug": slug,
        }
    )


def render_new_disclosure(
    *,
    title: str,
    filed: date,
    embargo: date,
    filed_to: str = "<recipient(s) + channel>",
    affected: str = "<package(s) + version(s)>",
) -> str:
    """Render the boilerplate for a new disclosure markdown file."""
    return Template(NEW_DISCLOSURE_TEMPLATE).safe_substitute(
        {
            "title": title,
            "filed_date": _format_date(filed),
            "embargo_date": _format_date(embargo),
            "filed_to": filed_to,
            "affected": affected,
        }
    )
