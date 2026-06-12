"""Day-count + milestone arithmetic for the disclosure track.

Milestone cadence is the one used in the mcp-witness disclosure record itself:
+14 / +21 / +30 / +45 / +60 / +90. Each milestone has a recommended action.
The cadence is encoded as data so callers can iterate or modify without
having to touch the rest of the codebase.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class Milestone:
    """One disclosure-cadence checkpoint."""

    day: int
    label: str  # short human label e.g. "day +14 ping"
    action: str  # one-line recommended action for this milestone


# Milestone cadence — kept in ascending day order. `next_milestone()` relies on this.
MILESTONES: tuple[Milestone, ...] = (
    Milestone(
        14,
        "day +14 ping",
        "Send a short follow-up: 'just confirming the original mail reached you'.",
    ),
    Milestone(21, "day +21 ping", "Second follow-up: reference the day +14 ping; still soft tone."),
    Milestone(
        30,
        "day +30 escalation",
        "Soft-channel escalation: LinkedIn / Twitter / contact form / third email.",
    ),
    Milestone(
        45,
        "day +45 pointer issue",
        "Public non-exploitative pointer issue on the upstream repo; cross-link the disclosure.",
    ),
    Milestone(
        60,
        "day +60 final notice",
        "Final notice: name the publish date; offer one last private channel.",
    ),
    Milestone(
        90,
        "day +90 publish",
        "Embargo end. Publish the full disclosure regardless of maintainer response.",
    ),
)


def days_since(filed: date, today: date | None = None) -> int:
    """Number of days from `filed` to `today` (default: today's date).

    Negative values indicate `filed` is in the future, which the caller can
    use to flag a malformed disclosure date.
    """
    today = today or date.today()
    return (today - filed).days


def next_milestone(day: int) -> Milestone | None:
    """The first milestone strictly after `day`, or None if past day +90.

    `day` is the current day-count (e.g. result of `days_since`). A disclosure
    on day +13 returns the +14 milestone; on day +14 returns the +21 milestone
    (since we're at the +14 milestone, the *next* one is +21).
    """
    for m in MILESTONES:
        if m.day > day:
            return m
    return None


def current_milestone(day: int) -> Milestone | None:
    """The milestone whose day is closest to `day` without exceeding it, or None.

    A disclosure on day +30 returns the +30 milestone; on day +31 still returns
    +30 (it's the one that's "current" until +45 hits).
    """
    chosen: Milestone | None = None
    for m in MILESTONES:
        if m.day <= day:
            chosen = m
        else:
            break
    return chosen
