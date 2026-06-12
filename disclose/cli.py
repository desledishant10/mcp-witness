"""argparse-based CLI for the disclosure helper.

Subcommands:
    new       — scaffold a new disclosure markdown file
    status    — show day-count + next-milestone for every disclosure on disk
    ping      — render a day-appropriate follow-up body for one disclosure

Today's date defaults to `date.today()`; pass `--today YYYY-MM-DD` to override
(used for reproducible tests + scheduled-run scenarios).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

from . import templates
from .dates import current_milestone, days_since, next_milestone
from .parse import Disclosure, is_closed, load_directory

DEFAULT_DISCLOSURES_DIR = Path("disclosures")


def _parse_iso_date(s: str) -> date:
    try:
        return date.fromisoformat(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"not an ISO date (YYYY-MM-DD): {s!r}") from e


def _slugify(text: str) -> str:
    """Lowercase, hyphenate, strip non-`[a-z0-9-]` for filename use."""
    s = text.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


# --------------------------------------------------------------------------- #
# subcommand: new
# --------------------------------------------------------------------------- #


def cmd_new(args: argparse.Namespace) -> int:
    filed: date = args.filing_date or date.today()
    embargo: date = args.embargo or (filed + timedelta(days=90))
    slug_base = _slugify(args.target)
    if args.class_:
        slug_base = f"{slug_base}-{_slugify(args.class_)}"
    slug = f"{filed.isoformat()}-{slug_base}"

    out_dir: Path = args.disclosures_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{slug}.md"

    if out_path.exists() and not args.force:
        print(f"refuse to overwrite existing file: {out_path}", file=sys.stderr)
        print("(pass --force to overwrite)", file=sys.stderr)
        return 2

    title = args.title or f"<vulnerability class> in {args.target}"
    body = templates.render_new_disclosure(
        title=title,
        filed=filed,
        embargo=embargo,
        filed_to=args.filed_to or "<recipient(s) + channel>",
        affected=args.affected or f"`{args.target}` v<version>",
    )
    out_path.write_text(body)
    print(f"scaffolded: {out_path}")
    print(f"  slug:    {slug}")
    print(f"  filed:   {filed.isoformat()}")
    print(f"  embargo: {embargo.isoformat()} (day +90)")
    print()
    print("next: open the file and fill in the channel-decision audit + body sections,")
    print("then send the report and update Status: 'drafted' -> 'filed' once it goes out.")
    return 0


# --------------------------------------------------------------------------- #
# subcommand: status
# --------------------------------------------------------------------------- #


def _status_row(d: Disclosure, today: date) -> dict:
    if d.filed is None:
        return {
            "slug": d.slug,
            "filed": None,
            "day": None,
            "status": d.status,
            "next_action": "(no Filed date)",
            "closed": False,
        }
    day = days_since(d.filed, today)
    closed = is_closed(d)
    if closed:
        next_action = "closed"
    else:
        nm = next_milestone(day)
        if nm is None:
            next_action = "embargo over, publish"
        else:
            target = d.filed + timedelta(days=nm.day)
            delta = (target - today).days
            if delta == 0:
                when = "today"
            elif delta > 0:
                when = f"in {delta}d ({target.isoformat()})"
            else:
                when = f"{-delta}d overdue ({target.isoformat()})"
            next_action = f"{nm.label} {when}"
    return {
        "slug": d.slug,
        "filed": d.filed.isoformat(),
        "day": day,
        "status": d.status,
        "next_action": next_action,
        "closed": closed,
        "embargo": d.embargo.isoformat() if d.embargo else None,
    }


def cmd_status(args: argparse.Namespace) -> int:
    today: date = args.today or date.today()
    disclosures = load_directory(args.disclosures_dir)
    rows = [_status_row(d, today) for d in disclosures]

    if args.json:
        print(json.dumps({"today": today.isoformat(), "rows": rows}, indent=2))
        return 0

    if not rows:
        print(f"no disclosures found in {args.disclosures_dir}/")
        return 0

    # Plain-text table. Widths sized for the longest slug + reasonable max.
    slug_w = max(len(r["slug"]) for r in rows)
    next_w = max(len(r["next_action"]) for r in rows)
    print(f"today: {today.isoformat()}  ({len(rows)} disclosures on disk)")
    print()
    print(f"  {'SLUG':<{slug_w}}  FILED       DAY   {'NEXT ACTION':<{next_w}}")
    print(f"  {'-' * slug_w}  ----------  ----  {'-' * next_w}")
    for r in rows:
        day_cell = f"+{r['day']:>3}" if r["day"] is not None else "  ? "
        filed_cell = r["filed"] or "          "
        print(f"  {r['slug']:<{slug_w}}  {filed_cell}  {day_cell}  {r['next_action']:<{next_w}}")

    # Summary line.
    open_count = sum(1 for r in rows if not r["closed"])
    closed_count = len(rows) - open_count
    due_today = sum(1 for r in rows if " today" in (r["next_action"] or ""))
    overdue = sum(1 for r in rows if "overdue" in (r["next_action"] or ""))
    print()
    print(
        f"summary: {open_count} open / {closed_count} closed; "
        f"{due_today} due today; {overdue} overdue"
    )
    return 0


# --------------------------------------------------------------------------- #
# subcommand: ping
# --------------------------------------------------------------------------- #


def _resolve_disclosure(slug_or_path: str, disclosures_dir: Path) -> Disclosure | None:
    """Find a disclosure by exact slug, basename, or path prefix-match."""
    candidate = Path(slug_or_path)
    if candidate.exists() and candidate.is_file():
        from .parse import parse_disclosure

        return parse_disclosure(candidate)

    by_slug = disclosures_dir / f"{slug_or_path}.md"
    if by_slug.exists():
        from .parse import parse_disclosure

        return parse_disclosure(by_slug)

    # Prefix match across all loadable disclosures.
    matches = [d for d in load_directory(disclosures_dir) if slug_or_path in d.slug]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"ambiguous: {len(matches)} disclosures match {slug_or_path!r}:", file=sys.stderr)
        for m in matches:
            print(f"  {m.slug}", file=sys.stderr)
    return None


def cmd_ping(args: argparse.Namespace) -> int:
    today: date = args.today or date.today()
    disc = _resolve_disclosure(args.slug, args.disclosures_dir)
    if disc is None:
        print(f"no disclosure found matching {args.slug!r}", file=sys.stderr)
        return 2

    if disc.filed is None:
        print(
            f"disclosure {disc.slug} has no Filed date, cannot compute day-count", file=sys.stderr
        )
        return 2

    day = days_since(disc.filed, today)
    if args.day is not None:
        day = args.day  # explicit override

    recipient = args.to or "<recipient name>"
    title = disc.title or f"disclosure {disc.slug}"
    affected = disc.affected or "<affected packages>"
    cm = current_milestone(day)
    nm = next_milestone(day)

    print(f"# Disclosure: {disc.slug}")
    print(f"# Day: +{day}")
    if cm:
        print(f"# Current milestone: {cm.label}. {cm.action}")
    if nm:
        target = disc.filed + timedelta(days=nm.day)
        delta = (target - today).days
        print(f"# Next milestone: {nm.label} on {target.isoformat()} (in {delta}d)")
    print()
    print(
        templates.render_ping(
            day=day,
            title=title,
            recipient=recipient,
            filed=disc.filed,
            embargo=disc.embargo,
            affected=affected,
            slug=disc.slug,
        )
    )
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-witness-disclose",
        description=(
            "Coordinated-disclosure helper. Scaffold new disclosure files, "
            "track day-count milestones across active disclosures, render "
            "day-appropriate follow-up message bodies."
        ),
    )
    p.add_argument(
        "--disclosures-dir",
        type=Path,
        default=DEFAULT_DISCLOSURES_DIR,
        help="directory containing disclosure markdown files (default: disclosures/)",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    # new
    p_new = sub.add_parser("new", help="scaffold a new disclosure record")
    p_new.add_argument("target", help="target package name (e.g. mcp-server-foo)")
    p_new.add_argument("--class", dest="class_", help="vulnerability class slug for filename")
    p_new.add_argument(
        "--title", help="disclosure title (default: '<vulnerability class> in <target>')"
    )
    p_new.add_argument("--filed-to", help="initial Filed-to field")
    p_new.add_argument("--affected", help="initial Affected field")
    p_new.add_argument(
        "--filing-date",
        type=_parse_iso_date,
        help="filing date (YYYY-MM-DD; default: today)",
    )
    p_new.add_argument(
        "--embargo",
        type=_parse_iso_date,
        help="embargo end date (default: filed + 90 days)",
    )
    p_new.add_argument("--force", action="store_true", help="overwrite an existing file")
    p_new.set_defaults(func=cmd_new)

    # status
    p_status = sub.add_parser("status", help="show day-count + next-milestone for every disclosure")
    p_status.add_argument(
        "--today",
        type=_parse_iso_date,
        help="treat this date as today (YYYY-MM-DD; default: date.today())",
    )
    p_status.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p_status.set_defaults(func=cmd_status)

    # ping
    p_ping = sub.add_parser("ping", help="render a day-appropriate follow-up body")
    p_ping.add_argument(
        "slug", help="disclosure slug (filename stem), exact path, or prefix substring"
    )
    p_ping.add_argument("--to", help="recipient name to drop into the greeting")
    p_ping.add_argument(
        "--today",
        type=_parse_iso_date,
        help="treat this date as today (YYYY-MM-DD; default: date.today())",
    )
    p_ping.add_argument("--day", type=int, help="override the computed day-count")
    p_ping.set_defaults(func=cmd_ping)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
