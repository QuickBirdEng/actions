#!/usr/bin/env python3
"""Maintenance release windows (§3.4).

Track 3 remediation is "next regular release", which is not a date. Turning it into one used
to be attempted from the *observed* release rhythm, and that does not work: three of four
products have a rhythm that has already lapsed, so the derived date lands in the past and a
finding is born overdue. Dermafy's would have been 109 days late on the day it was found.

Decided 2026-08-03: a product declares a **maintenance interval** — a commitment that a
maintenance release happens at least every N days — and the remediation deadline is the next
window on that grid. Three properties matter:

1. **The deadline is shared.** Every open Track 3/4 finding targets the same window, so a
   missed window is *one* breach about a release, not one per finding. On Kontina the
   difference is 1 recorded decision instead of 196.

2. **A missed window does not move the grid.** It advances from the missed due date, not from
   whenever a release eventually happens — otherwise not releasing buys time, which is the
   receding deadline that §2.2's latching exists to prevent.

3. **An early release resets the grid.** The maintenance was done; the next window counts from
   the actual release.

A finding is assigned to the first window that is at least its own **mitigation** period away.
One cannot be obliged to remediate before being obliged to mitigate, and without this a
finding discovered two days before a window would be due in two days. Track 4 has no
mitigation deadline, so it uses Track 3's — it rides the same release.

Usage:
  maintenance-windows.py --last-release ISO --interval 90d [--onboarded ISO]
                         [--now ISO] [--out f]
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

# The floor for assigning a finding to a window when its track has no mitigation deadline.
# Track 4 rides the same maintenance release as Track 3, so it inherits Track 3's period.
DEFAULT_MITIGATION_FLOOR_DAYS = 30


def parse_interval(s, default=90):
    """'90d' / '90' / '3m' -> days. Months are 30 days, matching the currency window."""
    if not s:
        return default
    s = str(s).strip().lower()
    try:
        if s.endswith("d"):
            return int(s[:-1])
        if s.endswith("m"):
            return int(s[:-1]) * 30
        if s.endswith("y"):
            return int(s[:-1]) * 365
        return int(s)
    except ValueError:
        return default


def parse_ts(s):
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def grid(origin, interval_days, now):
    """Window due dates from `origin`, and which of them have already elapsed.

    Returns (missed, next_window). `missed` are windows whose date has passed with no release
    recorded against them — the grid keeps advancing through them rather than waiting.
    """
    step = timedelta(days=interval_days)
    due = origin + step
    missed = []
    while due < now:
        missed.append(due)
        due = due + step
    return missed, due


def window_for(discovery, mitigation_days, origin, interval_days):
    """The first window at least `mitigation_days` after `discovery`.

    Not simply "the next window": a finding found shortly before a window cannot be required
    to be live in it. The floor is the finding's own mitigation deadline, because a
    remediation deadline earlier than the mitigation deadline is incoherent.
    """
    floor = discovery + timedelta(days=mitigation_days)
    step = timedelta(days=interval_days)
    due = origin + step
    # Advance to the first window at or after the floor. A finding whose floor is far in the
    # future (a long mitigation period, or a stale grid) still lands on a real grid point.
    while due < floor:
        due = due + step
    return due


def state(last_release, interval_days, now, onboarded=None):
    """Window state for a product.

    `onboarded` shifts the grid origin: at onboarding, a product's release history is a
    finding to be recorded, not a set of retroactive violations. Alvie and Dermafy each have
    three windows that had already elapsed before monitoring existed; counting those as
    breaches would open the account with a violation nobody could have acted on.
    """
    origin = last_release
    grid_origin_reason = "last production release"
    if onboarded and onboarded > last_release:
        origin = onboarded
        grid_origin_reason = ("onboarding date — windows before monitoring existed are "
                             "recorded as history, not as breaches")
    missed, nxt = grid(origin, interval_days, now)
    historic = []
    if origin is not last_release:
        historic, _ = grid(last_release, interval_days, origin)
    return {
        "schema": "quickbird.maintenance-windows/v1",
        "interval_days": interval_days,
        "last_production_release": last_release.isoformat(),
        "grid_origin": origin.isoformat(),
        "grid_origin_basis": grid_origin_reason,
        "onboarded": onboarded.isoformat() if onboarded else None,
        "evaluated_at": now.isoformat(),
        "next_window": nxt.isoformat(),
        "days_to_next_window": (nxt - now).days,
        "missed_windows": [d.isoformat() for d in missed],
        "missed_count": len(missed),
        # Windows that elapsed before this product was monitored. Reported so the state is
        # visible, never counted as breaches.
        "windows_before_onboarding": [d.isoformat() for d in historic],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--last-release", required=True)
    ap.add_argument("--interval", default="90d")
    ap.add_argument("--onboarded")
    ap.add_argument("--now")
    ap.add_argument("--out", default="-")
    args = ap.parse_args()

    last = parse_ts(args.last_release)
    if last is None:
        print(f"::error::could not parse --last-release {args.last_release!r}", file=sys.stderr)
        return 1
    now = parse_ts(args.now) or datetime.now(timezone.utc)
    out = state(last, parse_interval(args.interval), now, parse_ts(args.onboarded))

    text = json.dumps(out, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    msg = (f"maintenance: next window {out['next_window'][:10]} "
           f"(in {out['days_to_next_window']}d, every {out['interval_days']}d)")
    if out["missed_count"]:
        print(f"::error::{msg} — {out['missed_count']} window(s) missed since "
              f"{out['grid_origin'][:10]}", file=sys.stderr)
    else:
        print(msg, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
