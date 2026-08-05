#!/usr/bin/env python3
"""Offline checks of the maintenance window grid (WI §6.2).

Grounded in the real release dates of the four products, because the whole reason this model
replaced the previous one is that the previous one produced dates in the past on three of them.
"""
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location(
    "mw", os.path.join(os.environ.get("S", "../scripts"), "maintenance-windows.py"))
mw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mw)

bad = []
def eq(label, got, want):
    if got != want:
        bad.append(f"{label}: expected {want}, got {got}")

d = mw.parse_ts
NOW = d("2026-08-03")

eq("90d", mw.parse_interval("90d"), 90)
eq("3m", mw.parse_interval("3m"), 90)
eq("bare number", mw.parse_interval("90"), 90)
eq("garbage falls back", mw.parse_interval("whenever"), 90)

# Mindnet released 2026-07-21 and is inside its window.
st = mw.state(d("2026-07-21"), 90, NOW)
eq("mindnet next window", st["next_window"][:10], "2026-10-19")
eq("mindnet missed none", st["missed_count"], 0)

# Alvie last released 2025-10-01: three windows have elapsed. The grid advances through them
# rather than waiting for a release, so not releasing cannot buy time.
st = mw.state(d("2025-10-01"), 90, NOW)
eq("alvie missed three", st["missed_count"], 3)
eq("alvie next window", st["next_window"][:10], "2026-09-26")
# the next window is a grid point, not "now + 90d"
eq("grid point, not a fresh 90 days", st["next_window"][:10] != "2026-11-01", True)

# The same product onboarded today: history is recorded, not charged as breaches.
st = mw.state(d("2025-10-01"), 90, NOW, onboarded=NOW)
eq("onboarding clears the missed count", st["missed_count"], 0)
eq("but records what elapsed", len(st["windows_before_onboarding"]), 3)
eq("grid origin moves to onboarding", st["grid_origin"][:10], "2026-08-03")
eq("onboarding basis is stated", "not as breaches" in st["grid_origin_basis"], True)

# An onboarding date *older* than the last release must not pull the grid backwards.
st = mw.state(d("2026-07-21"), 90, NOW, onboarded=d("2026-01-01"))
eq("stale onboarding date is ignored", st["grid_origin"][:10], "2026-07-21")

# Osteocoach's window falls on 2026-08-05, two days away. A finding discovered today cannot be
# required to be live in two days — it lands in the window after, because a remediation
# deadline earlier than the mitigation deadline is incoherent.
origin = d("2026-05-07")
eq("next window at all", mw.grid(origin, 90, NOW)[1].date().isoformat(), "2026-08-05")
eq("finding today skips the imminent window",
   mw.window_for(NOW, 30, origin, 90).date().isoformat(), "2026-11-03")
eq("older finding makes the imminent window",
   mw.window_for(d("2026-06-01"), 30, origin, 90).date().isoformat(), "2026-08-05")
# Exactly on the boundary: a finding whose floor equals a window date belongs in it.
eq("floor exactly on the window",
   mw.window_for(d("2026-07-06"), 30, origin, 90).date().isoformat(), "2026-08-05")
eq("one day past the boundary rolls over",
   mw.window_for(d("2026-07-07"), 30, origin, 90).date().isoformat(), "2026-11-03")

# Track 4 has no mitigation deadline and rides Track 3's release, so it uses the same floor.
eq("track 4 uses the default floor", mw.DEFAULT_MITIGATION_FLOOR_DAYS, 30)
eq("track 4 lands on the same window as track 3",
   mw.window_for(NOW, mw.DEFAULT_MITIGATION_FLOOR_DAYS, origin, 90),
   mw.window_for(NOW, 30, origin, 90))

# A finding with a long mitigation period still lands on a real grid point, not on
# discovery + mitigation.
w = mw.window_for(NOW, 200, origin, 90)
eq("long floor still lands on the grid", ((w - origin).days % 90), 0)

for b in bad:
    print("  " + b)
sys.exit(1 if bad else 0)
