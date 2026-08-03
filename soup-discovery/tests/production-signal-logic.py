#!/usr/bin/env python3
"""Offline checks of production-release detection (§3.4).

Grounded in real portfolio data. alvie's three signals name releases 315 days apart, and
whichever one the tooling picks becomes the basis for every Track 3/4 deadline — so the
cases below are the actual release rows, not invented ones.
"""
import importlib.util, json, os, subprocess, sys

spec = importlib.util.spec_from_file_location(
    "bs", os.path.join(os.environ.get("S", "../scripts"), "backstop-report.py"))
bs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bs)

bad = []
def eq(label, got, want):
    if got != want:
        bad.append(f"{label}: expected {want}, got {got}")

# alvie, as GitHub actually reports it.
ALVIE = [
    {"at": "2026-07-31T00:00:00Z", "tag": "v1.0.8-qa36", "pre": True,  "asset": False},
    {"at": "2026-05-04T00:00:00Z", "tag": "v1.0.8-qa30", "pre": False, "asset": False},
    {"at": "2025-10-01T00:00:00Z", "tag": "v1.0.7",      "pre": False, "asset": False},
    {"at": "2025-06-23T00:00:00Z", "tag": "v1.0.4",      "pre": False, "asset": True},
]
P = bs.DEFAULT_TAG_PATTERN

eq("tag pattern skips -qa builds",
   bs._signal_dates(ALVIE, "tag_pattern", P)[0], "2025-10-01T00:00:00Z")
# The flag is unmaintained here: a -qa30 build is marked as a full release.
eq("prerelease flag picks the qa build",
   bs._signal_dates(ALVIE, "prerelease_flag", P)[0], "2026-05-04T00:00:00Z")
eq("asset signal picks the last mobile production build",
   bs._signal_dates(ALVIE, "production_asset", P)[0], "2025-06-23T00:00:00Z")
# Any of the three could be the honest answer; none can be derived from the repo. The
# spread is the point — a silent pick would move a deadline by ten months.
eq("three signals, three answers",
   len({bs._signal_dates(ALVIE, s, P)[0] for s in bs.SIGNALS}), 3)

def with_rows(rows, policy=None):
    real = subprocess.run
    def fake(*a, **k):
        return subprocess.CompletedProcess(
            a[0], 0, "\n".join(json.dumps(r) for r in rows), "")
    subprocess.run = fake
    try:
        return bs.release_dates("QuickBirdEng/x", policy=policy)
    finally:
        subprocess.run = real

dates, basis, dis = with_rows(ALVIE)
eq("default signal is the tag pattern", dates[0], "2025-10-01T00:00:00Z")
eq("basis names the signal used", "tag_pattern" in basis, True)
eq("disagreement reported", dis is not None, True)
eq("disagreement names all three", len(dis["latest_by_signal"]), 3)

# Configuring the maintained signal changes the measurement — that is the whole point of
# making it configurable rather than clever.
dates, basis, dis = with_rows(ALVIE, {"production_release": {"detect_by": "prerelease_flag"}})
eq("configured signal wins", dates[0], "2026-05-04T00:00:00Z")
eq("still reports the disagreement", dis is not None, True)

# mindnet: all three agree, so there is nothing to report and the run stays quiet.
MINDNET = [
    {"at": "2026-07-21T00:00:00Z", "tag": "v1.0.15", "pre": False, "asset": True},
    {"at": "2026-07-01T00:00:00Z", "tag": "v1.0.15-qa4", "pre": True, "asset": False},
]
dates, basis, dis = with_rows(MINDNET)
eq("agreement is silent", dis, None)
eq("agreed date", dates[0], "2026-07-21T00:00:00Z")

# kontina-backend has no clean semver tag at all. Falling back to counting every release is
# survivable; claiming it never released is not — but the fallback must say what it did.
KONTINA = [{"at": "2025-06-17T00:00:00Z", "tag": "v1.9.0-qa10", "pre": False, "asset": False}]
dates, basis, dis = with_rows(KONTINA)
eq("falls back rather than reporting no releases", dates[0], "2025-06-17T00:00:00Z")
eq("fallback is stated in the basis", "may overstate" in basis, True)
eq("fallback still flags the disagreement", dis is not None, True)

# --- continuous deployment ---------------------------------------------------------
# apellis has no tags and no releases; a cycle cannot be measured, and declaring one would
# invent a Track 3 deadline out of releases that never happen.
def with_deploys(rows):
    real = subprocess.run
    def fake(*a, **k):
        return subprocess.CompletedProcess(
            a[0], 0, "\n".join(json.dumps(r) for r in rows), "")
    subprocess.run = fake
    try:
        return bs.deployment_dates("QuickBirdEng/x")
    finally:
        subprocess.run = real

# apellis as it actually is: 100 deploys, every one of them to a development environment.
dev_only = [{"at": "2026-08-01T00:00:00Z", "env": "development", "ref": "abc"},
            {"at": "2026-07-30T00:00:00Z", "env": "appway-connector-development", "ref": "def"}]
dates, basis, prod = with_deploys(dev_only)
eq("dev-only deploys are counted", len(dates), 2)
eq("but not claimed as production", prod, False)
eq("basis says nothing reached users", "reaching users" in basis, True)

mixed = [{"at": "2026-08-01T00:00:00Z", "env": "development", "ref": "abc"},
         {"at": "2026-07-20T00:00:00Z", "env": "production", "ref": "def"}]
dates, basis, prod = with_deploys(mixed)
eq("production deploys win when present", dates, ["2026-07-20T00:00:00Z"])
eq("and are named as such", prod, True)

dates, basis, prod = with_deploys([])
eq("no deployments is not an error", dates, [])
eq("no deployments is not production", prod, False)

for b in bad:
    print("  " + b)
sys.exit(1 if bad else 0)
