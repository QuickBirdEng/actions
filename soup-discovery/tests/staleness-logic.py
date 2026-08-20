#!/usr/bin/env python3
"""Offline checks of the staleness window and its interaction with currency."""
import importlib.util, os, sys
from datetime import datetime, timedelta, timezone

spec = importlib.util.spec_from_file_location(
    "cc", os.path.join(os.environ.get("S", "../scripts"), "check-currency.py"))
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)

bad = []
def eq(label, got, want):
    if got != want:
        bad.append(f"{label}: expected {want}, got {got}")

eq("12m default",  cc.parse_window(None), 360)
eq("12m",          cc.parse_window("12m"), 360)
eq("18 months",    cc.parse_window("18months"), 540)
eq("540d",         cc.parse_window("540d"), 540)
eq("2y",           cc.parse_window("2y"), 730)
eq("garbage falls back", cc.parse_window("soon"), 360)

now = datetime(2026, 8, 2, tzinfo=timezone.utc)
eq("age of a year-old release", cc.age_days("2025-08-02T00:00:00+00:00", now), 365)
eq("naive timestamp accepted",  cc.age_days("2025-08-02T00:00:00", now), 365)
# A missing or unparsable date must not read as fresh — it yields None, and the caller
# treats that as "not stale-checked" rather than "recently released".
eq("missing date",     cc.age_days(None, now), None)
eq("unparsable date",  cc.age_days("last tuesday", now), None)

for b in bad:
    print("  " + b)
sys.exit(1 if bad else 0)
