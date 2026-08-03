#!/usr/bin/env python3
"""Periodic backstop reconciliation (§6.3, §7).

The backstop exists because automation fails silently. Everything else in this pipeline
reports what it found; this one reports what it *did not* find, which is the failure mode
a daily alert cannot surface — a product that stopped being scanned produces no alerts at
all, and that is indistinguishable from a product with nothing wrong.

Four questions, in order of how badly a wrong answer would hurt:

  1. Was every product actually scanned, and how recently? A gap in the record is the
     finding. Silence is not evidence.
  2. Are there findings whose deadline has passed with no recorded decision?
  3. Have any recorded risk acceptances expired without being renewed?
  4. Does each product's declared release cadence match what it actually released? A
     cadence that no longer holds turns every Track 3 deadline into fiction, because those
     deadlines are derived from it (§3.4). Needs the release history, which comes from
     GitHub rather than the evidence store — the run record carries the repo name and the
     declared cadence so this can be checked without every project's policy file.

Reads the evidence store — the dated run records the monitor writes — rather than
recomputing anything. If a run never happened there is nothing to recompute, and that
absence is precisely what this is looking for.

Usage: backstop-report.py <evidence-dir> [--products a,b] [--window 90] [--out f]
"""

import argparse
import glob
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


CADENCE_DAYS = {"daily": 1, "weekly": 7, "fortnightly": 14, "biweekly": 14,
                "monthly": 31, "quarterly": 92, "biannual": 183, "annual": 366}
# How far past the declared interval before the cadence counts as not holding. A release
# cycle that slips by a third is normal; one that has slipped by half has stopped being a
# cycle, and a deadline derived from it is no longer a deadline.
TOLERANCE = 1.5


def release_dates(repo, production_only=True):
    """Published dates of a repo's releases, newest first. None if they cannot be read.

    Counts *production* releases by default, identified the same way resolve-deployed.sh
    does: a release carrying a `-production` artifact. The distinction is not cosmetic. alvie
    published six releases in 90 days and looks like a product on a monthly cadence, while
    its last production build was over a year old — those releases went to staging and to
    study builds. A Track 3/4 deadline is a *remediation* deadline, and remediation is only
    satisfied on deploy, so the cadence that can carry such a deadline is the cadence at
    which things actually reach users.

    Falls back to counting every release when a repo has no production-flavoured artifacts
    at all, because a backend deployed from a plain tag has no such marker and would
    otherwise read as never releasing.
    """
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{repo}/releases?per_page=100",
             "--jq", '.[] | {at: .published_at, prod: ([.assets[].name] | any(test("production";"i")))}'],
            capture_output=True, text=True, timeout=60, check=True)
        rows = [json.loads(l) for l in (r.stdout or "").splitlines() if l.strip()]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, json.JSONDecodeError):
        return None, None
    if not rows:
        return [], "no releases"
    prod = [x["at"] for x in rows if x.get("prod") and x.get("at")]
    if production_only and prod:
        return prod, "production releases"
    if production_only and not prod:
        return ([x["at"] for x in rows if x.get("at")],
                "all releases — no production-flavoured artifacts exist in this repo, so this "
                "counts every release and may overstate how often the product reaches users")
    return [x["at"] for x in rows if x.get("at")], "all releases"


def parse_ts(s):
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence")
    ap.add_argument("--products", help="comma-separated list that SHOULD have records; "
                                       "a product missing entirely is the finding this catches")
    ap.add_argument("--window", type=int, default=90, help="days of history to reconcile")
    ap.add_argument("--max-gap", type=int, default=2,
                    help="days between runs before the cadence counts as broken")
    ap.add_argument("--out", default="-")
    ap.add_argument("--now")
    args = ap.parse_args()

    now = parse_ts(args.now) or datetime.now(timezone.utc)
    since_dt = now - timedelta(days=args.window)
    since = since_dt

    runs = defaultdict(list)
    for path in sorted(glob.glob(os.path.join(args.evidence, "**", "*.json"), recursive=True)):
        d = load(path)
        if not d or d.get("schema") != "quickbird.kev-monitor-run/v1":
            continue
        # A synthetic run is a test, not evidence that a product was monitored.
        if d.get("synthetic"):
            continue
        at = parse_ts(d.get("run_at"))
        if not at or at < since:
            continue
        runs[d.get("product") or "?"].append((at, d, path))

    expected = [p.strip() for p in (args.products or "").split(",") if p.strip()]
    products = sorted(set(list(runs.keys()) + expected))

    coverage, open_breaches, expired, cadence = [], [], [], []

    for product in products:
        rs = sorted(runs.get(product, []), key=lambda r: r[0])
        if not rs:
            coverage.append({"product": product, "runs": 0, "status": "never-scanned",
                             "detail": "no monitoring record in the window — the product "
                                       "produced no alerts because nothing looked at it"})
            continue

        last_at, last, _ = rs[-1]
        days_since = (now - last_at).days

        # Gaps between consecutive runs. A daily monitor that silently stopped for three
        # weeks looks exactly like three weeks of all-clear.
        gaps = []
        for (a, _, _), (b, _, _) in zip(rs, rs[1:]):
            g = (b - a).days
            if g > args.max_gap:
                gaps.append({"from": a.date().isoformat(), "to": b.date().isoformat(), "days": g})

        status = "ok"
        detail = f"{len(rs)} run(s), last {days_since}d ago"
        if days_since > args.max_gap:
            status = "stale"
            detail = f"last run {days_since}d ago — the monitor is not running"
        elif gaps:
            status = "gaps"
            detail = f"{len(gaps)} gap(s) longer than {args.max_gap}d in the window"

        incomplete = sum(1 for _, d, _ in rs if d.get("verdict") == "incomplete")
        if incomplete and status == "ok":
            status = "incomplete-runs"
            detail += f"; {incomplete} run(s) could not establish an answer"

        coverage.append({"product": product, "runs": len(rs), "status": status,
                         "detail": detail, "last_run": last_at.isoformat(),
                         "gaps": gaps, "incomplete_runs": incomplete,
                         "last_verdict": last.get("verdict")})

        # --- declared cadence vs. reality (§3.4) ---------------------------------
        declared = last.get("release_cadence")
        repo = last.get("repo")
        if not declared:
            cadence.append({"product": product, "status": "not-declared",
                            "detail": "the policy declares no release_cadence, so Track 3/4 "
                                      "deadlines have nothing to derive from"})
        elif not repo:
            cadence.append({"product": product, "declared": declared, "status": "unknown",
                            "detail": "the run record carries no repo, so releases cannot be read"})
        else:
            dates, basis = release_dates(repo)
            expected = CADENCE_DAYS.get(str(declared).lower())
            if dates is None:
                cadence.append({"product": product, "declared": declared, "status": "unknown",
                                "detail": f"could not read releases for {repo} — not knowing "
                                          f"whether the cadence holds is not the same as it holding"})
            elif expected is None:
                cadence.append({"product": product, "declared": declared, "status": "unknown",
                                "detail": f"'{declared}' is not a cadence this can measure "
                                          f"({', '.join(sorted(CADENCE_DAYS))})"})
            elif not dates:
                cadence.append({"product": product, "declared": declared, "status": "broken",
                                "detail": f"declared {declared} but the repo has no releases at all"})
            else:
                newest = parse_ts(dates[0])
                since = (now - newest).days if newest else None
                in_window = sum(1 for d in dates
                                if (p := parse_ts(d)) and p >= since_dt)
                expected_in_window = max(1, int(args.window / expected))
                if since is not None and since > expected * TOLERANCE:
                    status, detail = "broken", (
                        f"declared {declared} (~{expected}d) but the last release was {since}d "
                        f"ago — every Track 3/4 deadline derived from this cadence is fiction")
                elif in_window < expected_in_window:
                    status, detail = "lagging", (
                        f"declared {declared}: expected ~{expected_in_window} release(s) in "
                        f"{args.window}d, found {in_window}")
                else:
                    status, detail = "holds", (
                        f"declared {declared}: {in_window} release(s) in {args.window}d, "
                        f"last {since}d ago")
                cadence.append({"product": product, "declared": declared, "status": status,
                                "detail": detail, "last_release": dates[0],
                                "days_since_last_release": since,
                                "releases_in_window": in_window,
                                "counted": basis})

        esc = (last.get("escalation") or {})
        for e in esc.get("escalations", []) or []:
            if e.get("level") == "undecided":
                open_breaches.append({"product": product, "id": e.get("id"),
                                      "track": e.get("track"),
                                      "detail": (e.get("detail") or [""])[-1]})
            dec = e.get("decision") or {}
            exp = parse_ts(dec.get("expires"))
            if exp and exp < now:
                expired.append({"product": product, "id": e.get("id"),
                                "decision": dec.get("decision"), "expired": dec.get("expires"),
                                "by": dec.get("by")})

    doc = {
        "schema": "quickbird.backstop-report/v1",
        "generated_at": now.isoformat(),
        "window_days": args.window,
        "summary": {
            "products": len(products),
            "never_scanned": sum(1 for c in coverage if c["status"] == "never-scanned"),
            "stale": sum(1 for c in coverage if c["status"] == "stale"),
            "with_gaps": sum(1 for c in coverage if c["status"] == "gaps"),
            "clean": sum(1 for c in coverage if c["status"] == "ok"),
            "undecided_breaches": len(open_breaches),
            "expired_decisions": len(expired),
            "cadence_broken": sum(1 for c in cadence if c["status"] == "broken"),
            "cadence_lagging": sum(1 for c in cadence if c["status"] == "lagging"),
            "cadence_unknown": sum(1 for c in cadence if c["status"] in ("unknown", "not-declared")),
        },
        "coverage": coverage,
        "undecided_breaches": open_breaches,
        "expired_decisions": expired,
        "cadence": cadence,
    }

    # The report is only worth anything if a bad result is visible without reading JSON.
    problems = (doc["summary"]["never_scanned"] + doc["summary"]["stale"]
                + doc["summary"]["with_gaps"] + len(open_breaches) + len(expired)
                + doc["summary"]["cadence_broken"])
    doc["verdict"] = "clean" if problems == 0 else "action-required"

    text = json.dumps(doc, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    s = doc["summary"]
    print(f"backstop: {s['products']} product(s) · {s['clean']} clean · "
          f"{s['never_scanned']} never scanned · {s['stale']} stale · {s['with_gaps']} with gaps · "
          f"{s['undecided_breaches']} undecided breaches · {s['expired_decisions']} expired decisions",
          file=sys.stderr)
    for c in coverage:
        if c["status"] in ("never-scanned", "stale"):
            print(f"::error::{c['product']}: {c['detail']}", file=sys.stderr)
        elif c["status"] != "ok":
            print(f"::warning::{c['product']}: {c['detail']}", file=sys.stderr)
    for b in open_breaches:
        print(f"::error::{b['product']} {b['id']}: {b['detail']}", file=sys.stderr)
    for c in cadence:
        if c["status"] == "broken":
            print(f"::error::{c['product']} cadence: {c['detail']}", file=sys.stderr)
        elif c["status"] in ("lagging", "not-declared", "unknown"):
            print(f"::warning::{c['product']} cadence: {c['detail']}", file=sys.stderr)
    for e in expired:
        print(f"::error::{e['product']} {e['id']}: the {e['decision']} decision expired "
              f"{e['expired'][:10]} and was not renewed", file=sys.stderr)

    # Exit non-zero on action-required: a backstop that always passes is not a control.
    return 0 if doc["verdict"] == "clean" else 1


if __name__ == "__main__":
    sys.exit(main())
