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
     cadence that no longer holds turns every Track 3 deadline into fiction (§3.4).
     NOT YET IMPLEMENTED — reported under `not_checked` rather than silently omitted.

Reads the evidence store — the dated run records the monitor writes — rather than
recomputing anything. If a run never happened there is nothing to recompute, and that
absence is precisely what this is looking for.

Usage: backstop-report.py <evidence-dir> [--products a,b] [--window 90] [--out f]
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


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
    since = now - timedelta(days=args.window)

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

    coverage, open_breaches, expired = [], [], []

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
        },
        "coverage": coverage,
        "undecided_breaches": open_breaches,
        "expired_decisions": expired,
        # §3.4 asks the backstop to compare each declared release cadence against what was
        # actually released, because a cadence that no longer holds turns every Track 3
        # deadline into fiction. That needs the release history, which lives in GitHub and
        # not in the evidence store, so it is stated as missing rather than shipped as an
        # empty list that reads like a clean result.
        "not_checked": [
            "declared release cadence vs. actual releases (§3.4) — needs the release "
            "history; run resolve-deployed against each repo and compare"
        ],
    }

    # The report is only worth anything if a bad result is visible without reading JSON.
    problems = (doc["summary"]["never_scanned"] + doc["summary"]["stale"]
                + doc["summary"]["with_gaps"] + len(open_breaches) + len(expired))
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
    for e in expired:
        print(f"::error::{e['product']} {e['id']}: the {e['decision']} decision expired "
              f"{e['expired'][:10]} and was not renewed", file=sys.stderr)

    # Exit non-zero on action-required: a backstop that always passes is not a control.
    return 0 if doc["verdict"] == "clean" else 1


if __name__ == "__main__":
    sys.exit(main())
