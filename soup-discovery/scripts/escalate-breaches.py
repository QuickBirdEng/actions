#!/usr/bin/env python3
"""Deadline escalation (WI-006-09: Decide).

A deadline that is only checked at the moment it expires is a deadline nobody can act on.
This produces four levels, so the alert changes before the date rather than after it:

    ok           the deadline is far enough away to be routine
    approaching  inside the lead time — the alert says so and names the date
    breached     past due, and a documented decision is now required within 5 working days
    undecided    breached, the decision window has also elapsed, nothing recorded

`undecided` is the level that matters. WI-006-09: Decide does not say "escalate on breach" and stop; it
requires a *recorded decision* — a revised remediation date or a risk acceptance — within
five working days. Without somewhere to record that, a breach escalates once and then
becomes background noise, which is exactly the state a backstop review is supposed to
catch and too late.

Decisions live in `.soup-decisions.yml` in the repo, next to `.soup-scope.yml` and
`.soup-policy.yml`, for the same reason VEX statements live in the SOUP records: a decision
to accept a missed deadline on a medical device should arrive as a reviewable change, not
as a Slack reply.

Usage: escalate-breaches.py <lifecycle-or-findings.json> [--decisions f] [--policy p]
                            [--lead 7d] [--out f] [--now ISO]
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

OK, APPROACHING, BREACHED, UNDECIDED = "ok", "approaching", "breached", "undecided"
# A unit whose fix is on a third party's release schedule is not in breach: the request is on
# record and has a follow-up date. It sits between "approaching" and "breached" — visible on
# every run, but not demanding a decision that is not ours to make.
WAITING = "waiting-on-vendor"
RANK = {OK: 0, APPROACHING: 1, WAITING: 1, BREACHED: 2, UNDECIDED: 3}


def parse_dur(s, default_days=7):
    if not s:
        return timedelta(days=default_days)
    try:
        if s.endswith("h"):
            return timedelta(hours=int(s[:-1]))
        if s.endswith("d"):
            return timedelta(days=int(s[:-1]))
    except ValueError:
        pass
    return timedelta(days=default_days)


def working_days_between(a, b):
    """Whole working days from a to b, weekends excluded.

    WI-006-09: Decide says five *working* days. Counting calendar days would silently shorten the window
    across a weekend and escalate a finding whose owner has not yet had the chance to look
    at it — which trains people to treat the escalation as noise.
    """
    if b <= a:
        return 0
    days = 0
    cur = a.date()
    end = b.date()
    while cur < end:
        cur += timedelta(days=1)
        if cur.weekday() < 5:
            days += 1
    return days


def load_decisions(path):
    """CVE -> decision.

    YAML is converted by yq rather than pyyaml: the pipeline already requires yq, and
    adding a Python YAML dependency would mean a runner without it silently reports every
    breach as undecided — a wrong answer that looks like a real finding.
    """
    if not path:
        return {}
    try:
        if path.endswith((".yml", ".yaml")):
            r = subprocess.run(["yq", "-o=json", ".", path],
                               capture_output=True, text=True, check=True)
            doc = json.loads(r.stdout or "{}") or {}
        else:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh) or {}
    except FileNotFoundError:
        return {}
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError) as e:
        # Refuse rather than degrade: an unreadable decisions file makes every recorded
        # decision invisible, and the run would escalate breaches that are already handled.
        print(f"::error::could not read {path}: {e}", file=sys.stderr)
        raise SystemExit(1)
    out = {}
    for d in doc.get("decisions", []) or []:
        if d.get("cve"):
            out[d["cve"]] = d
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--decisions", help=".soup-decisions.yml")
    ap.add_argument("--policy")
    ap.add_argument("--units", help="group-remediation.py output. With it, escalation happens "
                                    "per remediation action rather than per finding, which is "
                                    "the whole point of WI-006-09-01: What carries the timeframe: one decision, not hundreds")
    ap.add_argument("--lead", default="7d", help="how long before a deadline to start warning")
    ap.add_argument("--out", default="-")
    ap.add_argument("--now")
    args = ap.parse_args()

    now = datetime.fromisoformat(args.now) if args.now else datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    lead = parse_dur(args.lead)

    doc = json.load(open(args.findings, encoding="utf-8"))

    # finding id -> the action(s) that resolve it. A list, not a single index: a finding
    # affecting more than one artifact or dependency is a real member of more than one unit
    # (WI-006-09-01: What carries the timeframe), and a `unit_of[fid] = i` overwrite would
    # escalate its breach under only the last unit found, silencing it in every other one.
    units, unit_of = [], defaultdict(list)
    if args.units:
        try:
            u = json.load(open(args.units, encoding="utf-8"))
            units = u.get("units", []) or []
        except (OSError, json.JSONDecodeError) as e:
            print(f"::error::could not read {args.units}: {e}", file=sys.stderr)
            return 1
        for i, unit in enumerate(units):
            for fid in unit.get("findings", []) or []:
                unit_of[fid].append(i)
    policy = json.load(open(args.policy, encoding="utf-8")) if args.policy else {}
    decision_window = int(str(policy.get("breach", {}).get("decision_within", "5d")).rstrip("d") or 5)
    decisions = load_decisions(args.decisions)

    results = []
    for f in doc.get("findings", []):
        # A finding whose remediation is already satisfied has no live deadline.
        if f.get("remediation_satisfied"):
            continue

        worst, detail = OK, []
        for clock in ("mitigation", "remediation"):
            if f.get(f"{clock}_satisfied"):
                continue
            due_s = f.get(f"{clock}_due")
            if not due_s:
                continue
            due = datetime.fromisoformat(due_s)
            if now > due:
                level = BREACHED
                overdue_wd = working_days_between(due, now)
                dec = decisions.get(f["id"])
                if dec:
                    detail.append(f"{clock} breached {overdue_wd} working day(s) ago. "
                                  f"Decision on record: {dec.get('decision','?')}")
                elif overdue_wd > decision_window:
                    level = UNDECIDED
                    detail.append(f"{clock} breached {overdue_wd} working days ago and no "
                                  f"decision is recorded. WI-006-09: Decide required one within {decision_window}")
                else:
                    detail.append(f"{clock} breached. A documented decision is required within "
                                  f"{decision_window - overdue_wd} more working day(s)")
            elif due - now <= lead:
                level = APPROACHING
                hrs = int((due - now).total_seconds() // 3600)
                detail.append(f"{clock} due in {hrs}h ({due_s[:10]})")
            else:
                level = OK
            if RANK[level] > RANK[worst]:
                worst = level

        if worst == OK:
            continue

        dec = decisions.get(f["id"])
        results.append({
            "id": f["id"],
            "track": f.get("track"),
            "state": f.get("state"),
            "level": worst,
            "detail": detail,
            "mitigation_due": f.get("mitigation_due"),
            "remediation_due": f.get("remediation_due"),
            "decision": ({"decision": dec.get("decision"), "by": dec.get("by"),
                          "date": dec.get("date"), "expires": dec.get("expires"),
                          "reason": dec.get("reason")} if dec else None),
        })

    # A recorded decision that has itself expired is worse than none: it reads as handled.
    for r in results:
        d = r.get("decision")
        if d and d.get("expires"):
            try:
                if datetime.fromisoformat(d["expires"]).replace(tzinfo=timezone.utc) < now:
                    r["level"] = UNDECIDED
                    r["detail"].append(f"the recorded decision expired on {d['expires'][:10]} "
                                       f"and has not been renewed")
            except ValueError:
                pass

    # --- collapse to remediation actions (WI-006-09-01: What carries the timeframe) ------------------------------
    # Without this, a waiting-on-vendor image with 99 findings in it escalates 99 times and the
    # grouping achieves nothing. The unit takes the worst level among its members, so nothing
    # is hidden — 99 lines become one line that names 99 findings.
    if units:
        per_unit = {}
        standalone = []
        for r in results:
            idxs = unit_of.get(r["id"])
            if not idxs:
                standalone.append(r)
                continue
            # Every unit this finding is a member of sees its breach, not just one of them.
            for idx in idxs:
                per_unit.setdefault(idx, []).append(r)

        collapsed = []
        for idx, members in per_unit.items():
            unit = units[idx]
            worst = max(members, key=lambda m: RANK[m["level"]])
            level = worst["level"]
            detail = list(worst["detail"])
            state = unit.get("state", "ours")

            # A fix on someone else's release schedule is not a breach of ours. It stays
            # visible on every run and it does not ask anyone to accept a risk they cannot
            # remove — but an elapsed follow-up date turns it into a real decision, and that
            # decision is about the image, not about each finding inside it.
            if state == "waiting-on-vendor":
                # Including when the members are `undecided`. That level means "the deadline
                # passed and no decision is on record" — and a dated request to the vendor with
                # a live follow-up date IS the record. Requiring a second decision on top of it
                # would ask someone to accept a risk they have already acted on and cannot
                # remove. The follow-up date is what keeps this from becoming a parking space.
                level = WAITING
                detail = [unit.get("state_detail", "")]
            elif state == "vendor-overdue":
                level = UNDECIDED
                detail = [unit.get("state_detail", "")]
            elif state in ("no-vendor-request", "vendor-request-undated") and RANK[level] >= RANK[BREACHED]:
                detail = [unit.get("state_detail", "")] + detail

            collapsed.append({
                "unit": unit.get("action"),
                "kind": unit.get("kind"),
                "artifact": unit.get("artifact"),
                "state": state,
                "id": unit.get("id") or f"{unit.get('kind')}:{unit.get('artifact')}",
                "track": unit.get("track"),
                "level": level,
                "detail": detail,
                "finding_count": len(unit.get("findings", []) or []),
                "escalating_findings": [m["id"] for m in members],
                "kev_findings": unit.get("kev_findings", []),
                "shared_findings": unit.get("shared_findings", {}),
                "mitigation_due": unit.get("mitigation_due"),
                "remediation_due": unit.get("remediation_due"),
                "vendor_request": unit.get("vendor_request"),
                "decision": worst.get("decision"),
            })
        results = collapsed + standalone

    results.sort(key=lambda r: (-RANK[r["level"]], r.get("track") or ""))
    by_level = {}
    for r in results:
        by_level[r["level"]] = by_level.get(r["level"], 0) + 1

    out = {
        "schema": "quickbird.deadline-escalation/v1",
        "evaluated_at": now.isoformat(),
        "lead_time": args.lead,
        "decision_window_working_days": decision_window,
        "summary": {"total": len(results), "by_level": by_level,
                    "worst": (results[0]["level"] if results else OK)},
        "escalations": results,
    }
    text = json.dumps(out, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    if results:
        print("escalation: " + ", ".join(f"{k} {v}" for k, v in sorted(by_level.items())),
              file=sys.stderr)
        for r in results:
            if r["level"] == UNDECIDED:
                # the last detail is the one that raised the level; detail[0] may be an
                # earlier, milder observation about the other clock
                print(f"::error::{r['id']}: {r['detail'][-1]}", file=sys.stderr)
    else:
        print("escalation: nothing approaching or breached", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
