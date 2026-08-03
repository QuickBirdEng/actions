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
import re
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



# What counts as a production release is not a property of a tag. Read from the pipeline: a tag
# push triggers the *staging* workflow (both plain and -qaN forms), and production is a manual
# `workflow_dispatch` of a separate workflow, gated by a named allow-list. So the authoritative
# record is the GitHub deployment with environment=Production — the same source resolve-deployed.sh
# already uses to answer "what is running".
#
# The three signals this replaces were all proxies and all wrong. Measured on alvie: the tag
# pattern said 2025-10-01, the prerelease flag 2026-05-04, the asset name 2025-06-23 — and the
# production deployment record says v1.0.7 was deployed on 2026-04-21, six months after that tag
# was published. A release date is not a deploy date.
# `Study` counts too. On these products a study environment is usually the same thing as
# production — Osteocoach has no environment named Production at all and deploys `Study`, so
# matching only /prod/ reported a live product as unseeable. Kept as a fixed list rather than a
# per-project setting: the environment names are a fact about the pipeline, and a knob here would
# be one more thing to get wrong.
PRODUCTION_ENV_RX = re.compile(r"prod|study", re.I)
# A deployment whose ref is not a tag is not an application release. mindnet's newest Production
# record is a branch ref from a content-migration workflow; counting it would date the maintenance
# grid from a database migration. Same rule as resolve-deployed.sh.
TAG_REF_RX = re.compile(r"^v?[0-9]+(\.[0-9]+)*([.-][A-Za-z0-9.+-]+)?$")


def _gh_json(args, timeout=60):
    try:
        r = subprocess.run(["gh", "api"] + args, capture_output=True, text=True,
                           timeout=timeout, check=True)
        return [json.loads(l) for l in (r.stdout or "").splitlines() if l.strip()]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, json.JSONDecodeError):
        return None


def production_deploys(repo):
    """Production deployment timestamps with a tag ref, newest first.

    Returns (dates, basis, environments_seen). `dates` is None only if the records could not be
    read — which is not the same as a product that never deployed and must not read as one.

    Filtered server-side by environment. Paginating the whole deployment history does not work at
    this scale: mindnet has ~25,000 records across its environments and the unfiltered walk timed
    out, reporting a product with 1059 production deploys as unknown. Filtered, the same answer
    takes under a second.
    """
    # `--jq .environments[].name` emits bare strings, which are not JSON per line — the parser
    # returned None and the whole thing fell into the fallback path, silently reporting products
    # with hundreds of production deploys as having none. Ask for objects.
    envs_doc = _gh_json([f"repos/{repo}/environments", "--jq",
                         '.environments[] | {name: .name}'])
    if envs_doc is None:
        # Fall back to one unfiltered page rather than giving up: better a partial answer that
        # says so than none.
        rows = _gh_json([f"repos/{repo}/deployments?per_page=100", "--jq",
                         '.[] | {at: .created_at, env: .environment, ref: .ref}'])
        if rows is None:
            return None, None, []
        envs = sorted({str(x.get("env") or "?") for x in rows})
        prod_rows = [x for x in rows if PRODUCTION_ENV_RX.search(str(x.get("env") or ""))]
        suffix = " (environment list unavailable; read from the newest 100 records only)"
    else:
        envs = sorted(str(e.get("name")) for e in envs_doc if e.get("name"))
        prod_envs = [e for e in envs if PRODUCTION_ENV_RX.search(e)]
        if not prod_envs:
            return ([], f"no production environment among the ones this repo defines "
                        f"({', '.join(envs[:6]) or 'none'})", envs)
        prod_rows = []
        for e in prod_envs:
            got = _gh_json([f"repos/{repo}/deployments?environment={e}&per_page=100", "--jq",
                            '.[] | {at: .created_at, env: .environment, ref: .ref}'])
            if got:
                prod_rows.extend(got)
        suffix = ""

    if not prod_rows:
        return ([], f"no deployment records at all{suffix}"
                    if not envs else f"no production deployment records{suffix}", envs)

    prod_rows.sort(key=lambda x: str(x.get("at") or ""), reverse=True)
    tagged = [x["at"] for x in prod_rows
              if x.get("at") and TAG_REF_RX.match(str(x.get("ref") or ""))]
    if not tagged:
        return ([], f"{len(prod_rows)} production deployment(s), none from a tag — the newest ref "
                    f"is {prod_rows[0].get('ref')!r}, which is not an application release{suffix}",
                envs)
    dropped = len(prod_rows) - len(tagged)
    basis = f"production deployments from a tag{suffix}"
    if dropped:
        basis += f" ({dropped} non-tag production record(s) ignored — not application releases)"
    return tagged, basis, envs


def parse_interval_days(s, default=90):
    """'90d' / '3m' / '90' -> days. Mirrors maintenance-windows.py."""
    if not s:
        return default
    t = str(s).strip().lower()
    try:
        if t.endswith("d"):
            return int(t[:-1])
        if t.endswith("m"):
            return int(t[:-1]) * 30
        if t.endswith("y"):
            return int(t[:-1]) * 365
        return int(t)
    except ValueError:
        return default


def window_grid(origin, interval_days, now):
    """Elapsed windows and the next one. A missed window advances the grid from its own due
    date rather than from a release that never happened — otherwise not releasing buys time."""
    step = timedelta(days=interval_days)
    due = origin + step
    missed = []
    while due < now:
        missed.append(due)
        due = due + step
    return missed, due


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
    drift = []

    for product in products:
        rs = sorted(runs.get(product, []), key=lambda r: r[0])
        if not rs:
            coverage.append({"product": product, "runs": 0, "status": "never-scanned",
                             "detail": "no monitoring record in the window — the product "
                                       "produced no alerts because nothing looked at it"})
            continue

        last_at, last, _ = rs[-1]
        days_since = (now - last_at).days

        # --- QMS determinations that changed under us ----------------------------
        # Decided 2026-08-03: tier and cra_scope stay in the product repo, protected by
        # CODEOWNERS. That is a review control, and a review control is only as good as the
        # branch protection behind it — so the evidence store gets a detection to go with it.
        # Both values move a real obligation: tier caps the maintenance commitment and sets the
        # backstop interval, cra_scope decides whether a KEV alert says a 24-hour reporting
        # clock is running. A change is not necessarily wrong; going unnoticed is.
        for field in ("tier", "cra_scope", "maintenance_interval"):
            seen = []
            for at, rec, _ in rs:
                val = rec.get(field)
                if val is None or val == "":
                    continue
                if not seen or seen[-1][1] != val:
                    seen.append((at, val))
            if len(seen) > 1:
                drift.append({
                    "product": product,
                    "field": field,
                    "changes": [{"at": a.isoformat(), "to": str(v)} for a, v in seen],
                    "detail": (f"{field} changed during the window: "
                               + " -> ".join(f"{v} ({a.date().isoformat()})" for a, v in seen)
                               + ". This value is agreed with the customer in the SLA and "
                                 "copied into the product repo; confirm the change followed a "
                                 "change to the contract and was reviewed."),
                })

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

        # --- the maintenance commitment vs. reality (§3.4) -----------------------
        # Not "does the observed rhythm match a declared one" any more. A product commits to a
        # maintenance release at least every `maintenance_interval`, every open Track 3/4
        # finding targets the same window, and the question here is whether the windows were
        # met. A missed window is one finding about a release — not one per CVE, which on
        # Kontina would have been 196.
        interval = last.get("maintenance_interval")
        repo = last.get("repo")
        onboarded = parse_ts(last.get("onboarded"))
        if not interval:
            cadence.append({"product": product, "status": "not-declared",
                            "detail": "the policy declares no maintenance_interval, so Track 3/4 "
                                      "findings have no window to land on and cannot breach"})
        elif not repo:
            cadence.append({"product": product, "declared": interval, "status": "unknown",
                            "detail": "the run record carries no repo, so releases cannot be read"})
        else:
            iv = parse_interval_days(interval)
            dates, basis, envs = production_deploys(repo)
            if dates is None:
                cadence.append({"product": product, "declared": interval, "status": "unknown",
                                "detail": f"could not read the deployment records for {repo} — "
                                          f"not knowing whether the maintenance windows were met "
                                          f"is not the same as them having been met",
                                "environments": envs})
            elif not dates:
                # Deliberately `unknown`, not `broken`. A repo with no production environment is
                # not a product that never maintains itself — it is a product this check cannot
                # see, and saying otherwise would put a wrong finding in front of someone.
                # Measured: osteocoach deploys to `Study`, kontina-backend has no deployment
                # records at all.
                cadence.append({"product": product, "declared": interval, "status": "unknown",
                                "detail": f"commits to maintenance every {interval}, but the "
                                          f"deployment records do not show a production release: "
                                          f"{basis}. Either this product deploys under a different "
                                          f"environment name, or its production deploys are not "
                                          f"recorded as GitHub deployments — both are worth fixing, "
                                          f"because this is the same record that answers what is "
                                          f"running.",
                                "counted": basis, "environments": envs})
            else:
                newest = parse_ts(dates[0])
                origin = newest
                origin_basis = "last production deployment from a tag"
                if onboarded and newest and onboarded > newest:
                    origin = onboarded
                    origin_basis = ("onboarding date — windows that elapsed before monitoring "
                                    "existed are history, not breaches")
                missed, nxt = window_grid(origin, iv, now)
                since = max(0, (now - newest).days) if newest else None
                if missed:
                    status, detail = "broken", (
                        f"commits to maintenance every {interval}; {len(missed)} window(s) "
                        f"missed since {origin.date().isoformat()} (last was "
                        f"{missed[-1].date().isoformat()}). One decision is required about the "
                        f"release, not one per finding — every open Track 3/4 finding was due in "
                        f"a window that did not happen")
                else:
                    status, detail = "holds", (
                        f"commits to maintenance every {interval}: next window "
                        f"{nxt.date().isoformat()} in {(nxt - now).days}d, last "
                        f"production deploy {since}d ago")
                cadence.append({"product": product, "declared": interval, "status": status,
                                "detail": detail, "last_release": dates[0],
                                "days_since_last_release": since,
                                "next_window": nxt.isoformat(),
                                "missed_windows": [d.isoformat() for d in missed],
                                "grid_origin": origin.isoformat(),
                                "grid_origin_basis": origin_basis,
                                "counted": basis,
                                "environments": envs})

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
            "determination_drift": len(drift),
        },
        "coverage": coverage,
        "undecided_breaches": open_breaches,
        "expired_decisions": expired,
        "cadence": cadence,
        "determination_drift": drift,
    }

    # The report is only worth anything if a bad result is visible without reading JSON.
    problems = (doc["summary"]["never_scanned"] + doc["summary"]["stale"]
                + doc["summary"]["with_gaps"] + len(open_breaches) + len(expired)
                + doc["summary"]["cadence_broken"] + len(drift))
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
