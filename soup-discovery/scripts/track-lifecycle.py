#!/usr/bin/env python3
"""Three-state finding lifecycle (DEV-191).

    open                        the deployed version is vulnerable and no fix is staged
    fix ready - release pending a fix is in main; the deployed version is still vulnerable
    deployed                    the running version contains the fix

The distinction that carries the whole ticket: **only a deploy stops the remediation
clock.** A merged fix satisfies mitigation, because exposure is now bounded by a known
release date, but users are still running the vulnerable build until it ships. Collapsing
the middle state into "fixed" is the failure this exists to prevent — it is how a finding
gets marked resolved while the thing it affects is still live.

That is also why this needs two inputs. The deployed SBOM alone cannot tell "nobody has
fixed it" from "it is fixed and waiting to ship"; both look identical from the running
version. The comparison against main is what separates them.

Usage:
  track-lifecycle.py --deployed <findings.json> [--main <bom-or-findings>]
                     [--state prior.json] [--policy p.json] [--out f]
"""

import argparse
import json
import sys
from datetime import datetime, timezone

OPEN = "open"
FIX_READY = "fix-ready-release-pending"
DEPLOYED = "deployed"
GONE = "no-longer-present"
UNKNOWN = "unknown"


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def component_versions(doc):
    """name -> set(versions) from a CycloneDX document."""
    out = {}
    for c in doc.get("components", []) or []:
        n, v = c.get("name"), c.get("version")
        if n and v:
            out.setdefault(n, set()).add(v)
    return out


def vulnerable_ids(doc):
    return {v.get("id") for v in (doc.get("vulnerabilities") or []) if v.get("id")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deployed", required=True,
                    help="classified findings for the running version")
    ap.add_argument("--main", help="BOM or classified findings for main — without it, "
                                   "fix-ready cannot be distinguished from open")
    ap.add_argument("--state", help="previous lifecycle output")
    ap.add_argument("--policy", help="effective policy, for the release-required signal")
    ap.add_argument("--out", default="-")
    ap.add_argument("--now")
    args = ap.parse_args()

    now = datetime.fromisoformat(args.now) if args.now else datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    deployed = load(args.deployed)
    findings = deployed.get("findings", [])
    policy = load(args.policy) if args.policy else {}

    prior = {}
    if args.state:
        try:
            prior = {f["id"]: f for f in load(args.state)["findings"]}
        except (OSError, KeyError, json.JSONDecodeError):
            print(f"::warning::could not read {args.state} — every finding will look new, "
                  f"and no transition will be reported", file=sys.stderr)

    # main is optional but its absence is a real limitation, not a detail: without it every
    # unfixed finding reads as `open`, and the middle state — the one this ticket exists for
    # — can never be reached.
    main_fixed = None
    if args.main:
        try:
            m = load(args.main)
            main_fixed = (vulnerable_ids(m) if "vulnerabilities" in m
                          else {f["id"] for f in m.get("findings", [])})
        except (OSError, json.JSONDecodeError):
            print(f"::warning::could not read {args.main}", file=sys.stderr)
    if main_fixed is None:
        print("::warning::no main comparison given — 'fix ready, release pending' cannot be "
              "distinguished from 'open'. Findings that are already fixed in main will be "
              "reported as open.", file=sys.stderr)

    out, transitions = [], []
    seen = set()

    for f in findings:
        fid = f["id"]
        seen.add(fid)
        was = prior.get(fid)
        prev_state = was.get("state") if was else None

        if main_fixed is None:
            state = OPEN
            basis = "no main comparison available"
        elif fid not in main_fixed:
            state = FIX_READY
            basis = "not present in main — a fix is staged but the running version still has it"
        else:
            state = OPEN
            basis = "present in main and in the running version"

        rec = dict(f)
        rec["state"] = state
        rec["state_basis"] = basis

        # The remediation clock is only satisfied by a deploy. Mitigation can be satisfied
        # by the staged fix, because exposure is bounded once a release is scheduled.
        rec["mitigation_satisfied"] = state == FIX_READY
        rec["remediation_satisfied"] = False

        # A Track 1 finding whose fix is staged but whose remediation deadline falls before
        # the next scheduled release is the only thing that may force an out-of-band
        # release. Deliberately narrow.
        rec["release_required"] = bool(
            state == FIX_READY
            and f.get("track") == "immediate"
            and f.get("remediation_due")
            and not f.get("remediation_overdue", False)
        )
        if state == FIX_READY and f.get("remediation_overdue"):
            rec["release_required"] = True
            rec["release_required_why"] = "remediation deadline already breached and the fix is not live"
        elif rec["release_required"]:
            rec["release_required_why"] = (
                f"Track 1 fix is staged but not deployed; remediation due "
                f"{(f.get('remediation_due') or '')[:10]}"
            )

        if prev_state and prev_state != state:
            transitions.append({"id": fid, "from": prev_state, "to": state, "at": now.isoformat()})
        rec["state_since"] = (was.get("state_since") if was and prev_state == state
                              else now.isoformat())
        out.append(rec)

    # A finding that was tracked and is no longer reported for the running version is
    # resolved — but only because we successfully scanned. `deployed` is a claim that the
    # running version no longer contains it, and that claim needs a scan behind it.
    scan_ok = deployed.get("summary", {}).get("total") is not None
    for fid, was in prior.items():
        if fid in seen:
            continue
        rec = dict(was)
        if scan_ok:
            rec["state"] = DEPLOYED
            rec["state_basis"] = "no longer reported for the running version — the fix is live"
            rec["remediation_satisfied"] = True
            rec["mitigation_satisfied"] = True
        else:
            rec["state"] = UNKNOWN
            rec["state_basis"] = "not in this run's results, but the scan did not complete — absence is not resolution"
            rec["remediation_satisfied"] = False
        rec["release_required"] = False
        if was.get("state") != rec["state"]:
            transitions.append({"id": fid, "from": was.get("state"), "to": rec["state"],
                                "at": now.isoformat(), "resolved": rec["state"] == DEPLOYED})
        rec["state_since"] = now.isoformat()
        out.append(rec)

    by_state = {}
    for r in out:
        by_state[r["state"]] = by_state.get(r["state"], 0) + 1

    release_required = [r for r in out if r.get("release_required")]
    doc = {
        "schema": "quickbird.finding-lifecycle/v1",
        "evaluated_at": now.isoformat(),
        "product": deployed.get("product") or policy.get("product"),
        "main_comparison": args.main is not None and main_fixed is not None,
        "summary": {
            "total": len(out),
            "by_state": by_state,
            "release_required": len(release_required),
            "transitions": len(transitions),
            "resolved_this_run": sum(1 for t in transitions if t.get("resolved")),
        },
        "release_required": [
            {"id": r["id"], "track": r.get("track"),
             "remediation_due": r.get("remediation_due"),
             "why": r.get("release_required_why")} for r in release_required],
        "transitions": transitions,
        "findings": out,
    }

    text = json.dumps(doc, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    s = doc["summary"]
    print("lifecycle: " + ", ".join(f"{k} {v}" for k, v in sorted(by_state.items()))
          + f" · {s['transitions']} transitions"
          + f" · {s['resolved_this_run']} resolved"
          + f" · {s['release_required']} release-required", file=sys.stderr)

    for r in release_required:
        print(f"::warning::release required: {r['id']} — {r.get('release_required_why')}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
