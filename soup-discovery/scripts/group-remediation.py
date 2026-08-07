#!/usr/bin/env python3
"""Group findings by the action that resolves them (WI: What carries the timeframe).

A deadline on a CVE assumes the CVE is a unit of work. Usually it is not. Measured on
one backend product, where the per-finding model demanded mitigation of 23 findings in 72 hours
and 288 more in 20 days:

    521 findings  ->  2 actions

Both actions are "bump or replace a third-party image": 422 of the findings are inside a
vendor REST service we deploy but do not build, 99 inside a third-party WireGuard image.
**Not one of the 521 is in code QuickBird writes.**

That is why the per-finding deadlines could not be met, and it was never about capacity. The
deadline was attached to the wrong thing. This is the same error WI: The maintenance window removed from Track 3,
and the same repair applies: the deadline belongs to the action.

A **remediation unit** is one action:

    third-party image    every finding inside an image we deploy but do not build. There is
                         exactly one lever — a newer image from its vendor, a different image,
                         or a documented compensating control. Grouping these per package
                         would produce actions nobody here can perform, which the first
                         version of this script did: ten separate "upgrade <go module>" items
                         inside someone else's WireGuard image.
    base-image bump      OS-package findings in an image we do build. Annex B B.1.1 already says a CVE
                         in an OS package is remediated by bumping the image; this makes that
                         operational.
    dependency upgrade   one direct dependency in our own code. Here the CVE genuinely is
                         close to the unit of work.
    no upgrade path      findings in our own code whose advisory publishes no fixed version.
                         Separate because an upgrade is not available: the routes are a
                         compensating control or a VEX statement.

The unit inherits the **worst track** of its members and the **earliest** deadline among them,
so grouping can never move a deadline outward — only the number of decisions changes. A KEV
finding in an OS package pulls its whole image bump to Track 1, which is correct: the image is
what gets bumped either way.

Nothing here softens a classification. Every finding keeps its track and its dates. What
changes is that the deadline is attached to something a person can do, and that a missed
deadline produces one decision instead of hundreds.

Usage: group-remediation.py <classified-findings.json> <assessed-bom.cdx.json> [--out f]
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone

TRACK_ORDER = ["kev", "immediate", "expedited", "planned", "monitor"]

# Package types that are OS packages, i.e. contents of a base image rather than something a
# developer selected. Kept explicit rather than inferred from a `distro=` qualifier, because
# a missing qualifier would silently reclassify a finding into its own unit.
OS_PKG_TYPES = {"rpm", "deb", "apk"}


def is_third_party_image(artifact):
    """Is this an image we deploy but do not build?

    discover.sh names those candidates `deployed-*` — they come from a registry reference in a
    manifest rather than from a Dockerfile in our repo. The distinction decides what actions
    exist at all: inside an image we do not build, "upgrade golang.org/x/crypto" is not
    something anyone here can do. The only action is to bump or replace the image, or to ask
    its vendor.

    Getting this wrong is not cosmetic. On one backend product the first version of this grouping
    produced ten separate "upgrade <module>" actions inside a third-party WireGuard image, none
    of which QuickBird can perform.
    """
    return artifact.replace("quickbird:artifact:", "").startswith("deployed-")


def parse_ts(v):
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def load_vendor_requests(path):
    """Unit key -> recorded request to a third-party vendor.

    Both remediation units of the product it was measured on are "bump or replace a third-party
    image", so
    the fix is on someone else's release schedule. A 30-day deadline on such a unit breaches
    with certainty and without anyone having done anything wrong — which produces exactly the
    rubber stamps WI: What carries the timeframe was meant to remove.

    So a documented request to the vendor puts the unit in `waiting-on-vendor`: not a breach,
    but not closed either. It carries a follow-up date, and when that passes with no new image
    the escalation is about replacing the image, not about accepting each CVE.

    Lives in .soup-decisions.yml next to the deadline decisions, and read through yq for the
    same reason: a missing Python YAML module would otherwise make every recorded request
    invisible and report handled units as breached.
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
        print(f"::error::could not read {path}: {e}", file=sys.stderr)
        raise SystemExit(1)
    out = {}
    for v in doc.get("vendor_requests", []) or []:
        if v.get("unit"):
            out[str(v["unit"])] = v
    return out


def props(obj):
    return {p["name"]: p["value"] for p in obj.get("properties", []) or []}


def purl_type(purl):
    m = re.match(r"^pkg:([a-zA-Z0-9._-]+)/", purl or "")
    return (m.group(1).lower() if m else "")


def purl_name(purl):
    """Readable package name: the last path segment before the version."""
    body = (purl or "").split("?")[0].split("@")[0]
    seg = [s for s in body.replace("pkg:", "", 1).split("/") if s]
    return seg[-1] if len(seg) > 1 else (seg[0] if seg else "?")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("bom")
    ap.add_argument("--decisions", help=".soup-decisions.yml, for recorded vendor requests")
    ap.add_argument("--now")
    ap.add_argument("--out", default="-")
    args = ap.parse_args()

    now = parse_ts(args.now) or datetime.now(timezone.utc)
    vendor = load_vendor_requests(args.decisions)

    doc = json.load(open(args.findings, encoding="utf-8"))
    bom = json.load(open(args.bom, encoding="utf-8"))

    # component ref -> what it is and where it came from
    comp = {}
    for c in bom.get("components", []) or []:
        p = props(c)
        comp[c.get("bom-ref")] = {
            "purl": c.get("purl") or "",
            "name": c.get("name") or "?",
            "version": c.get("version") or "",
            "artifact": p.get("quickbird:component:artifact", ""),
        }

    # finding id -> the refs it affects, and its published fix status
    affects = defaultdict(list)
    fix_status = {}
    for v in bom.get("vulnerabilities", []) or []:
        for a in v.get("affects", []) or []:
            if a.get("ref"):
                affects[v.get("id")].append(a["ref"])
        fix_status[v.get("id")] = props(v).get("quickbird:vuln:fix", "unknown")

    units = {}
    unplaced = []
    for f in doc.get("findings", []):
        fid = f.get("id")
        refs = affects.get(fid) or []
        if not refs:
            # A finding with no affected component cannot be assigned to an action. Reported
            # rather than dropped: it still has a track and a deadline of its own.
            unplaced.append({"id": fid, "track": f.get("track"),
                             "why": "the BOM records no affected component for this finding"})
            continue

        for ref in refs:
            c = comp.get(ref)
            if not c:
                unplaced.append({"id": fid, "track": f.get("track"),
                                 "why": f"affected ref {ref} is not in the component list"})
                continue

            artifact = c["artifact"] or "unattributed"
            ptype = purl_type(c["purl"])
            fx = fix_status.get(fid, "unknown")

            if is_third_party_image(artifact):
                # One unit for the whole image, whatever the package type. We do not build it,
                # so there is exactly one lever: a newer image, a different image, or a VEX.
                key = ("third-party-image", artifact)
                img = artifact.replace("quickbird:artifact:", "").replace("deployed-", "")
                action = (f"bump or replace the third-party image {img} — we do not build it, "
                          f"so nothing inside it can be upgraded here; the levers are a newer "
                          f"image from its vendor, a different image, or a documented "
                          f"compensating control")
            elif fx == "none-published":
                key = ("no-upgrade-path", artifact)
                action = (f"no upgrade path in {artifact.replace('quickbird:artifact:', '')} — "
                          f"the advisory publishes no fixed version, so this needs a "
                          f"compensating control or a VEX statement, not a bump")
            elif ptype in OS_PKG_TYPES:
                key = ("base-image-bump", artifact)
                action = (f"bump the base image of "
                          f"{artifact.replace('quickbird:artifact:', '')}")
            else:
                key = ("dependency-upgrade", artifact, purl_name(c["purl"]))
                action = (f"upgrade {purl_name(c['purl'])} in "
                          f"{artifact.replace('quickbird:artifact:', '')}")

            u = units.setdefault(key, {
                "kind": key[0], "artifact": artifact, "action": action,
                "findings": [], "components": set(), "fix_status": set(),
                "no_fix": set(),
            })
            u["findings"].append(fid)
            u["components"].add(f"{c['name']}@{c['version']}")
            u["fix_status"].add(fx)
            if fx == "none-published":
                u["no_fix"].add(fid)

    by_track = {f["id"]: f for f in doc.get("findings", [])}
    out_units = []
    for key, u in units.items():
        members = sorted(set(u["findings"]))
        tracks = [by_track[m].get("track") for m in members if m in by_track]
        worst = min((TRACK_ORDER.index(t) for t in tracks if t in TRACK_ORDER),
                    default=len(TRACK_ORDER) - 1)
        worst_track = TRACK_ORDER[worst]
        # The unit's deadline is the earliest deadline among its members, so grouping can
        # never move a deadline outward — only the number of decisions changes.
        def earliest(field):
            vals = [by_track[m].get(field) for m in members
                    if m in by_track and by_track[m].get(field)]
            return min(vals) if vals else None

        # The field is the string "true" / "unknown" / None, straight from the BOM property —
        # `is True` never matched and every unit reported zero KEV members, including units
        # whose track was `kev`. "unknown" deliberately counts: it classifies as KEV.
        kev = [m for m in members
               if m in by_track and by_track[m].get("kev") in ("true", "unknown")]
        out_units.append({
            "kind": u["kind"],
            "artifact": u["artifact"],
            "action": u["action"],
            "track": worst_track,
            "finding_count": len(members),
            "findings": members,
            "kev_findings": kev,
            "component_count": len(u["components"]),
            # Even a bump may not clear these: the advisory publishes no fixed version. Carried
            # on the unit so it is visible without splitting the action in two.
            "findings_without_published_fix": len(u["no_fix"]),
            "mitigation_due": earliest("mitigation_due"),
            "remediation_due": earliest("remediation_due"),
            "fix_status": sorted(u["fix_status"]),
        })

    # --- vendor state (WI: What carries the timeframe) -------------------------------------------------
    # A third-party image is the case where remediation is not ours to perform. The state says
    # which of three situations a unit is in, and only the last one is a breach.
    for unit in out_units:
        img = unit["artifact"].replace("quickbird:artifact:", "")
        req = vendor.get(img) or vendor.get(unit["artifact"])
        if unit["kind"] != "third-party-image":
            unit["state"] = "ours"
            continue
        if not req:
            unit["state"] = "no-vendor-request"
            unit["state_detail"] = (
                "remediation here means a newer image from the vendor, and no request to them "
                "is on record. Until one is, the deadline below is being counted against work "
                "nobody has started — record the request in .soup-decisions.yml under "
                "vendor_requests, or decide to replace the image.")
            continue
        follow = parse_ts(req.get("follow_up"))
        unit["vendor_request"] = {
            "requested": str(req.get("requested") or ""),
            "follow_up": str(req.get("follow_up") or ""),
            "contact": str(req.get("contact") or ""),
            "note": str(req.get("note") or ""),
        }
        if follow and now > follow:
            unit["state"] = "vendor-overdue"
            unit["state_detail"] = (
                f"the vendor was asked on {req.get('requested')} and the follow-up date "
                f"{req.get('follow_up')} has passed with no fixed image. The decision now is "
                f"whether to replace this image, not whether to accept each finding in it.")
        elif follow:
            unit["state"] = "waiting-on-vendor"
            unit["state_detail"] = (
                f"requested from the vendor on {req.get('requested')}; following up "
                f"{req.get('follow_up')}. Not a breach — the fix is on their release schedule, "
                f"and this is on record.")
        else:
            unit["state"] = "vendor-request-undated"
            unit["state_detail"] = (
                "a request to the vendor is recorded but carries no follow_up date, so nothing "
                "will ever bring it back up. A request without a follow-up date is a note, not "
                "a control.")

    out_units.sort(key=lambda x: (TRACK_ORDER.index(x["track"]), -x["finding_count"]))

    summary = {
        "findings_total": len(doc.get("findings", [])),
        "units_total": len(out_units),
        "units_by_track": {},
        "findings_by_track": {},
    }
    summary["units_by_state"] = {}
    for u in out_units:
        summary["units_by_track"][u["track"]] = summary["units_by_track"].get(u["track"], 0) + 1
        st = u.get("state", "ours")
        summary["units_by_state"][st] = summary["units_by_state"].get(st, 0) + 1
    for f in doc.get("findings", []):
        t = f.get("track")
        summary["findings_by_track"][t] = summary["findings_by_track"].get(t, 0) + 1

    out = {
        "schema": "quickbird.remediation-units/v1",
        "summary": summary,
        "units": out_units,
        "unplaced": unplaced,
    }
    text = json.dumps(out, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    print(f"remediation: {summary['findings_total']} finding(s) resolve through "
          f"{summary['units_total']} action(s) — "
          + ", ".join(f"{k} {v}" for k, v in sorted(summary["units_by_track"].items())),
          file=sys.stderr)
    if unplaced:
        print(f"::warning::{len(unplaced)} finding(s) could not be tied to an action and keep "
              f"their own deadline", file=sys.stderr)
    for u in out_units:
        if u.get("state") == "vendor-overdue":
            print(f"::error::{u['action'][:80]} — {u['state_detail']}", file=sys.stderr)
        elif u.get("state") in ("no-vendor-request", "vendor-request-undated"):
            print(f"::warning::{u['action'][:80]} — {u['state_detail']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
