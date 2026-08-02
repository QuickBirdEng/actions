#!/usr/bin/env python3
"""Apply the classification (§2.1, §3) to the findings in a BOM.

This is what makes the policy do something. Until now .soup-policy.yml validated its
deadlines and thresholds and nothing read them; this turns a vulnerability plus its CVSS,
KEV, EPSS and VEX into a track and two dated deadlines.

Deliberately a separate step from scanning and enrichment: the scan says what is there, the
enrichment says what is known about it, and this says what we have to do about it. Only the
last of the three is policy, and only the last one changes when the process changes.

Usage: classify-findings.py <bom.cdx.json> <effective-policy.json> [--state prior.json] [--out f]
"""

import argparse
import json
import math
import sys
from datetime import datetime, timedelta, timezone

# --- CVSS 3.1 ---------------------------------------------------------------
# Implemented from the specification rather than reused from action-scripts/
# cvss-3-1-severity.sh, which diverges in two ways: it omits the scope-changed impact
# correction (the -0.029 offset and the -3.25*(ISC-0.02)^15 term) and it does not apply
# Roundup, which the spec requires to round *up* to one decimal. The effect is small per
# vector but systematic and always downward: 164 of the 2592 possible base vectors land in
# a lower severity band, e.g. AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L is 7.0 (High) and reads
# there as 6.92 (Medium). At a band boundary that is a different track and a different
# deadline, so the two must not disagree.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"H": 0.44, "L": 0.77}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_IMP = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS 3.1 Roundup: to one decimal, always upward."""
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31_base(vector: str):
    """Base score from a CVSS:3.1 vector, or None if it cannot be parsed."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
        scope = m["S"]
        av, ac = _AV[m["AV"]], _AC[m["AC"]]
        pr = (_PR_U if scope == "U" else _PR_C)[m["PR"]]
        ui = _UI[m["UI"]]
        c, i, a = _IMP[m["C"]], _IMP[m["I"]], _IMP[m["A"]]
    except (KeyError, ValueError):
        return None

    isc = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = 6.42 * isc if scope == "U" else 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    raw = (impact + expl) if scope == "U" else 1.08 * (impact + expl)
    return _roundup(min(10.0, raw))


# --- helpers ----------------------------------------------------------------
def props(o):
    return {p["name"]: p["value"] for p in (o.get("properties") or [])}


def parse_duration(s):
    """'72h' -> timedelta; 'none'/'next-release'/None -> None (not a fixed deadline)."""
    if not s or s in ("none", "next-release"):
        return None
    try:
        if s.endswith("h"):
            return timedelta(hours=int(s[:-1]))
        if s.endswith("d"):
            return timedelta(days=int(s[:-1]))
    except ValueError:
        pass
    return None


TRACK_ORDER = ["immediate", "expedited", "planned", "monitor"]
BANDS = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def cvss_of(v):
    """Highest CVSS base score across the vulnerability's non-EPSS ratings."""
    best = None
    for r in v.get("ratings", []) or []:
        if (r.get("source") or {}).get("name") == "EPSS":
            continue
        s = cvss31_base(r.get("vector") or "")
        if s is None and isinstance(r.get("score"), (int, float)):
            s = float(r["score"])
        if s is not None and (best is None or s > best):
            best = s
    return best


def epss_of(v):
    for r in v.get("ratings", []) or []:
        if (r.get("source") or {}).get("name") == "EPSS":
            return r.get("score")
    return None


def classify(v, policy):
    """Return (track, rule, why). Rules are §2.1, first match wins."""
    p = props(v)
    kev = p.get("quickbird:vuln:kev")
    analysis = v.get("analysis") or {}
    cvss = cvss_of(v)
    epss = epss_of(v)
    hi = policy["epss"]["high"]
    el = policy["epss"]["elevated"]

    if analysis.get("state") == "not_affected" and analysis.get("justification"):
        return None, 0, "VEX not_affected with a justification — not applicable"

    # KEV overrides CVSS upward and is unconditional. "unknown" is not "no": a catalog we
    # could not read must not silently downgrade a finding, so it is treated as KEV for
    # classification and flagged, rather than assumed benign.
    if kev == "true":
        return "immediate", 1, "in the CISA KEV catalog — actively exploited"
    if kev == "unknown":
        return "immediate", 1, "KEV membership could not be established — treated as KEV until it can"

    if cvss is None:
        return "expedited", 9, "no CVSS score available — an unknown is not a low"
    if cvss >= 9.0:
        return "immediate", 2, f"CVSS {cvss} (Critical)"
    if cvss >= 7.0:
        if epss is not None and epss >= hi:
            return "immediate", 3, f"CVSS {cvss} (High) with EPSS {epss} >= {hi}"
        return "expedited", 4, f"CVSS {cvss} (High)"
    if cvss >= 4.0:
        if epss is not None and epss >= el:
            return "expedited", 5, f"CVSS {cvss} (Medium) with EPSS {epss} >= {el}"
        return "planned", 6, f"CVSS {cvss} (Medium)"
    if cvss > 0:
        if epss is not None and epss >= el:
            return "planned", 7, f"CVSS {cvss} (Low) with EPSS {epss} >= {el}"
        return "monitor", 8, f"CVSS {cvss} (Low)"
    return "monitor", 8, "CVSS 0.0"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bom")
    ap.add_argument("policy")
    ap.add_argument("--state", help="previous run, for latching and clock starts")
    ap.add_argument("--out", default="-")
    ap.add_argument("--now", help="ISO timestamp, for reproducible tests")
    args = ap.parse_args()

    bom = json.load(open(args.bom, encoding="utf-8"))
    policy = json.load(open(args.policy, encoding="utf-8"))
    prior = {}
    if args.state:
        try:
            prior = {f["id"]: f for f in json.load(open(args.state, encoding="utf-8"))["findings"]}
        except (OSError, KeyError, json.JSONDecodeError):
            print(f"::warning::could not read prior state {args.state} — "
                  f"no latching and every clock restarts today", file=sys.stderr)

    now = datetime.fromisoformat(args.now) if args.now else datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    threshold = BANDS.get(str(policy.get("alerts", {}).get("threshold", "high")).lower(), 1)
    findings, suppressed = [], []

    for v in bom.get("vulnerabilities", []) or []:
        track, rule, why = classify(v, policy)
        vid = v.get("id")
        if track is None:
            suppressed.append({"id": vid, "why": why,
                               "justification": (v.get("analysis") or {}).get("justification")})
            continue

        was = prior.get(vid)
        latched_from = None
        if was and was.get("track") in TRACK_ORDER:
            # §2.2 — a track may only move up. EPSS is recomputed daily and decays; without
            # latching a Track 1 finding quietly becomes Track 2 a week later, its deadline
            # moves outward, and the audit trail shows a deadline that was never breached
            # because it kept receding.
            if TRACK_ORDER.index(was["track"]) < TRACK_ORDER.index(track):
                latched_from, track = track, was["track"]

        # The clock starts when we first saw it (§3), not at CVE publication. An escalation
        # restarts it from the date of escalation rather than retroactively.
        escalated = bool(was and was.get("track") != track and latched_from is None)
        first_seen = now if (not was or escalated) else datetime.fromisoformat(was["first_seen"])

        td = policy["tracks"].get(track, {})
        out = {
            "id": vid,
            "track": track,
            "rule": rule,
            "why": why,
            "cvss": cvss_of(v),
            "epss": epss_of(v),
            "kev": props(v).get("quickbird:vuln:kev"),
            "first_seen": first_seen.isoformat(),
            "affects": [a.get("ref") for a in (v.get("affects") or [])],
            "vex_state": (v.get("analysis") or {}).get("state"),
        }
        if latched_from:
            out["latched"] = {"from": latched_from, "held_at": track,
                              "why": "a track may only move up (§2.2)"}
        if escalated and was:
            out["escalated_from"] = was.get("track")

        for clock in ("mitigation", "remediation"):
            spec = td.get(clock)
            delta = parse_duration(spec)
            if delta is None:
                out[f"{clock}_due"] = None
                out[f"{clock}_basis"] = spec or "not set"
                if spec == "next-release":
                    out[f"{clock}_basis"] = (
                        f"next regular release (cadence: {policy.get('release_cadence','undeclared')}, "
                        f"ceiling {policy.get('planned_remediation_ceiling','none')})")
            else:
                due = first_seen + delta
                out[f"{clock}_due"] = due.isoformat()
                out[f"{clock}_overdue"] = now > due
                out[f"{clock}_basis"] = spec

        out["alerts"] = TRACK_ORDER.index(track) <= threshold
        findings.append(out)

    findings.sort(key=lambda f: (TRACK_ORDER.index(f["track"]), -(f["cvss"] or 0)))
    overdue = [f for f in findings
               if f.get("mitigation_overdue") or f.get("remediation_overdue")]

    doc = {
        "schema": "quickbird.classified-findings/v1",
        "classified_at": now.isoformat(),
        "product": policy.get("product"),
        "policy": {
            "process_version": policy.get("process_version"),
            "epss": policy["epss"],
            "tracks": policy["tracks"],
            "alert_threshold": policy.get("alerts", {}).get("threshold"),
        },
        "summary": {
            "total": len(findings),
            "by_track": {t: sum(1 for f in findings if f["track"] == t) for t in TRACK_ORDER},
            "suppressed_by_vex": len(suppressed),
            "alerting": sum(1 for f in findings if f["alerts"]),
            "overdue": len(overdue),
            "latched": sum(1 for f in findings if "latched" in f),
        },
        "findings": findings,
        "suppressed": suppressed,
    }

    out = json.dumps(doc, indent=2)
    if args.out == "-":
        print(out)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")

    s = doc["summary"]
    print(f"classified {s['total']} findings: "
          + ", ".join(f"{t} {s['by_track'][t]}" for t in TRACK_ORDER)
          + f" · {s['suppressed_by_vex']} VEX-suppressed · {s['alerting']} alerting"
          + f" · {s['overdue']} overdue · {s['latched']} latched", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
