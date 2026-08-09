#!/usr/bin/env python3
"""Apply the classification (WI-006-09-01: Classification of a finding, WI-006-09-01: Timeframes) to the findings in a BOM.

This is what makes the policy do something. Until now .soup-policy.yml validated its
deadlines and thresholds and nothing read them; this turns a vulnerability plus its CVSS,
KEV, EPSS and VEX into a track and two dated deadlines.

Deliberately a separate step from scanning and enrichment: the scan says what is there, the
enrichment says what is known about it, and this says what we have to do about it. Only the
last of the three is policy, and only the last one changes when the process changes.

Usage: classify-findings.py <bom.cdx.json> <effective-policy.json> [--state prior.json] [--out f]
"""

import argparse
import importlib.util
import json
import os
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


# KEV is its own track, not the top of the CVSS ladder. "Actively exploited" is a state of the
# world; "CVSS 9.8" is a property of the vulnerability, and the two deserve different clocks —
# measured on one backend product, 0 of 23 Critical findings were in KEV, so a shared 72h clock was
# being justified by a risk that was not present in any of them.
TRACK_ORDER = ["kev", "immediate", "expedited", "planned", "monitor"]
# Alert bands map onto tracks: KEV and Critical both alert at "critical".
BANDS = {"critical": 1, "high": 2, "medium": 3, "low": 4}


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
    """Return (track, rule, why). Rules are WI-006-09-01: Classification of a finding, first match wins."""
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
        return "kev", 1, "in the CISA KEV catalog — actively exploited"
    if kev == "unknown":
        return "kev", 1, "KEV membership could not be established — treated as KEV until it can"

    if cvss is None:
        # No parsable CVSS 3.x vector. Increasingly this means a CVSS 4.0-only advisory —
        # there is no v4 scorer here, but the database severity is a usable band, and
        # falling straight to rule 9 would put a v4 Critical three tracks too low.
        band = (p.get("quickbird:vuln:osv-severity") or "").strip().upper()
        if band == "CRITICAL":
            return "immediate", 2, "vendor severity Critical (no parsable CVSS 3.x vector)"
        if band == "HIGH":
            if epss is not None and epss >= hi:
                return "immediate", 3, f"vendor severity High with EPSS {epss} >= {hi}"
            return "expedited", 4, "vendor severity High (no parsable CVSS 3.x vector)"
        if band in ("MODERATE", "MEDIUM"):
            if epss is not None and epss >= el:
                return "expedited", 5, f"vendor severity Medium with EPSS {epss} >= {el}"
            return "planned", 6, "vendor severity Medium (no parsable CVSS 3.x vector)"
        if band == "LOW":
            if epss is not None and epss >= el:
                return "planned", 7, f"vendor severity Low with EPSS {epss} >= {el}"
            return "monitor", 8, "vendor severity Low (no parsable CVSS 3.x vector)"
        return "planned", 9, "no CVSS score available — an unknown is not a low"
    if cvss >= 9.0:
        return "immediate", 2, f"CVSS {cvss} (Critical)"
    if cvss >= 7.0:
        if epss is not None and epss >= hi:
            # A high EPSS is a strong signal but not an observation of exploitation, so this
            # escalates to Critical rather than into the KEV track.
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
    ap.add_argument("--windows", help="maintenance-windows.py output; without it, Track 3/4 "
                                      "remediation has no date and cannot breach")
    ap.add_argument("--annotate-bom", help="stamp the grq-4 contradiction back onto the assessed "
                                           "BOM. The bundle is the evidence, so a record whose "
                                           "snapshot no longer holds belongs in it — and the PDF "
                                           "renders only what the bundle says, by design")
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

    # Loaded rather than reimplemented: the window arithmetic decides a deadline, and two
    # copies of it would eventually disagree about which release a finding belongs to.
    windows = None
    if args.windows:
        try:
            windows = json.load(open(args.windows, encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"::error::could not read {args.windows}: {e}", file=sys.stderr)
            return 1
        spec = importlib.util.spec_from_file_location(
            "mw", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "maintenance-windows.py"))
        mw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mw)

    threshold = BANDS.get(str(policy.get("alerts", {}).get("threshold", "high")).lower(), 1)

    def _date(v):
        try:
            d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    onboarded = _date(policy.get("onboarded"))
    baseline_start = _date(policy.get("baseline_clocks_start"))
    if onboarded and not baseline_start:
        print("::warning::onboarded is set but baseline_clocks_start is not — every pre-existing "
              "finding will run from its first scan, which on a product with a backlog means the "
              "whole backlog is due at once", file=sys.stderr)
    findings, suppressed = [], []

    # --- SOUP records whose grq-4 snapshot no longer matches reality (WI-006-09: Observe) ------
    # grq-4 ("Does not contain major or critical security issues") is evaluated once, against
    # metadata.input_version, at approval time. A patch move inside the approved family keeps the
    # approval — correctly — but the vulnerability picture can change underneath it. Nothing
    # reconciled the two, so a record could keep asserting "no major or critical security issues"
    # while the monitor reported a Critical in the same component. An auditor holding both
    # documents side by side finds that in a minute.
    #
    # Keyed on the component, because that is the unit that gets re-checked. A library with 40
    # High findings is one record to look at, not 40 alerts — the same reason WI-006-09-01: What carries the timeframe attaches
    # deadlines to actions rather than findings.
    comp_by_ref = {}
    for c in bom.get("components", []) or []:
        comp_by_ref[c.get("bom-ref")] = c
    recheck = {}

    def note_contradiction(v, cvss, kev):
        """Record that a finding contradicts a grq-4 marked fulfilled."""
        for a in v.get("affects", []) or []:
            c = comp_by_ref.get(a.get("ref"))
            if not c:
                continue
            cp = props(c)
            if cp.get("quickbird:soup:req:grq-4:fulfilled") != "true":
                # Either there is no record, or grq-4 is already recorded as unfulfilled with a
                # stated reason. Neither is a contradiction.
                continue
            key = c.get("bom-ref")
            e = recheck.setdefault(key, {
                "component": c.get("name"),
                "version": c.get("version"),
                "record": cp.get("quickbird:soup:record", ""),
                "approved_family": cp.get("quickbird:soup:approved-family", ""),
                "approved_against_version": cp.get("quickbird:soup:checked-version", ""),
                "approval_state": cp.get("quickbird:soup:approved", ""),
                "grq4_claims": cp.get("quickbird:soup:req:grq-4:description", ""),
                "contradicted_by": [],
            })
            e["contradicted_by"].append({"id": v.get("id"), "cvss": cvss, "kev": kev})

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
            # WI-006-09-01: Classification of a finding — a track may only move up. EPSS is recomputed daily and decays; without
            # latching a Track 1 finding quietly becomes Track 2 a week later, its deadline
            # moves outward, and the audit trail shows a deadline that was never breached
            # because it kept receding.
            if TRACK_ORDER.index(was["track"]) < TRACK_ORDER.index(track):
                latched_from, track = track, was["track"]

        # The clock starts when we first saw it (WI-006-09-01: Timeframes), not at CVE publication. An escalation
        # restarts it from the date of escalation rather than retroactively.
        escalated = bool(was and was.get("track") != track and latched_from is None)
        first_seen = now if (not was or escalated) else datetime.fromisoformat(was["first_seen"])

        # --- onboarding baseline (WI-006-09-02: Onboarding) --------------------------------------
        # Starting every clock at first discovery is right for a product already under
        # monitoring, and wrong on the day monitoring begins: the whole accumulated backlog is
        # dated the same day. On one backend product that is 23 Critical findings with a 14-day
        # mitigation deadline and 288 more at 30 days, none of which anyone could have acted on
        # before there was a scan.
        #
        # So a product states an onboarding date and the date its baseline clocks start. Findings
        # already present at onboarding run from the later date; anything found afterwards runs
        # normally. KEV is exempt — active exploitation is not something a plan can defer, and
        # measured, 0 of those 23 Critical findings were in KEV, so the exemption costs nothing
        # here while keeping the one case that matters sharp.
        #
        # Absent a stated baseline date there is no baseline. A missing field must not become a
        # silent amnesty for a whole backlog.
        clock_start = first_seen
        baseline = False
        # Dates, not instants: `onboarded` parses to midnight, so a scan later the same day
        # had first_seen > onboarded and the whole backlog missed the baseline — on the one
        # day the baseline exists for.
        if track != "kev" and onboarded and baseline_start \
                and first_seen.date() <= onboarded.date():
            clock_start = baseline_start
            baseline = True

        td = policy["tracks"].get(track, {})
        out = {
            "id": vid,
            "track": track,
            "rule": rule,
            "why": why,
            "cvss": cvss_of(v),
            "epss": epss_of(v),
            "kev": props(v).get("quickbird:vuln:kev"),
            # Carried so the alert can say since when it has been exploited — the alert
            # composer read these fields before anything wrote them.
            "kev_date_added": props(v).get("quickbird:vuln:kev-date-added"),
            "kev_ransomware": props(v).get("quickbird:vuln:kev-ransomware") == "true",
            "first_seen": first_seen.isoformat(),
            "clock_start": clock_start.isoformat(),
            "affects": [a.get("ref") for a in (v.get("affects") or [])],
            "vex_state": (v.get("analysis") or {}).get("state"),
        }
        if baseline:
            out["baseline"] = {
                "onboarded": onboarded.date().isoformat(),
                "clocks_start": baseline_start.date().isoformat(),
                "why": ("present when monitoring began, so its deadlines run from the agreed "
                        "baseline date rather than from the first scan (WI-006-09-02: Onboarding). Recorded, not "
                        "waived — the finding keeps its track."),
            }
        if latched_from:
            out["latched"] = {"from": latched_from, "held_at": track,
                              "why": "a track may only move up (WI-006-09-01: Classification of a finding)"}
        if escalated and was:
            out["escalated_from"] = was.get("track")

        for clock in ("mitigation", "remediation"):
            spec = td.get(clock)
            delta = parse_duration(spec)
            if delta is None:
                out[f"{clock}_due"] = None
                out[f"{clock}_basis"] = spec or "not set"
                if spec == "next-release":
                    # WI-006-09-01: The maintenance window: the next maintenance window, not a date derived from an observed
                    # rhythm. Every open Track 3/4 finding lands on the same window, so a
                    # missed window is one breach about a release rather than one per finding.
                    if windows:
                        origin = mw.parse_ts(windows["grid_origin"])
                        iv = int(windows["interval_days"])
                        # Floor: a finding cannot be due for remediation before it is due for
                        # mitigation. Track 4 has no mitigation deadline and rides Track 3's.
                        mit = parse_duration(td.get("mitigation"))
                        floor_days = (mit.days if mit
                                      else mw.DEFAULT_MITIGATION_FLOOR_DAYS)
                        due = mw.window_for(clock_start, floor_days, origin, iv)
                        out[f"{clock}_due"] = due.isoformat()
                        out[f"{clock}_overdue"] = now > due
                        out[f"{clock}_basis"] = (
                            f"maintenance window {due.date().isoformat()} "
                            f"(every {iv}d, earliest window at least {floor_days}d after "
                            f"discovery)")
                    else:
                        out[f"{clock}_basis"] = (
                            "next regular release — NO DATE: no maintenance window was "
                            "supplied, so this clock cannot breach")
            else:
                due = clock_start + delta
                out[f"{clock}_due"] = due.isoformat()
                out[f"{clock}_overdue"] = now > due
                out[f"{clock}_basis"] = spec

        out["alerts"] = TRACK_ORDER.index(track) <= threshold
        findings.append(out)

        # Deliberately on severity, not on track. grq-4 says "major or critical", which is High
        # and Critical; the `expedited` track also holds Medium findings escalated by EPSS and
        # unscored ones, and pulling those in would blunt the signal. VEX-suppressed findings are
        # already excluded above — a justified not_affected means the component is not exposed, so
        # it does not contradict anything.
        _cvss = cvss_of(v)
        _kev = props(v).get("quickbird:vuln:kev") == "true"
        if _kev or (_cvss is not None and _cvss >= 7.0):
            note_contradiction(v, _cvss, _kev)

    for e in recheck.values():
        e["contradicted_by"].sort(key=lambda x: (not x["kev"], -(x["cvss"] or 0)))
        n = len(e["contradicted_by"])
        e["why"] = (
            f"grq-4 is recorded as fulfilled"
            + (f" against {e['approved_against_version']}" if e["approved_against_version"] else "")
            + f", but the version in this bundle ({e['version']}) has {n} finding(s) at High or "
              f"above that no VEX statement covers. The approval is not withdrawn by this — it "
              f"needs re-checking, which WI-006-03 treats as a review event."
            + (" Note the approval is itself temporary." if e["approval_state"] == "temporary" else ""))
    recheck_list = sorted(recheck.values(), key=lambda e: -len(e["contradicted_by"]))

    findings.sort(key=lambda f: (TRACK_ORDER.index(f["track"]), -(f["cvss"] or 0)))
    overdue = [f for f in findings
               if f.get("mitigation_overdue") or f.get("remediation_overdue")]

    doc = {
        "schema": "quickbird.classified-findings/v1",
        "classified_at": now.isoformat(),
        "product": policy.get("product"),
        # WI-006-09: Observe — records whose grq-4 snapshot no longer matches what the scan finds. Not an
        # incident and deliberately not in the alert: a review event.
        "soup_records_to_recheck": recheck_list,
        "baseline": ({"onboarded": onboarded.date().isoformat(),
                      "clocks_start": baseline_start.date().isoformat(),
                      "findings": sum(1 for f in findings if f.get("baseline")),
                      "kev_exempt": sum(1 for f in findings if f.get("track") == "kev")}
                     if onboarded and baseline_start else None),
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
            "soup_records_to_recheck": len(recheck_list),
        },
        "findings": findings,
        "suppressed": suppressed,
    }

    # Stamp the classification back into the bundle. Written in place so the PDF and any
    # other consumer see it without a second input file — the alternative was passing the
    # findings document to the renderer, which would break the property that the PDF is a
    # pure function of the bundle and therefore cannot drift from it. Annex B B.7 documents
    # these properties; until this block wrote them onto the vulnerabilities, only the
    # separate findings document carried them and a bundle reader saw a bare vector string.
    if args.annotate_bom:
        try:
            target = json.load(open(args.annotate_bom, encoding="utf-8"))
            by_id = {f["id"]: f for f in findings}
            for v in target.get("vulnerabilities", []) or []:
                f = by_id.get(v.get("id"))
                if not f:
                    continue
                extra = [
                    {"name": "quickbird:finding:track", "value": f["track"]},
                    {"name": "quickbird:finding:rule", "value": str(f["rule"])},
                    {"name": "quickbird:finding:why", "value": f["why"]},
                    {"name": "quickbird:finding:clock-start", "value": f["clock_start"]},
                ]
                if f.get("cvss") is not None:
                    extra.append({"name": "quickbird:finding:cvss", "value": str(f["cvss"])})
                if f.get("epss") is not None:
                    extra.append({"name": "quickbird:finding:epss", "value": str(f["epss"])})
                for clock in ("mitigation", "remediation"):
                    if f.get(f"{clock}_due"):
                        extra.append({"name": f"quickbird:finding:{clock}-due",
                                      "value": f[f"{clock}_due"]})
                    if f.get(f"{clock}_overdue"):
                        extra.append({"name": f"quickbird:finding:{clock}-overdue",
                                      "value": "true"})
                v["properties"] = sorted((v.get("properties") or []) + extra,
                                         key=lambda x: (x["name"], x.get("value") or ""))
            by_ref = {e_key: e for e_key, e in recheck.items()}
            for c in target.get("components", []) or []:
                e = by_ref.get(c.get("bom-ref"))
                if not e:
                    continue
                c["properties"] = sorted(
                    (c.get("properties") or []) + [
                        {"name": "quickbird:soup:recheck", "value": "grq-4"},
                        {"name": "quickbird:soup:recheck-findings",
                         "value": str(len(e["contradicted_by"]))},
                        {"name": "quickbird:soup:recheck-why", "value": e["why"]},
                    ],
                    key=lambda x: (x["name"], x.get("value") or ""))
            with open(args.annotate_bom, "w", encoding="utf-8") as fh:
                json.dump(target, fh, indent=2)
                fh.write("\n")
        except (OSError, json.JSONDecodeError) as e:
            print(f"::warning::could not annotate {args.annotate_bom}: {e}", file=sys.stderr)

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

    # One line per record, not per finding: the record is what gets re-checked.
    for e in recheck_list:
        print(f"::warning::SOUP record needs re-checking: {e['component']} {e['version']} — "
              f"grq-4 recorded as fulfilled"
              + (f" against {e['approved_against_version']}" if e["approved_against_version"] else "")
              + f", but {len(e['contradicted_by'])} finding(s) at High or above are open"
              + (f" (incl. KEV {e['contradicted_by'][0]['id']})"
                 if e["contradicted_by"] and e["contradicted_by"][0]["kev"] else "")
              + f". Record: {e['record'] or 'unknown'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
