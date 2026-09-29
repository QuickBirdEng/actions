#!/usr/bin/env python3
"""The headline numbers of an assessed BOM — the five tiles at the top of the VDR.

Extracted so the Slack summary and the document cannot disagree. render-vdr-pdf.py imports
`summary()` for its own tiles, and the monitor calls this file as a script: it needs the
numbers on a runner that has no reportlab, and installing a PDF library to count findings
would be the wrong trade.

Usage: summarise-bom.py <assessed.cdx.json> [--units units.json] [--out f]
"""

import argparse
import json
import re
import sys


def props(obj):
    return {p["name"]: p["value"] for p in (obj.get("properties") or [])}


def _one_per_library(entries):
    """Collapse the copies of one library into one row.

    A Dockerfile candidate is scanned as the image it produces, so the same library is found
    once per image containing it and once in the lockfile declaring it. Counting the copies
    would inflate every currency number by the number of artefacts.
    """
    seen = set()
    n = 0
    for c, p in entries:
        key = c.get("purl") or (c.get("name"), c.get("version"))
        if key in seen:
            continue
        seen.add(key)
        n += 1
    return n


def summary(bundle, units=None):
    components = bundle.get("components") or []
    vulns = bundle.get("vulnerabilities") or []

    cur = []
    for c in components:
        p = props(c)
        st = p.get("quickbird:currency:status")
        if st:
            cur.append((c, p, st))
    beyond = _one_per_library([(c, p) for c, p, st in cur
                              if st in ("behind", "stale-and-behind")])
    stale = _one_per_library([(c, p) for c, p, st in cur if st == "stale"])
    deprecated = _one_per_library([(c, p) for c, p, st in cur if st == "deprecated"])
    # Exempt by the process (a publisher on the staleness allow-list) stays listed in the
    # document but is not a number anyone has to act on.
    exempt = _one_per_library([(c, p) for c, p, st in cur
                               if st == "stale" and p.get("quickbird:currency:stale-exempt")])

    def cvss_of(v):
        try:
            return float(props(v).get("quickbird:finding:cvss", ""))
        except ValueError:
            return None

    scored = [cvss_of(v) for v in vulns if "quickbird:finding:track" in props(v)]
    return {
        "beyond_limit": beyond,
        "critical": sum(1 for x in scored if x is not None and x >= 9),
        "high": sum(1 for x in scored if x is not None and 7 <= x < 9),
        "stale": stale + deprecated - exempt,
        "kev": sum(1 for v in vulns if props(v).get("quickbird:vuln:kev") == "true"),
        "overdue": sum(1 for v in vulns for k in ("mitigation", "remediation")
                       if props(v).get(f"quickbird:finding:{k}-overdue") == "true"),
        "findings": len(scored),
        "actions": ((units or {}).get("summary") or {}).get("units_total"),
    }


def render(s, label=""):
    """One Slack line. The same four tiles the report leads with, in the same order."""
    head = f"*{label}*  " if label else ""
    kev = f"{s['kev']} / {s['overdue']}"
    return (f"{head}"
            f"*{s['beyond_limit']}* beyond update limit  ·  "
            f"*{s['critical']} / {s['high']}* Critical / High  ·  "
            f"*{s['stale']}* stale  ·  "
            f"*{kev}* KEV / overdue")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--units")
    ap.add_argument("--out", default="-")
    ap.add_argument("--render", metavar="LABEL", nargs="?", const="",
                    help="print the Slack line instead of JSON")
    args = ap.parse_args()

    bundle = json.load(open(args.bundle, encoding="utf-8"))
    units = json.load(open(args.units, encoding="utf-8")) if args.units else None
    s = summary(bundle, units)

    text = render(s, args.render) if args.render is not None else json.dumps(s, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
