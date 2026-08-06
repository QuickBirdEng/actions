#!/usr/bin/env python3
"""Render the release evidence bundle (CycloneDX) as a human-readable PDF.

The machine-readable bundle is the authoritative artifact; this is what a person reads —
a release reviewer, an auditor, a notified body, or a customer asking what is in the
product. It renders only what the bundle says, so the two cannot drift.

One deliberate choice runs through the layout: **what is missing is as prominent as what
is present.** The completeness marker and the named gaps are on page one, above the
component counts. A bundle that is 95% complete and silent about the other 5% is the
failure mode worth designing against — it looks exactly like a complete one.

reportlab, matching the existing generate-soup-pdf.py rather than introducing a second
PDF toolchain.

Usage: render-bundle-pdf.py <bundle.cdx.json> <out.pdf>
"""

import json
import os
import sys
from collections import Counter

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

GREY = colors.HexColor("#6b7280")
RED = colors.HexColor("#b91c1c")
AMBER = colors.HexColor("#b45309")
GREEN = colors.HexColor("#15803d")
LINE = colors.HexColor("#d1d5db")
HEADBG = colors.HexColor("#f3f4f6")


def props(obj):
    return {p["name"]: p["value"] for p in obj.get("properties", []) or []}


def prop_all(obj, name):
    return [p["value"] for p in obj.get("properties", []) or [] if p["name"] == name]


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if s is not None else "")


def build(bundle, out_path):
    meta = bundle.get("metadata", {})
    subject = meta.get("component", {}) or {}
    mprops = props(meta)
    components = bundle.get("components", []) or []
    vulns = bundle.get("vulnerabilities", []) or []

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=20, spaceAfter=2)
    sub = ParagraphStyle("sub", parent=styles["Normal"], fontSize=11, textColor=GREY,
                         spaceAfter=14)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceBefore=14,
                        spaceAfter=6)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=7.5, leading=9.5)
    cell = ParagraphStyle("cell", parent=styles["Normal"], fontSize=7.5, leading=9.5)

    doc = SimpleDocTemplate(out_path, pagesize=A4, leftMargin=18 * mm,
                            rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"SBOM — {subject.get('name','')} {subject.get('version','')}")
    el = []

    def table(data, widths, align_left_cols=()):
        t = Table(data, colWidths=widths, repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), HEADBG),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.25, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        t.setStyle(TableStyle(style))
        return t

    # ---------------------------------------------------------------- cover
    el.append(Paragraph(f"Software Bill of Materials", h1))
    el.append(Paragraph(
        f"{esc(subject.get('name','—'))} &nbsp;·&nbsp; version {esc(subject.get('version','—'))}",
        sub))

    complete = mprops.get("quickbird:sbom:complete")
    gaps = prop_all(meta, "quickbird:sbom:missing")
    tier = mprops.get("quickbird:sbom:tier", "unmarked")

    # Before anything else. Every tier renders identically, so the only thing separating a build
    # that runs in production from one that never shipped is saying which this is, first and
    # unmissably.
    if tier == "candidate":
        el.append(Paragraph(
            f'<b>Built from tag {esc(subject.get("version","?"))}.</b> Whether this version is '
            f'the one running in production is <b>not</b> stated here and cannot be: in this '
            f'pipeline a tag build deploys to staging, and production is a separate, later step. '
            f'The deployment history is what records which version went live — this document '
            f'records what that version contains. Use it as release evidence only for a version '
            f'the deployment history shows was deployed.', body))
        el.append(Spacer(1, 8))
    elif tier != "release":
        el.append(Paragraph(
            f'<font color="#b91c1c"><b>Not release evidence — this is a '
            f'{esc(tier)} build.</b></font> Produced for inspection and for comparing '
            f'component sets between builds. It describes a build that was not released, so '
            f'it is not a controlled record and must not be supplied to a customer, an '
            f'auditor or a notified body.', body))
        el.append(Spacer(1, 8))

    # Completeness first, before anything reassuring.
    if complete == "false":
        el.append(Paragraph(
            f'<font color="#b45309"><b>This bill of materials is incomplete.</b></font> '
            f'{len(gaps)} in-scope component(s) could not be scanned and are listed below. '
            f'Everything else in this document is complete for the components that were scanned.',
            body))
        el.append(Spacer(1, 4))
        el.append(table(
            [["Not covered by this document", "why it matters"]] +
            [[Paragraph(esc(g), cell),
              Paragraph("no component data — vulnerabilities in it are not represented here", cell)]
             for g in gaps],
            [70 * mm, 100 * mm]))
    elif complete == "true":
        el.append(Paragraph(
            '<font color="#15803d"><b>Complete.</b></font> Every in-scope component was scanned.',
            body))
    else:
        el.append(Paragraph(
            '<font color="#b91c1c"><b>Completeness not stated.</b></font> This document does '
            'not record whether every in-scope component was scanned, so it cannot be relied '
            'on as a full inventory.', body))

    el.append(Spacer(1, 10))

    kev_cat = mprops.get("quickbird:vuln:kev-catalog-version", "not recorded")
    epss_mv = mprops.get("quickbird:vuln:epss-model-version", "not recorded")
    epss_sd = mprops.get("quickbird:vuln:epss-score-date", "not recorded")
    stale = mprops.get("quickbird:vuln:enrichment-stale")

    el.append(Paragraph("Provenance", h2))
    prov = [
        ["Field", "Value"],
        ["Format", f"CycloneDX {bundle.get('specVersion','?')}"],
        ["Generated", meta.get("timestamp", "not recorded (comparable tier)")],
        ["Components", str(len(components))],
        ["Scanned targets", mprops.get("quickbird:sbom:artifact-count", "—")],
        ["CISA KEV catalog", kev_cat],
        ["EPSS model / score date", f"{epss_mv} / {epss_sd}"],
    ]
    if stale == "true":
        prov.append(["Feed status", "STALE — at least one feed came from cache"])
    el.append(table([[Paragraph(esc(a), cell), Paragraph(esc(b), cell)] for a, b in prov],
                    [55 * mm, 115 * mm]))
    el.append(Spacer(1, 4))
    el.append(Paragraph(
        "The KEV catalog version and the EPSS model version are recorded because neither is "
        "reconstructable later: CISA publishes only the current catalog, and EPSS scores are "
        "not comparable across model versions.", small))

    # ------------------------------------------------------- inventory summary
    el.append(Paragraph("Inventory", h2))
    eco = Counter()
    for c in components:
        purl = c.get("purl") or ""
        eco[purl.split("/")[0].replace("pkg:", "") if purl.startswith("pkg:") else "other"] += 1
    rows = [["Ecosystem", "Components"]] + [[k, str(v)] for k, v in sorted(eco.items())]
    with_lic = sum(1 for c in components if c.get("licenses"))
    with_hash = sum(1 for c in components if c.get("hashes"))
    el.append(table([[Paragraph(esc(a), cell), Paragraph(esc(b), cell)] for a, b in rows],
                    [55 * mm, 115 * mm]))
    el.append(Spacer(1, 4))
    el.append(Paragraph(
        f"{with_lic} of {len(components)} components carry a license, {with_hash} a hash. "
        f"Undetermined licenses and missing hashes are stated rather than inferred — container "
        f"OS packages generally carry neither.", small))

    # --------------------------------------------------------- SOUP assessment
    assessed = [c for c in components if props(c).get("quickbird:soup:record")]
    el.append(PageBreak())
    el.append(Paragraph("SOUP assessment", h2))
    if not assessed:
        el.append(Paragraph(
            "No component in this bundle carries a SOUP assessment record. The inventory is "
            "present but the evaluation is not — this document is not sufficient as a SOUP "
            "evaluation report in that state.", body))
    else:
        el.append(Paragraph(
            f"{len(assessed)} of {len(components)} components carry a SOUP record. The "
            f"remainder are transitive dependencies, which are in scope for vulnerability "
            f"monitoring but are not separately approved.", small))
        el.append(Spacer(1, 6))
        rows = [["Component", "Version", "Approved for", "Approver / date", "Requirements"]]
        for c in sorted(assessed, key=lambda x: (x.get("name") or "").lower()):
            p = props(c)
            reqs = {k: v for k, v in p.items()
                    if k.startswith("quickbird:soup:req:") and k.endswith(":fulfilled")}
            met = sum(1 for v in reqs.values() if v == "true")
            unmet = [k.split(":")[3] for k, v in reqs.items() if v != "true"]
            ann = (c.get("annotations") or [{}])[0]
            who = ann.get("annotator", {}).get("individual", {}).get("name", "—")
            when = (ann.get("timestamp") or "")[:10]
            reqtxt = f"{met}/{len(reqs)} met"
            if unmet:
                reqtxt += f'<br/><font color="#b45309">open: {esc(", ".join(sorted(unmet)))}</font>'
            # A requirement recorded as met that today's scan contradicts. Shown in the same cell
            # as the requirement count, because the reader needs both facts together: what the
            # record asserts and what holds now. Otherwise this is precisely the discrepancy an
            # auditor assembles by hand from two documents.
            if p.get("quickbird:soup:recheck") == "grq-4":
                n = p.get("quickbird:soup:recheck-findings", "?")
                reqtxt += (f'<br/><font color="#b45309"><b>grq-4 recorded met, but {esc(n)} '
                           f'High+ finding(s) open today — re-check</b></font>')
            # A temporary approval is a provisional decision: an approver signed off an
            # unfulfilled requirement on a branch, with a recorded reason. Rendering it the same
            # as a full approval would put a provisional sign-off into the document an auditor
            # reads as though it were settled — which is the one thing this table must not do.
            approved = p.get("quickbird:soup:approved", "")
            if who == "—":
                whotxt = '<font color="#b91c1c">not approved</font>'
            elif approved == "temporary":
                why = p.get("quickbird:soup:approval-temporary-reason", "no reason recorded")
                whotxt = (f'<font color="#b45309"><b>TEMPORARY</b></font><br/>{esc(who)}'
                          f'<br/>{esc(when)}<br/><font size="6">{esc(why[:90])}</font>')
            else:
                whotxt = f"{esc(who)}<br/>{esc(when)}"
            rows.append([
                Paragraph(esc(c.get("name")), cell),
                Paragraph(esc(c.get("version")), cell),
                Paragraph(esc(p.get("quickbird:soup:approved-family", "—")), cell),
                Paragraph(whotxt, cell),
                Paragraph(reqtxt, cell),
            ])
        el.append(table(rows, [45 * mm, 22 * mm, 25 * mm, 38 * mm, 40 * mm]))

    mismatches = prop_all(meta, "quickbird:soup:record-version-mismatch")
    if mismatches:
        el.append(Spacer(1, 6))
        el.append(Paragraph(
            f'<font color="#b91c1c"><b>{len(mismatches)} SOUP approval(s) do not cover the '
            f'shipped version.</b></font> The component ships now, under an approval that '
            f'applies to a different version family — a review event per WI §7 #4:', body))
        for m in mismatches:
            el.append(Paragraph(f'&bull; {esc(m)}', small))

    orphans = prop_all(meta, "quickbird:soup:orphaned-record")
    if orphans:
        el.append(Spacer(1, 6))
        el.append(Paragraph(
            f'<font color="#b45309"><b>{len(orphans)} SOUP record(s) match no component '
            f'in this build.</b></font> The SOUP list and the shipped software disagree: '
            f'{esc(", ".join(orphans))}.', body))

    # -------------------------------------------------------- vulnerabilities
    el.append(PageBreak())
    el.append(Paragraph("Vulnerabilities", h2))
    if not vulns:
        el.append(Paragraph("No known vulnerabilities were reported for the components in "
                            "this bundle at the time of generation.", body))
    else:
        kev = [v for v in vulns if props(v).get("quickbird:vuln:kev") == "true"]
        unknown_kev = [v for v in vulns if props(v).get("quickbird:vuln:kev") == "unknown"]
        analysed = [v for v in vulns if v.get("analysis")]
        not_affected = [v for v in vulns if (v.get("analysis") or {}).get("state") == "not_affected"]

        el.append(Paragraph(
            f"{len(vulns)} known vulnerabilities. {len(kev)} in the CISA KEV catalog "
            f"(actively exploited). {len(analysed)} carry a VEX assessment, of which "
            f"{len(not_affected)} are assessed as not affecting this product. "
            f"{len(vulns) - len(analysed)} have no assessment yet.", body))
        if unknown_kev:
            el.append(Paragraph(
                f'<font color="#b91c1c">KEV membership could not be established for '
                f'{len(unknown_kev)} of them — the catalog was unreachable. Absence of a KEV '
                f'flag on those is not evidence that they are not exploited.</font>', small))
        el.append(Spacer(1, 6))

        def vrow(v):
            p = props(v)
            cvss = next((r.get("vector") or str(r.get("score", ""))
                         for r in v.get("ratings", []) if r.get("source", {}).get("name") != "EPSS"), "—")
            epss = next((r.get("score") for r in v.get("ratings", [])
                         if r.get("source", {}).get("name") == "EPSS"), None)
            an = v.get("analysis") or {}
            state = an.get("state", "")
            if state == "not_affected":
                st = f'<font color="#15803d">not affected</font><br/>{esc(an.get("justification",""))}'
            elif state:
                st = esc(state)
            else:
                st = '<font color="#b45309">no assessment</font>'
            flags = []
            if p.get("quickbird:vuln:kev") == "true":
                flags.append('<font color="#b91c1c"><b>KEV</b></font>')
            if p.get("quickbird:vuln:kev") == "unknown":
                flags.append('<font color="#b91c1c">KEV?</font>')
            if epss is not None:
                flags.append(f"EPSS {epss:.2f}")
            return [
                Paragraph(esc(v.get("id")), cell),
                Paragraph(esc(cvss)[:40], cell),
                Paragraph("<br/>".join(flags) or "—", cell),
                Paragraph(st, cell),
                Paragraph(str(len(v.get("affects", []) or [])), cell),
            ]

        # KEV and unassessed first — those are the ones that need action.
        priority = [v for v in vulns
                    if props(v).get("quickbird:vuln:kev") in ("true", "unknown")
                    or not v.get("analysis")]
        rest = [v for v in vulns if v not in priority]
        shown = priority[:120]
        rows = [["CVE", "CVSS vector", "Signals", "Assessment", "Affects"]]
        rows += [vrow(v) for v in sorted(shown, key=lambda x: x.get("id", ""))]
        el.append(table(rows, [30 * mm, 52 * mm, 22 * mm, 46 * mm, 20 * mm]))
        if len(priority) > len(shown):
            el.append(Paragraph(
                f"… and {len(priority)-len(shown)} further vulnerabilities needing attention. "
                f"The complete list is in the machine-readable bundle; this table is truncated "
                f"for readability, not because the rest were assessed.", small))
        if rest:
            el.append(Spacer(1, 4))
            el.append(Paragraph(
                f"{len(rest)} further vulnerabilities carry an assessment and are not in the "
                f"KEV catalog. They are in the machine-readable bundle.", small))

    # ------------------------------------------------------ full inventory
    el.append(PageBreak())
    el.append(Paragraph("Complete component inventory", h2))
    el.append(Paragraph(
        f"All {len(components)} components, as recorded in the bundle.", small))
    el.append(Spacer(1, 6))
    rows = [["Component", "Version", "License", "Identifier"]]
    for c in sorted(components, key=lambda x: ((x.get("name") or "").lower(),
                                               x.get("version") or "")):
        lic = c.get("licenses") or []
        lictxt = ", ".join(
            (l.get("license", {}).get("id") or l.get("license", {}).get("name")
             or l.get("expression") or "") for l in lic) or "—"
        rows.append([
            Paragraph(esc(c.get("name")), cell),
            Paragraph(esc(c.get("version")), cell),
            Paragraph(esc(lictxt)[:40], cell),
            Paragraph(esc(c.get("purl") or c.get("cpe") or "—")[:60], small),
        ])
    el.append(table(rows, [45 * mm, 25 * mm, 32 * mm, 68 * mm]))

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GREY)
        canvas.drawString(18 * mm, 10 * mm,
                          f"{subject.get('name','')} {subject.get('version','')} — "
                          f"generated from the CycloneDX bundle; the bundle is authoritative")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(el, onFirstPage=footer, onLaterPages=footer)


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: render-bundle-pdf.py <bundle.cdx.json> <out.pdf>")
    src, out = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        bundle = json.load(f)
    if bundle.get("bomFormat") != "CycloneDX":
        sys.exit(f"::error::{src} is not a CycloneDX document")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    build(bundle, out)
    print(f"wrote {out} ({os.path.getsize(out)} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
