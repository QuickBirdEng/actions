#!/usr/bin/env python3
"""Render the SBOM report — composition only, one per release.

Document 1 of the two-report split. Everything time-dependent (vulnerabilities,
classification, deadlines, latest versions) belongs to the Dependency & Vulnerability
Report; this document states what the build is made of, and nothing that ages:

    1  Direct dependencies      the deliberate choices, with supplier/licence and record
    2  Transitive and OS        aggregate by ecosystem — itemised in the bundle
    3  Scanned artefacts        each source with its identity (digest, build date)

Reads the assessed bundle (it is a superset of the pure inventory) but renders only the
static facts from it.

Usage: render-sbom-pdf.py <bundle.cdx.json> <out.pdf>
"""

import hashlib
import json
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, PageTemplate, Paragraph,
                                Spacer, Table, TableStyle)

INK = colors.HexColor("#16181d")
MUTED = colors.HexColor("#5b6472")
LINE = colors.HexColor("#d8dce3")
ACCENT = colors.HexColor("#1f4e79")
BOX = colors.HexColor("#f6f7f9")
WARN = colors.HexColor("#b45309")
BAD = colors.HexColor("#b91c1c")
GOOD = colors.HexColor("#15803d")

body = ParagraphStyle("body", fontName="Helvetica", fontSize=8.5, leading=12, textColor=INK)
small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=10, textColor=MUTED)
cell = ParagraphStyle("cell", parent=body, fontSize=7.5, leading=10)
h1 = ParagraphStyle("h1", parent=body, fontSize=15, leading=19, fontName="Helvetica-Bold")
h2 = ParagraphStyle("h2", parent=body, fontSize=10.5, leading=14, fontName="Helvetica-Bold",
                    textColor=ACCENT, spaceBefore=14, spaceAfter=4)


def props(obj):
    return {p["name"]: p["value"] for p in (obj.get("properties") or [])}


def esc(s):
    return (str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def table(data, widths, style_extra=()):
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("BACKGROUND", (0, 0), (-1, 0), BOX),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        *style_extra,
    ]))
    return t


def license_of(c):
    for entry in (c.get("licenses") or []):
        lic = entry.get("license") or {}
        if lic.get("id") or lic.get("name"):
            return lic.get("id") or lic.get("name")
    return None


def build(bundle, bundle_path, out_path):
    meta = bundle.get("metadata") or {}
    mp = props(meta)
    root = meta.get("component") or {}
    components = bundle.get("components") or []

    sha = hashlib.sha256(open(bundle_path, "rb").read()).hexdigest()
    tier = mp.get("quickbird:sbom:tier", "unmarked").upper()
    complete = mp.get("quickbird:sbom:complete", "?")
    gaps = [p["value"] for p in (meta.get("properties") or [])
            if p["name"] == "quickbird:sbom:missing"]
    syft_v = next((t.get("version") for t in ((meta.get("tools") or {}).get("components") or [])
                   if t.get("name") == "syft"), "?")
    generated = meta.get("timestamp") or "deterministic build (no timestamp)"

    artifacts = [c for c in components
                 if str(c.get("bom-ref", "")).startswith("quickbird:artifact:")]
    direct = [c for c in components
              if props(c).get("quickbird:dependency:scope") == "direct"
              or (props(c).get("quickbird:soup:record")
                  and props(c).get("quickbird:dependency:scope") != "dev")]
    direct = list({c.get("bom-ref"): c for c in direct}.values())
    direct_refs = {c.get("bom-ref") for c in direct}
    rest = [c for c in components
            if c.get("bom-ref") not in direct_refs and c not in artifacts]

    # approver per component, from the approval annotations
    approver = {}
    for a in (bundle.get("annotations") or []):
        for subj in a.get("subjects") or []:
            who = ((a.get("annotator") or {}).get("individual") or {}).get("name")
            approver[subj] = (who, (a.get("timestamp") or "")[:10])
    for c in components:
        for a in (c.get("annotations") or []):
            who = ((a.get("annotator") or {}).get("individual") or {}).get("name")
            approver[c.get("bom-ref")] = (who, (a.get("timestamp") or "")[:10])

    el = []
    el.append(Paragraph(
        f"Software Bill of Materials — {esc(root.get('name'))} "
        f"<font face='Courier'>{esc(root.get('version'))}</font>", h1))
    el.append(Paragraph("Component inventory of this build · Record per WI-0XX-01, stage #3",
                        small))
    el.append(Spacer(1, 4))
    tier_col = {"CANDIDATE": ACCENT, "STAGING": MUTED, "BRANCH": WARN}.get(tier, MUTED)
    comp_txt = ('<font color="#15803d"><b>COMPLETE</b></font>' if complete == "true"
                else f'<font color="#b91c1c"><b>INCOMPLETE — {len(gaps)} gap(s)</b></font>')
    el.append(Paragraph(
        f'<font color="{tier_col.hexval() if hasattr(tier_col, "hexval") else "#5b6472"}">'
        f'<b>{esc(tier)}</b></font> &nbsp;·&nbsp; {comp_txt}', body))
    el.append(Spacer(1, 6))
    el.append(table([[Paragraph(
        f"<b>Producer</b> QuickBird GmbH &nbsp;·&nbsp; "
        f"<b>Generation tool</b> soup-discovery / syft {esc(syft_v)} &nbsp;·&nbsp; "
        f"<b>Format</b> CycloneDX {esc(bundle.get('specVersion'))} &nbsp;·&nbsp; "
        f"<b>Lifecycle</b> post-build<br/>"
        f"<b>Generated</b> {esc(generated)} &nbsp;·&nbsp; "
        f"<b>Document SHA-256</b> <font face='Courier'>{sha[:16]}…</font> &nbsp;·&nbsp; "
        f"<b>Components</b> {len(components) - len(artifacts)} ({len(direct)} direct) "
        f"from {len(artifacts)} artefacts", small)]],
        [170 * mm], (("BACKGROUND", (0, 0), (-1, -1), BOX),)))

    if gaps:
        el.append(Spacer(1, 6))
        el.append(Paragraph(
            f'<font color="#b91c1c"><b>Gaps:</b></font> the following in-scope artefacts '
            f'could not be scanned and are not contained in this inventory: '
            f'{esc(", ".join(gaps))}.', body))

    # ---- 1 direct dependencies ------------------------------------------------
    el.append(Paragraph("1&nbsp;&nbsp;Direct dependencies", h2))
    rows = [["Component", "Version", "Supplier / License", "Identifier", "SOUP record"]]
    for c in sorted(direct, key=lambda x: (x.get("name") or "").lower()):
        p = props(c)
        is_img = str(c.get("bom-ref", "")).startswith("quickbird:artifact:")
        name = esc(c.get("name")) + (' <font color="#5b6472">(image)</font>' if is_img else "")
        supplier = (c.get("supplier") or {}).get("name")
        lic = license_of(c)
        sup_txt = esc(supplier) if supplier else "—"
        if lic:
            sup_txt += f'<br/><font color="#5b6472">{esc(lic)}</font>'
        ident = c.get("purl") or p.get("quickbird:scan:target", "").replace("registry:", "")
        fam = p.get("quickbird:soup:approved-family", "")
        who, when = approver.get(c.get("bom-ref"), (None, ""))
        rec = f"{esc(fam)}" if fam else "—"
        if who:
            rec += f" · {esc(who)}<br/><font color='#5b6472'>{esc(when)}</font>"
        rows.append([
            Paragraph(name, cell),
            Paragraph(esc(c.get("version")), cell),
            Paragraph(sup_txt, cell),
            Paragraph(esc(ident)[:70], small),
            Paragraph(rec, cell),
        ])
    el.append(table(rows, [42 * mm, 20 * mm, 28 * mm, 48 * mm, 32 * mm]))

    # ---- 2 transitive and OS, aggregate ---------------------------------------
    el.append(Paragraph("2&nbsp;&nbsp;Transitive and operating-system components", h2))
    eco_counts = {}
    for c in rest:
        purl = c.get("purl") or ""
        eco = purl.split(":", 1)[1].split("/", 1)[0] if purl.startswith("pkg:") else "other"
        eco_counts[eco] = eco_counts.get(eco, 0) + 1
    rows = [["Ecosystem", "Components"]]
    for eco, n in sorted(eco_counts.items(), key=lambda kv: -kv[1]):
        rows.append([Paragraph(esc(eco), cell), Paragraph(str(n), cell)])
    rows.append([Paragraph("<b>Total</b>", cell), Paragraph(f"<b>{len(rest)}</b>", cell)])
    el.append(table(rows, [60 * mm, 30 * mm]))
    el.append(Paragraph(
        "Itemised in full, with identifiers and versions, in the machine-readable document.",
        small))

    # ---- 3 scanned artefacts ---------------------------------------------------
    el.append(Paragraph("3&nbsp;&nbsp;Scanned artefacts", h2))
    rows = [["Artefact", "Source", "Identity"]]
    for c in sorted(artifacts, key=lambda x: (x.get("name") or "").lower()):
        p = props(c)
        target = p.get("quickbird:scan:target", "")
        src = target.split(":", 1)[1] if ":" in target else target
        digest = p.get("quickbird:scan:image-digest", "")
        created = p.get("quickbird:scan:image-created", "")[:10]
        if digest:
            short = digest.split("sha256:")[-1][:12]
            ident = f"<font face='Courier'>sha256:{short}…</font>"
            if created:
                ident += f" · built {created}"
        else:
            ident = "resolved set"
        rows.append([
            Paragraph(esc(c.get("name")), cell),
            Paragraph(esc(src)[:70], small),
            Paragraph(ident, small),
        ])
    el.append(table(rows, [55 * mm, 65 * mm, 50 * mm]))

    # ---- footer ----------------------------------------------------------------
    el.append(Spacer(1, 14))
    el.append(Paragraph(
        f"Generated exclusively from <font face='Courier'>{esc(bundle_path.split('/')[-1])}"
        f"</font> (SHA-256 <font face='Courier'>{sha[:16]}…</font>). This document describes "
        f"composition and contains no vulnerability assessment. Related documents: "
        f"Dependency &amp; Vulnerability Report (assessment of this SBOM) · SOUP approval "
        f"records (.soups/). This is a record according to the quality management system of "
        f"QuickBird Medical.", small))

    doc = BaseDocTemplate(out_path, pagesize=A4,
                          leftMargin=20 * mm, rightMargin=20 * mm,
                          topMargin=16 * mm, bottomMargin=16 * mm)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 8 * mm,
                          f"SBOM Report — {root.get('name')} {root.get('version')}")
        canvas.drawRightString(190 * mm, 8 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=footer)])
    doc.build(el)


def main():
    if len(sys.argv) != 3:
        print("usage: render-sbom-pdf.py <bundle.cdx.json> <out.pdf>", file=sys.stderr)
        return 1
    with open(sys.argv[1], encoding="utf-8") as fh:
        bundle = json.load(fh)
    build(bundle, sys.argv[1], sys.argv[2])
    import os
    print(f"wrote {sys.argv[2]} ({os.path.getsize(sys.argv[2])} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
