#!/usr/bin/env python3
"""Render the Dependency & Vulnerability Report — the assessment, dated.

Document 2 of the two-report split. Structured by the questions the reader asked for, in
this order, each row shaded by decision state (rule violated without an accepted decision /
open within the process / compliant or accepted with a recorded reason):

    Applied rules  every rule with its value and its source (config or default)
    1  Summary     counts and severity distribution
    2  Updates     beyond the limit first, then available within the rules
    3  CVEs        per library, sorted by severity, with EPSS, via-path, Fixed-in and VEX
    4  Stale       deprecated/unmaintained first, then no-release-in-12-months
    5  Actions     the remediation units with their deadlines

Sections 2-4 are subdivided by platform (Web, Flutter app, Android/JVM, ...) — the same
grouping the SBOM report uses.

Deliberately argues from the configured rules, not from the SOUP record requirements —
those have their own layer.

Usage: render-vdr-pdf.py <bundle.cdx.json> <out.pdf> --policy effective.json
                         [--project-policy .soup-policy.yml] [--units units.json]
                         [--windows windows.json] [--date YYYY-MM-DD]
"""

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
from collections import deque

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
SEV2 = colors.HexColor("#f7d9d5")   # rule violated, no accepted decision
SEV1 = colors.HexColor("#fdf1ef")   # open within the process

body = ParagraphStyle("body", fontName="Helvetica", fontSize=8.5, leading=12, textColor=INK)
small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=10, textColor=MUTED)
cell = ParagraphStyle("cell", parent=body, fontSize=7.5, leading=10)
h1 = ParagraphStyle("h1", parent=body, fontSize=15, leading=19, fontName="Helvetica-Bold")
h2 = ParagraphStyle("h2", parent=body, fontSize=10.5, leading=14, fontName="Helvetica-Bold",
                    textColor=ACCENT, spaceBefore=14, spaceAfter=4)
h3 = ParagraphStyle("h3", parent=body, fontSize=9, leading=12, fontName="Helvetica-Bold",
                    spaceBefore=8, spaceAfter=3)

# Platform subcategories, shared with the SBOM renderer so both reports read the same way.
GROUP_ORDER = ["Web (npm)", "Flutter app (pub)", "Android / JVM (Maven)", ".NET (NuGet)",
               "Go", "Python", "Operating-system packages", "Container images",
               "GitHub Actions", "Other"]
ECO_LABEL = {"npm": "Web (npm)", "pub": "Flutter app (pub)",
             "maven": "Android / JVM (Maven)", "nuget": ".NET (NuGet)",
             "golang": "Go", "pypi": "Python",
             "apk": "Operating-system packages", "deb": "Operating-system packages",
             "rpm": "Operating-system packages",
             "github": "GitHub Actions", "githubactions": "GitHub Actions"}


def group_of(c):
    if str(c.get("bom-ref", "")).startswith("quickbird:artifact:"):
        return "Container images"
    purl = c.get("purl") or ""
    eco = purl.split(":", 1)[1].split("/", 1)[0] if purl.startswith("pkg:") else ""
    return ECO_LABEL.get(eco, "Other")


def props(obj):
    return {p["name"]: p["value"] for p in (obj.get("properties") or [])}


def esc(s):
    return (str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def version_key(v):
    """Order versions numerically. Plain string order puts 8.0.5 above 8.0.16.

    vite's advisories in one report publish both, and the Fixed-in column named 8.0.5 — a
    version below the one that actually carries the fix.
    """
    return [(0, int(part)) if part.isdigit() else (1, part)
            for part in re.split(r"[._+\-]", str(v)) if part]


def artifacts_of(p):
    """The artefacts a component was found in, without the property prefix."""
    raw = p.get("quickbird:component:artifact", "") or ""
    return [x.strip().replace("quickbird:artifact:", "")
            for x in raw.split(",") if x.strip()]


def one_row_per_library(entries):
    """Collapse the copies of one library into a single row, merging their artefacts.

    Since a Dockerfile candidate is scanned as the image it produces, the same library is
    found once per image that contains it and once in the lockfile that declares it. The
    currency note is stamped by purl, so every copy carries it and the table listed the same
    library three times — three rows for one decision, and a headline count to match.
    """
    out, seen = [], {}
    for c, p in entries:
        key = c.get("purl") or (c.get("name"), c.get("version"))
        if key in seen:
            for a in artifacts_of(p):
                if a not in seen[key][2]:
                    seen[key][2].append(a)
            continue
        seen[key] = [c, p, artifacts_of(p)]
        out.append(seen[key])
    return [(c, p, arts) for c, p, arts in out]


def lib_cell(c, arts, style, small_style):
    """Library name with the artefacts it sits in underneath."""
    txt = esc(c.get("name"))
    if arts:
        txt += (f'<br/><font size="6.5" color="#5b6472">in {esc(", ".join(sorted(arts)))}</font>')
    return Paragraph(txt, style)


def table(data, widths, shade=None):
    """shade: list of row indices -> colour"""
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("BACKGROUND", (0, 0), (-1, 0), BOX),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for idx, col in (shade or {}).items():
        style.append(("BACKGROUND", (0, idx), (-1, idx), col))
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle(style))
    return t


def link(vid, url=None):
    u = url or f"https://osv.dev/vulnerability/{vid}"
    return f'<link href="{esc(u)}"><font color="#1f4e79"><u>{esc(vid)}</u></font></link>'


def load_project_keys(path):
    """Top-level keys the project sets — everything else is a default."""
    if not path:
        return set()
    try:
        r = subprocess.run(["yq", "-o=json", ".", path], capture_output=True,
                           text=True, check=True)
        return set((json.loads(r.stdout or "{}") or {}).keys())
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError):
        return set()


def src_chip(is_config):
    return ('<font color="#1f4e79"><b>config</b></font>' if is_config
            else '<font color="#5b6472">default</font>')


def build_reverse_graph(bundle):
    """target ref -> sorted list of refs that depend on it. Sorted so the walk — and with
    it the rendered path — is deterministic across runs."""
    rev = {}
    for d in bundle.get("dependencies") or []:
        src = d.get("ref")
        for tgt in d.get("dependsOn") or []:
            rev.setdefault(tgt, []).append(src)
    for v in rev.values():
        v.sort()
    return rev


def via_path(ref, rev, names, stop_refs, cap=5):
    """Shortest chain of parents from ref up to a direct dependency (preferred) or, absent
    one, a top-level package — returned direct-most first. None when no edges exist."""
    seen = {ref}
    q = deque([(ref, [])])
    fallback = None
    while q:
        cur, path = q.popleft()
        for parent in rev.get(cur, []):
            if parent in seen:
                continue
            seen.add(parent)
            if parent not in names or str(parent).startswith("quickbird:"):
                continue    # the product root and artifact subjects end the walk
            chain = path + [parent]
            if parent in stop_refs:
                return list(reversed(chain))
            if not rev.get(parent) and fallback is None:
                fallback = list(reversed(chain))
            if len(chain) < cap:
                q.append((parent, chain))
    return fallback


def via_text(ref, rev, names, stop_refs):
    chain = via_path(ref, rev, names, stop_refs)
    if not chain:
        return None
    labels = [names[r] for r in chain]
    if len(labels) > 3:
        labels = [labels[0], "…", labels[-1]]
    return " › ".join(labels)


def build(args):
    bundle = json.load(open(args.bundle, encoding="utf-8"))
    policy = json.load(open(args.policy, encoding="utf-8"))
    units = (json.load(open(args.units, encoding="utf-8")) if args.units else {})
    windows = (json.load(open(args.windows, encoding="utf-8")) if args.windows else {})
    project_keys = load_project_keys(args.project_policy)

    meta = bundle.get("metadata") or {}
    mp = props(meta)
    root = meta.get("component") or {}
    components = bundle.get("components") or []
    vulns = bundle.get("vulnerabilities") or []
    comp_by_ref = {c.get("bom-ref"): c for c in components}
    sha = hashlib.sha256(open(args.bundle, "rb").read()).hexdigest()
    date = args.date or datetime.date.today().isoformat()

    el = []
    el.append(Paragraph(
        f"Dependency &amp; Vulnerability Report: {esc(root.get('name'))}", h1))
    el.append(Paragraph(
        f"Assessment of <b>{esc(root.get('version'))}</b>, dated <b>{esc(date)}</b>", small))
    el.append(Spacer(1, 6))
    el.append(Table([[Paragraph(
        f"<b>Assessed SBOM</b> <font face='Courier'>{esc(args.bundle.split('/')[-1])} · "
        f"{sha[:16]}…</font> &nbsp;·&nbsp; "
        f"<b>Data sources</b> OSV · KEV catalog "
        f"{esc(mp.get('quickbird:vuln:kev-catalog-version', '?'))} · EPSS "
        f"{esc(mp.get('quickbird:vuln:epss-model-version', '?'))} "
        f"({esc(mp.get('quickbird:vuln:epss-score-date', '?'))})", small)]],
        colWidths=[170 * mm], style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BOX),
            ("BOX", (0, 0), (-1, -1), 0.5, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4)])))

    # ---- applied rules ---------------------------------------------------------
    mb = (policy.get("dependency_currency") or {}).get("max_behind") or {}
    exempt_pubs = [str(x) for x in
                   ((policy.get("dependency_currency") or {}).get("stale_exempt_publishers") or [])]
    tr = policy.get("tracks") or {}

    def clocks(t):
        d = tr.get(t) or {}
        return f"{d.get('mitigation', 'n/a')} / {d.get('remediation', 'n/a')}"

    next_win = (windows.get("next_window") or "")[:10]
    rules = [
        ("Update limit (currency)",
         f"at most {mb.get('major', 0)} major / {mb.get('minor', 1)} minor behind the "
         f"latest release, patch drift {mb.get('patch', 'unlimited')}",
         "dependency_currency" in project_keys),
        ("Staleness window",
         f"no upstream release for > {policy.get('dependency_currency', {}).get('stale_after', '12m')} "
         f"→ replace, fork, or accept with reason",
         "dependency_currency" in project_keys),
        ("Staleness exemption",
         (", ".join(exempt_pubs) + " — staleness only, an update is still owed"
          if exempt_pubs else "none: every stale component needs its own reason"),
         "dependency_currency" in project_keys),
        ("Vulnerability classification",
         f"KEV → {clocks('kev')} · CVSS ≥ 9.0 → {clocks('immediate')} · "
         f"7.0–8.9 → {clocks('expedited')} · below → next window · unscored → Planned until scored",
         "tracks" in project_keys),
        ("EPSS escalation",
         f"≥ {policy.get('epss', {}).get('elevated', 0.1)} escalates one band · "
         f"≥ {policy.get('epss', {}).get('high', 0.5)} High → Immediate",
         "epss" in project_keys),
        ("Maintenance window",
         f"a maintenance release at least every {policy.get('maintenance_interval', '?')}"
         + (f"; next window {next_win}" if next_win else ""),
         "maintenance_interval" in project_keys),
        ("Reconciliation / CRA scope",
         f"every {policy.get('reconciliation_interval', '?')} · "
         f"CRA scope {policy.get('cra_scope', '?')}",
         True),
        ("Decision period after a breach",
         f"{policy.get('breach', {}).get('decision_within', '5d')} (working days) for a "
         f"revised date or a recorded risk acceptance",
         "breach" in project_keys),
        ("Notification threshold",
         f"new findings of severity {policy.get('alerts', {}).get('threshold', 'high')} "
         f"and above. Breaches and KEV always",
         "alerts" in project_keys),
    ]
    rows = [["Rule", "Value", "Source"]]
    for name, value, is_cfg in rules:
        rows.append([Paragraph(f"<b>{esc(name)}</b>", cell), Paragraph(esc(value), cell),
                     Paragraph(src_chip(is_cfg), cell)])
    el.append(Spacer(1, 6))
    el.append(Paragraph(
        "<b>Applied rules.</b> Values marked <font color='#1f4e79'><b>config</b></font> come "
        "from the product configuration (.soup-policy.yml). Values marked default are the "
        "process defaults that apply because the configuration does not override them.", small))
    el.append(table(rows, [46 * mm, 106 * mm, 18 * mm]))

    # ---- collect the data ------------------------------------------------------
    cur = []
    for c in components:
        p = props(c)
        st = p.get("quickbird:currency:status")
        if st:
            cur.append((c, p, st))
    beyond = one_row_per_library([(c, p) for c, p, st in cur if st in ("behind", "stale-and-behind")])
    within = one_row_per_library([(c, p) for c, p, st in cur if st == "update-available"])
    stale = one_row_per_library([(c, p) for c, p, st in cur if st == "stale"])
    deprecated = one_row_per_library([(c, p) for c, p, st in cur if st == "deprecated"])
    # Still listed in section 4 — the staleness is a fact and stays visible — but answered by
    # the process, so it is not a number anyone has to act on.
    stale_exempt = [e for e in stale if e[1].get("quickbird:currency:stale-exempt")]

    by_comp = {}
    for v in vulns:
        if (v.get("analysis") or {}).get("state") == "not_affected":
            continue
        fp = props(v)
        if "quickbird:finding:track" not in fp:
            continue
        for a in (v.get("affects") or [])[:1]:
            c = comp_by_ref.get(a.get("ref"))
            if not c:
                continue
            key = (c.get("name"), c.get("version"))
            by_comp.setdefault(key, {"comp": c, "vulns": []})["vulns"].append(v)

    def cvss_of(v):
        try:
            return float(props(v).get("quickbird:finding:cvss", ""))
        except ValueError:
            return None

    scored = [cvss_of(v) for v in vulns
              if "quickbird:finding:track" in props(v)]
    n_crit = sum(1 for x in scored if x is not None and x >= 9)
    n_high = sum(1 for x in scored if x is not None and 7 <= x < 9)
    n_med = sum(1 for x in scored if x is not None and 4 <= x < 7)
    n_low = sum(1 for x in scored if x is not None and x < 4)
    n_unscored = sum(1 for x in scored if x is None)
    n_kev = sum(1 for v in vulns if props(v).get("quickbird:vuln:kev") == "true")
    n_overdue = sum(1 for v in vulns for k in ("mitigation", "remediation")
                    if props(v).get(f"quickbird:finding:{k}-overdue") == "true")
    fixes = [props(v).get("quickbird:vuln:fix", "?") for v in vulns
             if "quickbird:finding:track" in props(v)]
    n_units = (units.get("summary") or {}).get("units_total")
    n_findings = len(scored)

    # ---- 1 summary ---------------------------------------------------------------
    el.append(Paragraph("1&nbsp;&nbsp;Summary", h2))
    tiles = [
        (str(len(beyond)), "libraries beyond the update limit", BAD),
        (f"{n_crit} / {n_high}", "open Critical / High CVEs", BAD),
        (str(len(stale) + len(deprecated) - len(stale_exempt)), "stale or deprecated", WARN),
        (f"{n_kev} / {n_overdue}", "KEV / deadlines overdue",
         GOOD if (n_kev + n_overdue) == 0 else BAD),
        (f"{n_findings} \u2192 {n_units if n_units is not None else 'n/a'}",
         "findings \u2192 remediation actions", INK),
    ]
    trow = [[Paragraph(
        f'<font color="{c.hexval().replace("0x", "#") if hasattr(c, "hexval") else "#16181d"}" size="11"><b>{esc(n)}</b></font><br/>'
        f'<font size="6.5" color="#5b6472">{esc(t)}</font>', cell)
        for n, t, c in tiles]]
    el.append(Table(trow, colWidths=[34 * mm] * 5, style=TableStyle([
                  ("GRID", (0, 0), (-1, -1), 0.5, LINE),
                  ("VALIGN", (0, 0), (-1, -1), "TOP"),
                  ("TOPPADDING", (0, 0), (-1, -1), 4),
                  ("BOTTOMPADDING", (0, 0), (-1, -1), 4)])))
    el.append(Spacer(1, 4))
    el.append(Paragraph(
        f"CVEs by severity: <font color='#b91c1c'><b>{n_crit} Critical</b></font> · "
        f"<font color='#b45309'><b>{n_high} High</b></font> · {n_med} Medium · {n_low} Low · "
        f"{n_unscored} unscored (see 5 Remediation actions for each one's own track). "
        f"Fix availability: "
        f"<b>{fixes.count('available')} with a published fix</b> · "
        f"{fixes.count('none-published')} without · "
        f"{fixes.count('prerelease-only')} only as a prerelease · "
        f"{len(fixes) - fixes.count('available') - fixes.count('none-published') - fixes.count('prerelease-only')}"
        f" undetermined.",
        small))
    el.append(Paragraph(
        "Row shading: <font color='#b91c1c'>rule violated, no accepted decision</font> · "
        "<font color='#b45309'>finding open within the process</font> · plain: compliant, or "
        "accepted with a recorded reason.", small))

    # ---- 2 updates available -----------------------------------------------------
    el.append(Paragraph("2&nbsp;&nbsp;Updates available", h2))
    upd_groups = {}
    for c, p, a in beyond:
        upd_groups.setdefault(group_of(c), {"beyond": [], "within": []})["beyond"].append((c, p, a))
    for c, p, a in within:
        upd_groups.setdefault(group_of(c), {"beyond": [], "within": []})["within"].append((c, p, a))
    if not upd_groups:
        el.append(Paragraph("none", small))
    sec = 0
    for gname in GROUP_ORDER:
        g = upd_groups.get(gname)
        if not g:
            continue
        sec += 1
        el.append(Paragraph(
            f"2.{sec}&nbsp;&nbsp;{esc(gname)}: {len(g['beyond'])} beyond the limit, "
            f"{len(g['within'])} within", h3))
        rows = [["Library", "Installed", "Latest", "Detail", "Status"]]
        shade = {}
        for c, p, arts in sorted(g["beyond"], key=lambda cp: (cp[0].get("name") or "").lower()):
            shade[len(rows)] = SEV2
            rows.append([
                lib_cell(c, arts, cell, small),
                Paragraph(esc(c.get("version")), cell),
                Paragraph(f"<b>{esc(p.get('quickbird:currency:latest', '?'))}</b>", cell),
                Paragraph(esc(p.get("quickbird:currency:detail", "beyond limit")), small),
                Paragraph("No decision recorded.", cell),
            ])
        for c, p, arts in sorted(g["within"], key=lambda cp: (cp[0].get("name") or "").lower()):
            rows.append([
                lib_cell(c, arts, cell, small),
                Paragraph(esc(c.get("version")), cell),
                Paragraph(esc(p.get("quickbird:currency:latest", "?")), cell),
                Paragraph("within limits", small),
                Paragraph("no decision required", small),
            ])
        # Library carries the artefact list underneath the name now. Total unchanged at 170mm.
        el.append(table(rows, [56 * mm, 18 * mm, 18 * mm, 38 * mm, 40 * mm], shade))

    # ---- 3 libraries with CVEs -----------------------------------------------------
    el.append(Paragraph("3&nbsp;&nbsp;Libraries with CVEs", h2))
    rev = build_reverse_graph(bundle)
    names = {c.get("bom-ref"): (c.get("name") or "") for c in components}
    direct_refs = {c.get("bom-ref") for c in components
                   if props(c).get("quickbird:dependency:scope") == "direct"
                   or (props(c).get("quickbird:soup:record")
                       and props(c).get("quickbird:dependency:scope") != "dev")}
    groups = []
    for (name, version), g in by_comp.items():
        vs = g["vulns"]
        mx = max((cvss_of(v) or -1 for v in vs), default=-1)
        kev = any(props(v).get("quickbird:vuln:kev") == "true" for v in vs)
        groups.append((mx, kev, name, version, g))
    groups.sort(key=lambda x: (-int(x[1]), -x[0], x[2] or ""))
    CAP = 50
    cve_groups = {}
    for item in groups[:CAP]:
        cve_groups.setdefault(group_of(item[4]["comp"]), []).append(item)
    if not groups:
        el.append(Paragraph("none", small))
    sec = 0
    for gname in GROUP_ORDER:
        items = cve_groups.get(gname)
        if not items:
            continue
        sec += 1
        el.append(Paragraph(
            f"3.{sec}&nbsp;&nbsp;{esc(gname)}: {len(items)} "
            f"{'library' if len(items) == 1 else 'libraries'}", h3))
        rows = [["Library", "Severity", "CVEs", "Fixed in", "VEX", "Status"]]
        shade = {}
        for mx, kev, name, version, g in items:
            vs = sorted(g["vulns"], key=lambda v: -(cvss_of(v) or -1))
            c = g["comp"]
            p = props(c)
            art = p.get("quickbird:component:artifact", "").replace("quickbird:artifact:", "")
            art = art.split(", ")[0]
            lib = esc(f"{name} @ {version}")
            if art:
                lib += f"<br/><font color='#5b6472' size='6.5'>in {esc(art)}</font>"
            via = via_text(c.get("bom-ref"), rev, names, direct_refs)
            if via:
                lib += f"<br/><font color='#5b6472' size='6.5'>via {esc(via)}</font>"
            sev = ("KEV" if kev else f"CVSS {mx:.1f}" if mx >= 0 else "unscored")
            sev_col = "#b91c1c" if (kev or mx >= 9) else "#b45309" if mx >= 7 or mx < 0 else "#5b6472"
            def epss_num(v):
                try:
                    return float(props(v).get("quickbird:finding:epss", ""))
                except ValueError:
                    return -1
            epss = max((epss_num(v) for v in vs), default=-1)
            sev_txt = f'<font color="{sev_col}"><b>{esc(sev)}</b></font>'
            if epss >= 0:
                sev_txt += f"<br/><font color='#5b6472' size='6.5'>EPSS {epss:.2f}</font>"
            ids = ", ".join(link(v.get("id"), (v.get("source") or {}).get("url")) for v in vs[:3])
            if len(vs) > 3:
                ids += f' <font color="#5b6472">and {len(vs) - 3} further</font>'
            def versions_in(state):
                return sorted({f for v in vs
                               if props(v).get("quickbird:vuln:fix") == state
                               for f in (props(v).get("quickbird:vuln:fix-versions", "")
                                         or "").split(", ")
                               if f}, key=version_key)

            # Split by state rather than pooling every fix-version in the group: a component
            # with a stable fix for one CVE and only a prerelease for another would otherwise
            # show whichever sorted last, which is how an alpha ends up printed as the answer.
            fx_avail, fx_pre = versions_in("available"), versions_in("prerelease-only")
            fstates = {props(v).get("quickbird:vuln:fix", "?") for v in vs}
            if fx_avail:
                fixed = f"<b>{esc(fx_avail[-1])}</b>"
            elif fx_pre:
                # Bold and unqualified, the version read as something to bump to. It is not:
                # a released product cannot adopt an alpha, so the column has to say which
                # kind of version this is.
                fixed = (f'<font color="#b45309"><b>{esc(fx_pre[-1])}</b><br/>'
                         f'<font size="6.5">prerelease only</font></font>')
            elif fstates == {"none-published"}:
                fixed = '<font color="#b45309"><b>no fix published</b></font>'
            else:
                fixed = "n/a"
            vex = next((esc((v.get("analysis") or {}).get("state")) for v in vs
                        if v.get("analysis")), "n/a")
            due = min((props(v).get("quickbird:finding:mitigation-due", "") or
                       props(v).get("quickbird:finding:remediation-due", "") for v in vs),
                      default="")[:10]
            track = props(vs[0]).get("quickbird:finding:track", "")
            status = "No decision recorded."
            if due:
                status += f" Mitigation due {due} ({track})."
            shade[len(rows)] = SEV2 if (kev or mx >= 9) else SEV1
            rows.append([
                Paragraph(lib, cell),
                Paragraph(sev_txt, cell),
                Paragraph(ids, small),
                Paragraph(fixed, cell),
                Paragraph(vex, cell),
                Paragraph(status, small),
            ])
        el.append(table(rows, [34 * mm, 16 * mm, 42 * mm, 22 * mm, 14 * mm, 42 * mm], shade))
    if len(groups) > CAP:
        el.append(Paragraph(
            f"… {len(groups) - CAP} further libraries with open CVEs, itemised in the "
            f"machine-readable report.", small))

    # ---- 4 stale and unmaintained ---------------------------------------------------
    el.append(Paragraph("4&nbsp;&nbsp;Stale and unmaintained", h2))
    if not deprecated:
        el.append(Paragraph("Declared deprecated / unmaintained: none detected.", small))
    stale_groups = {}
    for c, p, a in deprecated:
        stale_groups.setdefault(group_of(c), {"dep": [], "stale": []})["dep"].append((c, p, a))
    for c, p, a in stale:
        stale_groups.setdefault(group_of(c), {"dep": [], "stale": []})["stale"].append((c, p, a))
    if not stale_groups:
        el.append(Paragraph("No library on its latest version has exceeded the staleness "
                            "window.", small))
    sec = 0
    for gname in GROUP_ORDER:
        g = stale_groups.get(gname)
        if not g:
            continue
        sec += 1
        el.append(Paragraph(f"4.{sec}&nbsp;&nbsp;{esc(gname)}: {len(g['dep']) + len(g['stale'])}",
                            h3))
        rows = [["Library", "Installed = latest", "Detail", "Registry status", "Status"]]
        shade = {}
        for c, p, arts in sorted(g["dep"], key=lambda cp: (cp[0].get("name") or "").lower()):
            shade[len(rows)] = SEV2
            rows.append([
                lib_cell(c, arts, cell, small),
                Paragraph(esc(c.get("version")), cell),
                Paragraph(esc(p.get("quickbird:currency:detail", "")), small),
                Paragraph('<font color="#b91c1c"><b>deprecated</b></font>', cell),
                Paragraph("No decision recorded.", cell),
            ])
        for c, p, arts in sorted(g["stale"], key=lambda cp: (cp[0].get("name") or "").lower()):
            exempt = p.get("quickbird:currency:stale-exempt")
            if not exempt:
                shade[len(rows)] = SEV1
            who = p.get("quickbird:currency:publisher")
            rows.append([
                lib_cell(c, arts, cell, small),
                Paragraph(esc(c.get("version")), cell),
                Paragraph(esc(p.get("quickbird:currency:detail", "")), small),
                Paragraph(f"verified publisher {esc(who)}" if who else "active flag not set",
                          small),
                Paragraph(esc(exempt) if exempt else "No decision recorded.", cell),
            ])
        # Status carries a full sentence once a publisher exemption is in force, and
        # Registry status carries "verified publisher <domain>". Both were sized for two
        # words. Total unchanged at 170mm.
        el.append(table(rows, [52 * mm, 23 * mm, 31 * mm, 26 * mm, 38 * mm], shade))

    # ---- 5 remediation actions ----------------------------------------------------
    el.append(Paragraph("5&nbsp;&nbsp;Remediation actions", h2))
    rows = [["Action", "Track", "Findings", "Mitigation due", "Remediation due", "Status"]]
    shade = {}
    for u in (units.get("units") or []):
        track = u.get("track", "")
        if track in ("kev", "immediate"):
            shade[len(rows)] = SEV1
        tcol = {"kev": "#b91c1c", "immediate": "#b91c1c",
                "expedited": "#b45309"}.get(track, "#5b6472")
        state = u.get("state", "")
        status = {"no-vendor-request": "no vendor request recorded",
                  "vendor-overdue": "vendor follow-up elapsed, decision required",
                  "waiting-on-vendor": "waiting on vendor (on record)",
                  "vendor-request-undated": "vendor request without follow-up date",
                  "ours": "open"}.get(state, state or "open")
        shared = u.get("shared_findings") or {}
        if shared:
            # A finding here is also open under another action. Closing this one does not
            # close that finding, only this unit's part of it.
            status = f"{status} · {len(shared)} finding(s) also open under another action"
        rows.append([
            Paragraph(esc(u.get("action", ""))[:220], small),
            Paragraph(f'<font color="{tcol}"><b>{esc(track)}</b></font>', cell),
            Paragraph(str(u.get("finding_count", "")), cell),
            Paragraph(esc((u.get("mitigation_due") or "")[:10] or "n/a"), cell),
            Paragraph(esc((u.get("remediation_due") or "")[:10] or "next window"), cell),
            Paragraph(esc(status), small),
        ])
    if len(rows) == 1:
        rows.append([Paragraph("none, no open findings", small)] + [Paragraph("", small)] * 5)
    el.append(table(rows, [64 * mm, 18 * mm, 15 * mm, 21 * mm, 22 * mm, 30 * mm], shade))

    # ---- footer ----------------------------------------------------------------------
    el.append(Spacer(1, 14))
    el.append(Paragraph(
        f"Generated exclusively from the machine-readable assessment "
        f"<font face='Courier'>{esc(args.bundle.split('/')[-1])}</font> "
        f"(SHA-256 <font face='Courier'>{sha[:16]}…</font>). Statements in this document are "
        f"valid as of the assessment date stated in the header. Recorded decisions are read "
        f"from .soup-decisions.yml and the SOUP records. Classification and deadlines follow "
        f"the rules stated above. Related documents: SBOM Report "
        f"{esc(root.get('version'))} · SOUP approval records (.soups/). This is a record "
        f"according to the quality management system of QuickBird Medical.", small))

    doc = BaseDocTemplate(args.out, pagesize=A4,
                          leftMargin=20 * mm, rightMargin=20 * mm,
                          topMargin=16 * mm, bottomMargin=16 * mm)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 8 * mm,
                          f"Dependency & Vulnerability Report: {root.get('name')} "
                          f"{root.get('version')} · {date}")
        canvas.drawRightString(190 * mm, 8 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=footer)])
    doc.build(el)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("out")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--project-policy")
    ap.add_argument("--units")
    ap.add_argument("--windows")
    ap.add_argument("--date")
    args = ap.parse_args()
    build(args)
    import os
    print(f"wrote {args.out} ({os.path.getsize(args.out)} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
