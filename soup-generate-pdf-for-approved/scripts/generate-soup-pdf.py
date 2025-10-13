import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import os
import sys


SOUP_JSON_FILE = sys.argv[1]

with open(SOUP_JSON_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

METADATA_KEYS = {
    "license": "License",
    "analysis_period": "Analysis Period",
    "releases_found": "Releases Found",
    "min_expected": "Min Expected Releases",
    "recent_versions": "Recent Versions",
    "stars": "Stars",
    "forks": "Forks",
    "downloads_last_30_days": "Downloads (30d)",
    "total_versions_checked": "Versions Checked",
}

pdf_filename = "soup_reports/" + os.path.basename(SOUP_JSON_FILE) + ".pdf"
if not os.path.exists("soup_reports"):
    os.makedirs("soup_reports")

doc = SimpleDocTemplate(
    pdf_filename,
    pagesize=A4,
    rightMargin=30,
    leftMargin=30,
    topMargin=30,
    bottomMargin=40
)
elements = []
styles = getSampleStyleSheet()

status_style = ParagraphStyle(name='Status', alignment=1, fontSize=12, spaceBefore=4, spaceAfter=4)
wrap_style = ParagraphStyle(name='Wrap', fontSize=8.5, leading=11, spaceAfter=6)
left_wrap_style = ParagraphStyle(name='LeftWrap', parent=wrap_style, alignment=0)
heading_style = ParagraphStyle(name='Heading', fontSize=15, leading=16, spaceBefore=12, spaceAfter=6, fontName="Helvetica-Bold")
bold_left_style = ParagraphStyle(name='BoldLeft', parent=wrap_style, fontName="Helvetica-Bold")

def parse_date_safe(date_str):
    try:
        return datetime.strptime(date_str, "%B %d, %Y")
    except Exception:
        return datetime.min

def safe_paragraph(text, style):
    try:
        return Paragraph(text or "-", style)
    except Exception:
        safe_text = str(text).replace("<", "&lt;").replace(">", "&gt;")
        return Paragraph(safe_text or "-", style)

def format_standard_metadata(meta):
    if isinstance(meta, str):
        return f"<a href='{meta}' color='blue'>{meta}</a>"
    if not isinstance(meta, dict):
        return ""

    url_fields = [meta.get("url"), meta.get("license_url")]
    for link in url_fields:
        if link:
            name = meta.get("license") or meta.get("package") or link
            return f"<a href='{link}' color='blue'>{name}</a>"

    lines = []
    for key, label in METADATA_KEYS.items():
        value = meta.get(key)
        if not value:
            continue

        if key == "recent_versions" and isinstance(value, dict):
            sorted_versions = sorted(value.items(), key=lambda x: parse_date_safe(x[1]), reverse=True)[:3]
            lines.append(f"<b>{label}</b>:")
            for ver, date_str in sorted_versions:
                lines.append(f"&bull; {ver} – {date_str}")
        else:
            lines.append(f"<b>{label}</b>: {value}")

    return "<br/>".join(lines)

def format_grq4_metadata(meta, fulfilled):
    if fulfilled or not isinstance(meta, dict):
        return ""

    lines = []
    esv = meta.get("earliest_safe_version")
    if esv:
        lines.append(f"<b>Earliest Safe Version:</b> {esv}")

    vulns = meta.get("vulnerabilities", {})
    if isinstance(vulns, dict) and vulns:
        lines.append("<b>Vulnerabilities:</b>")
        for vuln_id, v in vulns.items():
            url = v.get("url", "")
            link = f"<a href='{url}' color='blue'>{vuln_id}</a>" if url else vuln_id
            lines.append(f"&bull; {link}")

    return "<br/>".join(lines)

elements.append(Paragraph("Details", heading_style))
elements.append(Spacer(1, 8))

urls = data.get("urls", {})
details_data = [
    [safe_paragraph("Name", bold_left_style),
     safe_paragraph(data.get("package", "-"), wrap_style)],
    [safe_paragraph("Version", bold_left_style),
     safe_paragraph(data.get("version", "-"), wrap_style)],
    [safe_paragraph("Purpose", bold_left_style),
     safe_paragraph(data.get("purpose", "-"), wrap_style)],
    [safe_paragraph("Origin", bold_left_style),
     safe_paragraph(f"<a href='{urls.get('provider', '#')}' color='blue'>{urls.get('provider', '-')}</a>", wrap_style)],
    [safe_paragraph("Provider", bold_left_style),
     safe_paragraph(data.get("provider", "-"), wrap_style)],
    [safe_paragraph("License", bold_left_style),
     safe_paragraph(data.get("license", "-"), wrap_style)],
    [safe_paragraph("Known Issues", bold_left_style),
     safe_paragraph(f"<a href='{urls.get('known_issues', '#')}' color='blue'>{urls.get('known_issues', '-')}</a>", wrap_style)]
]

details_table = Table(details_data, colWidths=[1.3*inch, 5.2*inch])
details_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
]))
elements.append(details_table)
elements.append(Spacer(1, 20))

elements.append(Paragraph("General Requirements", heading_style))
elements.append(Spacer(1, 6))

table_data = [["Number", "Requirement", "Fulfilled", "Details / Metadata", "Reason if not fulfilled"]]

for key, req in data.get("requirements", {}).items():
    if "grq-" not in key:
        continue

    fulfilled = req.get("fulfilled", False)
    desc = safe_paragraph(req.get("description", ""), left_wrap_style)
    reason = safe_paragraph(req.get("reason_if_requirement_not_fulfilled", "") or "-", wrap_style)

    fulfilled_cell = safe_paragraph(
        '<font color="green">&#10003;</font>' if fulfilled else '<font color="red">&#10007;</font>',
        status_style
    )

    meta = req.get("metadata", {})
    formatted_meta = format_grq4_metadata(meta, fulfilled) if key == "grq-4" else format_standard_metadata(meta)
    meta_paragraph = safe_paragraph(formatted_meta or "-", wrap_style)

    table_data.append([Paragraph(f"<b>{key.upper()}</b>", wrap_style), desc, fulfilled_cell, meta_paragraph, reason])

table = Table(
    table_data,
    repeatRows=1,
    colWidths=[0.6*inch, 2.0*inch, 0.7*inch, 2.6*inch, 1.3*inch]
)
table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ("ALIGN", (1, 1), (1, -1), "LEFT"),
    ("ALIGN", (3, 1), (3, -1), "LEFT"),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
]))
elements.append(table)


elements.append(Spacer(1, 20))
elements.append(Paragraph("Approval", heading_style))
elements.append(Spacer(1, 8))

approval = data.get("metadata", {}).get("approval", {})
by = approval.get("by")
on = approval.get("date")
condition = approval.get("condition", "")

if by and on:
    approval_text = f"<b>Approved By {by} on {on}</b>"
    if condition.strip():
        approval_text += f" (Condition: {condition.strip()})"
    elements.append(safe_paragraph(approval_text, styles["Normal"]))

doc.build(elements)
print(f"✅ {pdf_filename} created successfully.")
