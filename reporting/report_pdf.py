"""
reporting/report_pdf.py
Generates a professional PDF security assessment report using ReportLab.
Falls back gracefully if ReportLab is not installed.
"""

import logging
import os
from datetime import datetime
from typing import Optional

from utils.helpers import ensure_dir, unique_filename
from config.settings import OUTPUT_DIR, TOOL_NAME, TOOL_VERSION, PDF_COMPANY_NAME

logger = logging.getLogger(__name__)

# ── ReportLab Import (optional dependency) ────────────────────────────────────
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not installed; PDF report generation is disabled.")


# ── Colour palette ─────────────────────────────────────────────────────────────
if REPORTLAB_AVAILABLE:
    C_PRIMARY   = colors.HexColor("#1a1a2e")   # Dark navy
    C_ACCENT    = colors.HexColor("#16213e")   # Darker navy
    C_HIGHLIGHT = colors.HexColor("#0f3460")   # Medium navy
    C_RED       = colors.HexColor("#e94560")   # Alert red
    C_ORANGE    = colors.HexColor("#f5a623")   # Warning orange
    C_YELLOW    = colors.HexColor("#f7dc6f")   # Caution yellow
    C_GREEN     = colors.HexColor("#27ae60")   # Safe green
    C_WHITE     = colors.white
    C_LIGHT     = colors.HexColor("#ecf0f1")   # Light grey

    RISK_COLOURS = {
        "Critical":   C_RED,
        "Vulnerable": C_ORANGE,
        "Moderate":   C_YELLOW,
        "Secure":     C_GREEN,
        "Low":        C_GREEN,
        "Medium":     C_YELLOW,
        "High":       C_ORANGE,
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def save_pdf_report(
    networks:    list[dict],
    scan_meta:   dict,
    output_path: Optional[str] = None,
) -> Optional[str]:
    """Generate and save a PDF security assessment report.

    Args:
        networks:    Fully-analysed network list (sorted by risk score).
        scan_meta:   Scan metadata dict.
        output_path: Optional target path.  If None, a timestamped path in
                     OUTPUT_DIR is used.

    Returns:
        Path to the created PDF, or None if ReportLab is unavailable.
    """
    if not REPORTLAB_AVAILABLE:
        logger.error(
            "ReportLab is not installed.  Install it with: pip install reportlab"
        )
        return None

    ensure_dir(OUTPUT_DIR)
    path = output_path or unique_filename(OUTPUT_DIR, "wsa_report", ".pdf")

    try:
        _generate_pdf(networks, scan_meta, path)
        logger.info("PDF report saved → %s", path)
        return path
    except Exception as exc:        # pylint: disable=broad-except
        logger.error("PDF generation failed: %s", exc)
        raise


# ── PDF Construction ──────────────────────────────────────────────────────────

def _generate_pdf(networks: list[dict], scan_meta: dict, path: str) -> None:
    """Build and write the PDF document.

    Args:
        networks:  Analysed networks.
        scan_meta: Scan metadata.
        path:      Output file path.
    """
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = _build_styles()
    story: list = []

    # Cover
    story += _cover_section(scan_meta, networks, styles)
    story.append(PageBreak())

    # Executive Summary
    story += _executive_summary(networks, styles)
    story.append(PageBreak())

    # Network Overview Table
    story += _network_table_section(networks, styles)
    story.append(PageBreak())

    # Per-Network Detail
    story += _per_network_details(networks, styles)

    # Recommendations
    story += _recommendations_section(networks, styles)

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)


# ── Sections ──────────────────────────────────────────────────────────────────

def _cover_section(meta: dict, networks: list[dict], styles: dict) -> list:
    ts    = meta.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    iface = meta.get("interface", "unknown")
    story = [
        Spacer(1, 3 * cm),
        Paragraph(PDF_COMPANY_NAME.upper(), styles["cover_title"]),
        Spacer(1, 0.5 * cm),
        Paragraph("Wireless Security Assessment Report", styles["cover_sub"]),
        Spacer(1, 2 * cm),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT),
        Spacer(1, 0.5 * cm),
        Paragraph(f"Interface: {iface}", styles["cover_meta"]),
        Paragraph(f"Scan Date: {ts}", styles["cover_meta"]),
        Paragraph(f"Networks Found: {len(networks)}", styles["cover_meta"]),
        Spacer(1, 2 * cm),
        Paragraph(
            "⚠  This report contains sensitive security information.  "
            "Handle accordingly and restrict access to authorised personnel.",
            styles["disclaimer"],
        ),
    ]
    return story


def _executive_summary(networks: list[dict], styles: dict) -> list:
    critical   = sum(1 for n in networks if n.get("risk", {}).get("label") == "Critical")
    vulnerable = sum(1 for n in networks if n.get("risk", {}).get("label") == "Vulnerable")
    moderate   = sum(1 for n in networks if n.get("risk", {}).get("label") == "Moderate")
    secure     = sum(1 for n in networks if n.get("risk", {}).get("label") == "Secure")
    avg_score  = (
        round(sum(n.get("risk", {}).get("score", 0) for n in networks) / len(networks), 1)
        if networks else 0
    )

    summary_data = [
        ["Total Networks", str(len(networks))],
        ["Average Risk Score", f"{avg_score} / 100"],
        ["Critical",          str(critical)],
        ["Vulnerable",        str(vulnerable)],
        ["Moderate",          str(moderate)],
        ["Secure",            str(secure)],
        ["Open Networks",     str(sum(1 for n in networks if n.get("encryption") == "OPEN"))],
        ["WEP Networks",      str(sum(1 for n in networks if n.get("encryption") == "WEP"))],
        ["WPS Enabled",       str(sum(1 for n in networks if n.get("wps")))],
    ]

    tbl = Table(summary_data, colWidths=[8 * cm, 5 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), C_PRIMARY),
        ("TEXTCOLOR",    (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",     (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_LIGHT, C_WHITE]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING",      (0, 0), (-1, -1), 6),
    ]))

    return [
        Paragraph("Executive Summary", styles["h1"]),
        Spacer(1, 0.3 * cm),
        tbl,
        Spacer(1, 0.5 * cm),
    ]


def _network_table_section(networks: list[dict], styles: dict) -> list:
    story = [Paragraph("Network Overview", styles["h1"]), Spacer(1, 0.3 * cm)]

    headers = ["#", "SSID", "BSSID", "Signal", "Enc", "WPS", "Score", "Risk"]
    rows    = [headers]
    for idx, net in enumerate(networks, 1):
        risk  = net.get("risk", {})
        rows.append([
            str(idx),
            net.get("ssid", "<hidden>")[:22],
            net.get("bssid", ""),
            f"{net.get('signal', -100)} dBm",
            net.get("encryption", "?"),
            "Yes" if net.get("wps") else "No",
            str(risk.get("score", 0)),
            risk.get("label", "?"),
        ])

    col_widths = [0.6*cm, 4.5*cm, 4.0*cm, 2.2*cm, 1.8*cm, 1.4*cm, 1.6*cm, 2.5*cm]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)

    tbl_style = [
        ("BACKGROUND",  (0, 0), (-1, 0), C_PRIMARY),
        ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("GRID",        (0, 0), (-1, -1), 0.3, colors.grey),
        ("PADDING",     (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (1, 0), (-1, -1), [C_LIGHT, C_WHITE]),
    ]
    # Colour-code Risk column
    for r_idx, net in enumerate(networks, 1):
        label = net.get("risk", {}).get("label", "")
        c     = RISK_COLOURS.get(label, colors.grey)
        tbl_style.append(("BACKGROUND", (7, r_idx), (7, r_idx), c))
        tbl_style.append(("TEXTCOLOR",  (7, r_idx), (7, r_idx), C_WHITE))
        tbl_style.append(("FONTNAME",   (7, r_idx), (7, r_idx), "Helvetica-Bold"))

    tbl.setStyle(TableStyle(tbl_style))
    story.append(tbl)
    story.append(Spacer(1, 0.5 * cm))
    return story


def _per_network_details(networks: list[dict], styles: dict) -> list:
    story = [Paragraph("Detailed Network Analysis", styles["h1"]), Spacer(1, 0.3 * cm)]

    for net in networks:
        risk  = net.get("risk", {})
        label = risk.get("label", "Unknown")
        score = risk.get("score", 0)
        colour = RISK_COLOURS.get(label, colors.grey)

        # Network header
        header_data = [[
            f"{net.get('ssid', '<hidden>')}  |  {net.get('bssid', '')}",
            f"Score: {score}/100  |  {label}",
        ]]
        h_tbl = Table(header_data, colWidths=[11 * cm, 7 * cm])
        h_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, -1), C_PRIMARY),
            ("TEXTCOLOR",   (0, 0), (-1, -1), C_WHITE),
            ("FONTNAME",    (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("PADDING",     (0, 0), (-1, -1), 6),
            ("BACKGROUND",  (1, 0), (1, 0), colour),
        ]))
        story.append(KeepTogether([h_tbl]))

        # Findings
        all_findings = []
        enc_a = net.get("encryption_analysis", {})
        if enc_a:
            all_findings.append(enc_a)
        all_findings.extend(net.get("config_findings", []))
        all_findings.extend(net.get("rogue_findings", []))

        for f in all_findings:
            f_colour = RISK_COLOURS.get(f.get("risk_level", ""), colors.grey)
            finding_data = [
                [f"▶ {f.get('vulnerability') or f.get('check', '')}",
                 f.get("risk_level", "")],
                [Paragraph(f.get("description", ""), styles["body_small"]),
                 ""],
                [Paragraph(
                    f"<b>Scenario:</b> {f.get('unauthorized_access_scenario', '')}",
                    styles["scenario"]), ""],
                [Paragraph(
                    f"<b>Recommendation:</b> {f.get('recommendation', '')}",
                    styles["rec"]), ""],
            ]
            f_tbl = Table(finding_data, colWidths=[15.5 * cm, 2.5 * cm])
            f_tbl.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, 0), C_ACCENT),
                ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME",    (0, 0), (0, 0), "Helvetica-Bold"),
                ("FONTSIZE",    (0, 0), (-1, -1), 8),
                ("BACKGROUND",  (1, 0), (1, 0), f_colour),
                ("TEXTCOLOR",   (1, 0), (1, 0), C_WHITE),
                ("VALIGN",      (0, 0), (-1, -1), "TOP"),
                ("GRID",        (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("PADDING",     (0, 0), (-1, -1), 5),
                ("SPAN",        (0, 1), (1, 1)),
                ("SPAN",        (0, 2), (1, 2)),
                ("SPAN",        (0, 3), (1, 3)),
            ]))
            story.append(Spacer(1, 2 * mm))
            story.append(f_tbl)

        story.append(Spacer(1, 0.5 * cm))

    return story


def _recommendations_section(networks: list[dict], styles: dict) -> list:
    seen: set[str] = set()
    recs: list[str] = []

    for net in networks:
        all_f = (
            [net.get("encryption_analysis", {})]
            + net.get("config_findings", [])
            + net.get("rogue_findings", [])
        )
        for f in all_f:
            r = f.get("recommendation", "")
            if r and r not in seen:
                seen.add(r)
                recs.append(r)

    story = [
        PageBreak(),
        Paragraph("Consolidated Recommendations", styles["h1"]),
        Spacer(1, 0.3 * cm),
    ]
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f"{i}. {rec}", styles["rec"]))
        story.append(Spacer(1, 2 * mm))

    return story


# ── Page Footer ───────────────────────────────────────────────────────────────

def _page_footer(canvas, doc) -> None:
    """Draw a footer on each page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(2 * cm, 1.5 * cm, f"{TOOL_NAME} v{TOOL_VERSION}")
    canvas.drawRightString(
        A4[0] - 2 * cm, 1.5 * cm,
        f"CONFIDENTIAL  |  Page {doc.page}",
    )
    canvas.restoreState()


# ── Style Builder ─────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    """Create and return a dict of ParagraphStyle objects.

    Returns:
        Dict mapping style name → ParagraphStyle.
    """
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title", parent=base["Title"],
            fontSize=28, textColor=C_PRIMARY, spaceAfter=6,
            alignment=TA_CENTER,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", parent=base["Normal"],
            fontSize=16, textColor=C_HIGHLIGHT, spaceAfter=4,
            alignment=TA_CENTER,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta", parent=base["Normal"],
            fontSize=11, textColor=C_ACCENT, spaceAfter=3,
            alignment=TA_CENTER,
        ),
        "disclaimer": ParagraphStyle(
            "disclaimer", parent=base["Normal"],
            fontSize=9, textColor=C_RED, alignment=TA_CENTER,
            borderPad=4,
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"],
            fontSize=14, textColor=C_PRIMARY, spaceAfter=6,
        ),
        "body_small": ParagraphStyle(
            "body_small", parent=base["Normal"],
            fontSize=8, leading=11,
        ),
        "scenario": ParagraphStyle(
            "scenario", parent=base["Normal"],
            fontSize=8, leading=11, textColor=colors.HexColor("#7f4f00"),
        ),
        "rec": ParagraphStyle(
            "rec", parent=base["Normal"],
            fontSize=8, leading=11, textColor=colors.HexColor("#1a5276"),
        ),
    }
