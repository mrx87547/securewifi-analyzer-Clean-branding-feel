"""
PDF security assessment report generation.
"""

from __future__ import annotations

import logging
from datetime import datetime
from html import escape as html_escape
from pathlib import Path

from config.settings import OUTPUT_DIR, PDF_COMPANY_NAME, TOOL_NAME, TOOL_VERSION
from utils.helpers import ensure_dir, safe_console_text, unique_filename

logger = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not installed; PDF report generation is disabled.")


if REPORTLAB_AVAILABLE:
    C_PRIMARY = colors.HexColor("#1a1a2e")
    C_ACCENT = colors.HexColor("#16213e")
    C_HIGHLIGHT = colors.HexColor("#0f3460")
    C_RED = colors.HexColor("#e94560")
    C_ORANGE = colors.HexColor("#f5a623")
    C_YELLOW = colors.HexColor("#b7950b")
    C_GREEN = colors.HexColor("#27ae60")
    C_WHITE = colors.white
    C_LIGHT = colors.HexColor("#ecf0f1")

    RISK_COLOURS = {
        "Critical": C_RED,
        "Vulnerable": C_ORANGE,
        "Moderate": C_YELLOW,
        "Secure": C_GREEN,
        "Low": C_GREEN,
        "Medium": C_YELLOW,
        "High": C_ORANGE,
    }


def save_pdf_report(
    networks: list[dict],
    scan_meta: dict,
    output_path: str | None = None,
) -> str | None:
    """Generate and save a PDF security assessment report."""
    if not REPORTLAB_AVAILABLE:
        logger.error("ReportLab is not installed. Install it with: pip install reportlab")
        return None

    ensure_dir(OUTPUT_DIR)
    path = output_path or unique_filename(OUTPUT_DIR, "wsa_report", ".pdf")
    target = Path(path)
    ensure_dir(target.parent if target.parent != Path("") else Path("."))

    _generate_pdf(networks, scan_meta, str(target))
    logger.info("PDF report saved", extra={"event": "pdf_report_saved", "path": str(target)})
    return str(target)


def _generate_pdf(networks: list[dict], scan_meta: dict, path: str) -> None:
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
    story.extend(_cover_section(scan_meta, networks, styles))
    story.append(PageBreak())
    story.extend(_executive_summary(networks, styles))
    story.append(PageBreak())
    story.extend(_network_table_section(networks, styles))
    story.append(PageBreak())
    story.extend(_per_network_details(networks, styles))
    story.extend(_recommendations_section(networks, styles))
    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)


def _cover_section(meta: dict, networks: list[dict], styles: dict) -> list:
    timestamp = meta.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    interface = meta.get("interface", "unknown")
    mode = "demo" if meta.get("demo_mode") else "live"
    return [
        Spacer(1, 3 * cm),
        Paragraph(_p(PDF_COMPANY_NAME.upper()), styles["cover_title"]),
        Spacer(1, 0.5 * cm),
        Paragraph("Wireless Security Assessment Report", styles["cover_sub"]),
        Spacer(1, 2 * cm),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT),
        Spacer(1, 0.5 * cm),
        Paragraph(f"Interface: {_p(interface)}", styles["cover_meta"]),
        Paragraph(f"Mode: {_p(mode)}", styles["cover_meta"]),
        Paragraph(f"Scan Date: {_p(timestamp)}", styles["cover_meta"]),
        Paragraph(f"Networks Found: {len(networks)}", styles["cover_meta"]),
        Spacer(1, 2 * cm),
        Paragraph(
            "This report contains sensitive security information. Restrict access to authorised personnel.",
            styles["disclaimer"],
        ),
    ]


def _executive_summary(networks: list[dict], styles: dict) -> list:
    critical = sum(1 for item in networks if item.get("risk", {}).get("label") == "Critical")
    vulnerable = sum(1 for item in networks if item.get("risk", {}).get("label") == "Vulnerable")
    moderate = sum(1 for item in networks if item.get("risk", {}).get("label") == "Moderate")
    secure = sum(1 for item in networks if item.get("risk", {}).get("label") == "Secure")
    avg_score = (
        round(sum(item.get("risk", {}).get("score", 0) for item in networks) / len(networks), 1) if networks else 0
    )

    summary_data = [
        ["Total Networks", str(len(networks))],
        ["Average Risk Score", f"{avg_score} / 100"],
        ["Critical", str(critical)],
        ["Vulnerable", str(vulnerable)],
        ["Moderate", str(moderate)],
        ["Secure", str(secure)],
        ["Open Networks", str(sum(1 for item in networks if item.get("encryption") == "OPEN"))],
        ["WEP Networks", str(sum(1 for item in networks if item.get("encryption") == "WEP"))],
        ["WPS Enabled", str(sum(1 for item in networks if item.get("wps")))],
    ]
    table = Table(summary_data, colWidths=[8 * cm, 5 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), C_PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_LIGHT, C_WHITE]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return [Paragraph("Executive Summary", styles["h1"]), Spacer(1, 0.3 * cm), table, Spacer(1, 0.5 * cm)]


def _network_table_section(networks: list[dict], styles: dict) -> list:
    rows = [["#", "SSID", "BSSID", "Signal", "Enc", "WPS", "Score", "Risk"]]
    for index, network in enumerate(networks, 1):
        risk = network.get("risk", {})
        rows.append(
            [
                str(index),
                _t(network.get("ssid", "<hidden>"), limit=40),
                _t(network.get("bssid", "")),
                f"{network.get('signal', -100)} dBm",
                _t(network.get("encryption", "?")),
                "Yes" if network.get("wps") else "No",
                str(risk.get("score", 0)),
                _t(risk.get("label", "?")),
            ]
        )

    table = Table(
        rows, colWidths=[0.6 * cm, 4.5 * cm, 4.0 * cm, 2.2 * cm, 1.8 * cm, 1.4 * cm, 1.6 * cm, 2.5 * cm], repeatRows=1
    )
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), C_PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (1, 0), (-1, -1), [C_LIGHT, C_WHITE]),
    ]
    for row_index, network in enumerate(networks, 1):
        label = network.get("risk", {}).get("label", "")
        colour = RISK_COLOURS.get(label, colors.grey)
        style.extend(
            [
                ("BACKGROUND", (7, row_index), (7, row_index), colour),
                ("TEXTCOLOR", (7, row_index), (7, row_index), C_WHITE),
                ("FONTNAME", (7, row_index), (7, row_index), "Helvetica-Bold"),
            ]
        )
    table.setStyle(TableStyle(style))
    return [Paragraph("Network Overview", styles["h1"]), Spacer(1, 0.3 * cm), table, Spacer(1, 0.5 * cm)]


def _per_network_details(networks: list[dict], styles: dict) -> list:
    story = [Paragraph("Detailed Network Analysis", styles["h1"]), Spacer(1, 0.3 * cm)]

    for network in networks:
        risk = network.get("risk", {})
        label = risk.get("label", "Unknown")
        score = risk.get("score", 0)
        colour = RISK_COLOURS.get(label, colors.grey)

        header_table = Table(
            [
                [
                    f"{_t(network.get('ssid', '<hidden>'))} | {_t(network.get('bssid', ''))}",
                    f"Score: {score}/100 | {_t(label)}",
                ]
            ],
            colWidths=[11 * cm, 7 * cm],
        )
        header_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), C_PRIMARY),
                    ("TEXTCOLOR", (0, 0), (-1, -1), C_WHITE),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("BACKGROUND", (1, 0), (1, 0), colour),
                ]
            )
        )
        story.append(KeepTogether([header_table]))

        for finding in _all_findings(network):
            finding_table = _finding_table(finding, styles)
            story.append(Spacer(1, 2 * mm))
            story.append(finding_table)

        story.append(Spacer(1, 0.5 * cm))

    return story


def _finding_table(finding: dict, styles: dict) -> Table:
    colour = RISK_COLOURS.get(finding.get("risk_level", ""), colors.grey)
    title = finding.get("vulnerability") or finding.get("check", "")
    data = [
        [f"* {_t(title)}", _t(finding.get("risk_level", ""))],
        [Paragraph(_p(finding.get("description", ""), limit=2500), styles["body_small"]), ""],
        [
            Paragraph(
                f"<b>Scenario:</b> {_p(finding.get('unauthorized_access_scenario', ''), limit=3000)}",
                styles["scenario"],
            ),
            "",
        ],
        [Paragraph(f"<b>Recommendation:</b> {_p(finding.get('recommendation', ''), limit=2500)}", styles["rec"]), ""],
    ]
    table = Table(data, colWidths=[15.5 * cm, 2.5 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), C_ACCENT),
                ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (1, 0), (1, 0), colour),
                ("TEXTCOLOR", (1, 0), (1, 0), C_WHITE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
            ]
        )
    )
    return table


def _recommendations_section(networks: list[dict], styles: dict) -> list:
    seen: set[str] = set()
    recommendations: list[str] = []
    for network in networks:
        for finding in _all_findings(network):
            recommendation = finding.get("recommendation", "")
            if recommendation and recommendation not in seen:
                seen.add(recommendation)
                recommendations.append(recommendation)

    story = [PageBreak(), Paragraph("Consolidated Recommendations", styles["h1"]), Spacer(1, 0.3 * cm)]
    for index, recommendation in enumerate(recommendations, 1):
        story.append(Paragraph(f"{index}. {_p(recommendation, limit=2500)}", styles["rec"]))
        story.append(Spacer(1, 2 * mm))
    return story


def _all_findings(network: dict) -> list[dict]:
    findings = []
    encryption = network.get("encryption_analysis", {})
    if encryption:
        findings.append(encryption)
    findings.extend(network.get("config_findings", []))
    findings.extend(network.get("rogue_findings", []))
    return findings


def _page_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(2 * cm, 1.5 * cm, f"{TOOL_NAME} v{TOOL_VERSION}")
    canvas.drawRightString(A4[0] - 2 * cm, 1.5 * cm, f"CONFIDENTIAL | Page {doc.page}")
    canvas.restoreState()


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title", parent=base["Title"], fontSize=28, textColor=C_PRIMARY, spaceAfter=6, alignment=TA_CENTER
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", parent=base["Normal"], fontSize=16, textColor=C_HIGHLIGHT, spaceAfter=4, alignment=TA_CENTER
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta", parent=base["Normal"], fontSize=11, textColor=C_ACCENT, spaceAfter=3, alignment=TA_CENTER
        ),
        "disclaimer": ParagraphStyle(
            "disclaimer", parent=base["Normal"], fontSize=9, textColor=C_RED, alignment=TA_CENTER, borderPad=4
        ),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=14, textColor=C_PRIMARY, spaceAfter=6),
        "body_small": ParagraphStyle("body_small", parent=base["Normal"], fontSize=8, leading=11),
        "scenario": ParagraphStyle(
            "scenario", parent=base["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#7f4f00")
        ),
        "rec": ParagraphStyle(
            "rec", parent=base["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#1a5276")
        ),
    }


def _p(value: object, *, limit: int = 1000) -> str:
    return html_escape(safe_console_text(value, limit=limit))


def _t(value: object, *, limit: int = 120) -> str:
    return safe_console_text(value, limit=limit)
