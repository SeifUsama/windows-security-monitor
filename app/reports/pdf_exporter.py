"""
app/reports/pdf_exporter.py
-----------------------------
Generates PDF incident reports using ReportLab.

Report structure:
  - Header: Application name, generation timestamp
  - Incident Summary table
  - Detection Explanation
  - Attack Timeline
  - Related Events table
"""

from pathlib import Path
from typing import List, Any, Optional
from datetime import datetime

from app.utils.logger import log

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    log.warning("ReportLab not available — PDF export disabled")


# Color palette matching the app's theme
COLOR_CRITICAL = colors.HexColor("#dc3545")
COLOR_HIGH     = colors.HexColor("#fd7e14")
COLOR_MEDIUM   = colors.HexColor("#ffc107")
COLOR_LOW      = colors.HexColor("#28a745")
COLOR_INFO     = colors.HexColor("#6c757d")
COLOR_DARK     = colors.HexColor("#1a1a2e")
COLOR_HEADER   = colors.HexColor("#16213e")
COLOR_ACCENT   = colors.HexColor("#0f3460")


def _severity_color(severity: str):
    return {
        "CRITICAL": COLOR_CRITICAL,
        "HIGH":     COLOR_HIGH,
        "MEDIUM":   COLOR_MEDIUM,
        "LOW":      COLOR_LOW,
    }.get(severity.upper(), COLOR_INFO)


def export_incident_to_pdf(
    incident: Any,
    related_events: List[Any],
    output_path: str,
) -> bool:
    """
    Generate a PDF incident report.
    Returns True on success, False if ReportLab is unavailable or an error occurs.
    """
    if not REPORTLAB_AVAILABLE:
        log.warning("PDF export skipped: ReportLab not installed")
        return False

    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        inc = dict(incident) if hasattr(incident, "keys") else incident
        doc = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )
        styles = getSampleStyleSheet()
        story  = []

        # --- Title ---
        title_style = ParagraphStyle(
            "Title", parent=styles["Title"],
            textColor=COLOR_DARK, fontSize=18, spaceAfter=6,
        )
        sub_style = ParagraphStyle(
            "Sub", parent=styles["Normal"],
            textColor=colors.HexColor("#555555"), fontSize=9, spaceAfter=12,
        )
        story.append(Paragraph("Windows Security Monitor", title_style))
        story.append(Paragraph("Incident Investigation Report", title_style))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"Report for Incident #{inc.get('id', 'N/A')}",
            sub_style
        ))
        story.append(HRFlowable(width="100%", color=COLOR_ACCENT, thickness=2))
        story.append(Spacer(1, 0.4*cm))

        # --- Incident Summary Table ---
        sev = inc.get("severity", "INFO")
        sev_color = _severity_color(sev)

        heading_style = ParagraphStyle(
            "Heading", parent=styles["Heading2"],
            textColor=COLOR_DARK, fontSize=12, spaceBefore=10, spaceAfter=6,
        )
        story.append(Paragraph("Incident Summary", heading_style))

        summary_data = [
            ["Field", "Value"],
            ["Incident ID",     str(inc.get("id", "N/A"))],
            ["Attack Type",     inc.get("attack_type", "-")],
            ["Severity",        sev],
            ["Status",          inc.get("status", "-")],
            ["Source IP",       inc.get("source_ip") or "Not Available"],
            ["Target Username", inc.get("username") or "-"],
            ["First Seen",      str(inc.get("first_seen", "-"))],
            ["Last Seen",       str(inc.get("last_seen", "-"))],
            ["Event Count",     str(inc.get("event_count", 0))],
            ["Detection Rule",  inc.get("detection_rule", "-")],
            ["Demo Data",       "Yes (Simulated)" if inc.get("is_demo") else "No (Real Windows Logs)"],
        ]

        tbl = Table(summary_data, colWidths=[5*cm, 12*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), COLOR_HEADER),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 10),
            ("BACKGROUND",   (0, 2), (-1, 2), sev_color),  # Severity row
            ("TEXTCOLOR",    (0, 2), (-1, 2), colors.white),
            ("FONTNAME",     (0, 2), (-1, 2), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
            ("FONTSIZE",     (0, 1), (-1, -1), 9),
            ("FONTNAME",     (0, 1), (0, -1), "Helvetica-Bold"),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 0.5*cm))

        # --- Description ---
        story.append(Paragraph("Incident Description", heading_style))
        body_style = ParagraphStyle(
            "Body", parent=styles["Normal"], fontSize=9, leading=14, spaceAfter=8,
        )
        story.append(Paragraph(inc.get("description", "-"), body_style))
        story.append(Spacer(1, 0.3*cm))

        # --- Detection Explanation ---
        story.append(Paragraph("Detection Explanation", heading_style))
        code_style = ParagraphStyle(
            "Code", parent=styles["Code"],
            fontSize=8, leading=12, backColor=colors.HexColor("#f4f4f4"),
            leftIndent=10, rightIndent=10, spaceAfter=8,
        )
        reason = inc.get("detection_reason", "-").replace("\n", "<br/>")
        story.append(Paragraph(reason, code_style))
        story.append(Spacer(1, 0.3*cm))

        # --- Attack Timeline ---
        if related_events:
            story.append(Paragraph("Attack Timeline", heading_style))
            timeline_data = [["#", "Timestamp", "Event ID", "Description", "Username", "Source IP"]]
            for i, ev in enumerate(related_events, 1):
                e = dict(ev) if hasattr(ev, "keys") else ev
                timeline_data.append([
                    str(i),
                    str(e.get("timestamp", ""))[:19],
                    str(e.get("event_id", "-")),
                    (e.get("description") or e.get("message", "-"))[:40],
                    e.get("username") or "-",
                    e.get("source_ip") or "-",
                ])

            tbl2 = Table(
                timeline_data,
                colWidths=[0.8*cm, 3.5*cm, 1.5*cm, 6*cm, 2.5*cm, 2.7*cm],
            )
            tbl2.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), COLOR_ACCENT),
                ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff3cd"), colors.white]),
                ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ]))
            story.append(tbl2)
            story.append(Spacer(1, 0.5*cm))

        # --- Footer note ---
        footer_style = ParagraphStyle(
            "Footer", parent=styles["Normal"],
            fontSize=7, textColor=colors.grey, alignment=1,
        )
        demo_note = " [DEMO DATA — Simulated events for academic demonstration]" if inc.get("is_demo") else ""
        story.append(HRFlowable(width="100%", color=colors.lightgrey, thickness=0.5))
        story.append(Paragraph(
            f"Windows Security Monitor | Fundamentals of Cybersecurity Project{demo_note}",
            footer_style
        ))

        doc.build(story)
        log.info("PDF incident report saved to %s", output_path)
        return True

    except Exception as e:
        log.error("PDF export failed: %s", e)
        return False
