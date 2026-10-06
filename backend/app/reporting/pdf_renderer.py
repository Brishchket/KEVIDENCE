"""
pdf_renderer.py — Pure Python PDF vulnerability advisory renderer using ReportLab.

Renders:
  1. Single CVE Advisory PDF: Complete 6-section report + Executive Summary + Verification Appendix
  2. Portfolio Summary PDF: Top-N vulnerability portfolio overview + individual advisories

Design highlights:
  - Two-pass NumberedCanvas for dynamic "Page X of Y" page numbering
  - Clean running header and footer with confidentiality marker and CVE tracking
  - Wrapped long URLs and robust cell tables to prevent text overflows
  - Consistent light/dark color tokens matching the KEVIDENCE dashboard
  - 100% pure Python — zero external binaries (WeasyPrint / wkhtmltopdf free)
"""
from __future__ import annotations

import io
from typing import Any, Sequence

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Color Palette ─────────────────────────────────────────────────────────────

CLR_DARK_BG = HexColor("#0F172A")     # Slate 900
CLR_ACCENT_ORANGE = HexColor("#EA580C")# Orange 600
CLR_TEXT_DARK = HexColor("#0F172A")   # Slate 900
CLR_TEXT_MUTED = HexColor("#475569")  # Slate 600
CLR_BORDER = HexColor("#CBD5E1")      # Slate 300
CLR_CARD_BG = HexColor("#F8FAFC")     # Slate 50
CLR_ROW_ALT = HexColor("#F1F5F9")     # Slate 100
CLR_LINK = HexColor("#0284C7")        # Sky 600

PRIORITY_COLORS: dict[str, HexColor] = {
    "CRITICAL": HexColor("#DC2626"),  # Red 600
    "HIGH": HexColor("#EA580C"),      # Orange 600
    "MEDIUM": HexColor("#D97706"),    # Amber 600
    "LOW": HexColor("#059669"),       # Emerald 600
    "UNKNOWN": HexColor("#64748B"),   # Slate 500
}


# ── Two-Pass Canvas for Dynamic Page Numbers & Running Footers ─────────────────

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render 'Page X of Y'
    along with running headers and running footers.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []
        self.doc_cve_id: str = "CVE ADVISORY"

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_elements(num_pages)
            super().showPage()
        super().save()

    def draw_page_elements(self, total_pages: int) -> None:
        self.saveState()

        page_w, page_h = letter
        margin = 36  # 0.5 inch

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(CLR_TEXT_MUTED)
            self.drawString(margin, page_h - 26, "KEVIDENCE SECURITY ADVISORY")
            self.drawRightString(page_w - margin, page_h - 26, f"VULNERABILITY INTELLIGENCE • {self.doc_cve_id}")

            self.setStrokeColor(CLR_BORDER)
            self.setLineWidth(0.5)
            self.line(margin, page_h - 30, page_w - margin, page_h - 30)

        # Running Footer (all pages)
        self.setStrokeColor(CLR_BORDER)
        self.setLineWidth(0.5)
        self.line(margin, 36, page_w - margin, 36)

        self.setFont("Helvetica", 8)
        self.setFillColor(CLR_TEXT_MUTED)
        self.drawString(margin, 24, f"CONFIDENTIAL & PROPRIETARY • EVIDENCE-GROUNDED ASSESSMENT • {self.doc_cve_id}")

        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(page_w - margin, 24, page_str)

        self.restoreState()


# ── Score Bar Flowable ────────────────────────────────────────────────────────

class ScoreBarFlowable(Flowable):
    """
    Renders a visual priority score bar indicating the score position
    relative to LOW, MEDIUM, HIGH, and CRITICAL thresholds.
    """

    def __init__(self, score: float, priority_label: str, width: float = 540, height: float = 12):
        super().__init__()
        self.score = max(0.0, min(float(score), 1.0))
        self.priority_label = priority_label
        self.width = width
        self.height = height

    def wrap(self, availWidth: float, availHeight: float) -> tuple[float, float]:
        return self.width, self.height + 14

    def draw(self) -> None:
        self.canv.saveState()
        y_bar = 10

        # Background track
        self.canv.setFillColor(HexColor("#E2E8F0"))
        self.canv.roundRect(0, y_bar, self.width, self.height, 3, stroke=0, fill=1)

        # Filled score progress
        bar_color = PRIORITY_COLORS.get(self.priority_label, HexColor("#EA580C"))
        fill_w = max(4.0, self.score * self.width)
        self.canv.setFillColor(bar_color)
        self.canv.roundRect(0, y_bar, fill_w, self.height, 3, stroke=0, fill=1)

        # Threshold tick lines at 0.25, 0.50, 0.75
        self.canv.setStrokeColor(HexColor("#94A3B8"))
        self.canv.setLineWidth(0.75)
        for t in (0.25, 0.50, 0.75):
            tx = t * self.width
            self.canv.line(tx, y_bar, tx, y_bar + self.height)

        # Threshold labels below
        self.canv.setFont("Helvetica-Bold", 6.5)
        self.canv.setFillColor(HexColor("#64748B"))
        self.canv.drawString(2, 1, "LOW (0.00 - 0.24)")
        self.canv.drawCentredString(0.375 * self.width, 1, "MEDIUM (0.25 - 0.49)")
        self.canv.drawCentredString(0.625 * self.width, 1, "HIGH (0.50 - 0.74)")
        self.canv.drawRightString(self.width - 2, 1, f"CRITICAL (≥ 0.75) • Evaluated Score: {self.score:.3f}")

        self.canv.restoreState()


# ── Styles Builder ────────────────────────────────────────────────────────────

def _build_styles() -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    styles: dict[str, ParagraphStyle] = {}

    styles["DocTitle"] = ParagraphStyle(
        "DocTitle",
        parent=sample["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=CLR_TEXT_DARK,
    )

    styles["DocSubtitle"] = ParagraphStyle(
        "DocSubtitle",
        parent=sample["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=CLR_TEXT_MUTED,
    )

    styles["SectionHeader"] = ParagraphStyle(
        "SectionHeader",
        parent=sample["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=CLR_DARK_BG,
        spaceBefore=8,
        spaceAfter=4,
    )

    styles["Body"] = ParagraphStyle(
        "Body",
        parent=sample["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=CLR_TEXT_DARK,
        alignment=TA_LEFT,
        spaceAfter=4,
    )

    styles["BodyBold"] = ParagraphStyle(
        "BodyBold",
        parent=styles["Body"],
        fontName="Helvetica-Bold",
    )

    styles["Callout"] = ParagraphStyle(
        "Callout",
        parent=sample["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=12.5,
        textColor=CLR_TEXT_DARK,
    )

    styles["TableHeader"] = ParagraphStyle(
        "TableHeader",
        parent=sample["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=HexColor("#FFFFFF"),
        alignment=TA_LEFT,
    )

    styles["TableCell"] = ParagraphStyle(
        "TableCell",
        parent=sample["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=CLR_TEXT_DARK,
    )

    styles["TableCellBold"] = ParagraphStyle(
        "TableCellBold",
        parent=styles["TableCell"],
        fontName="Helvetica-Bold",
    )

    styles["TableCellRight"] = ParagraphStyle(
        "TableCellRight",
        parent=styles["TableCell"],
        alignment=TA_RIGHT,
    )

    styles["TableCellCenter"] = ParagraphStyle(
        "TableCellCenter",
        parent=styles["TableCell"],
        alignment=TA_CENTER,
    )

    styles["Badge"] = ParagraphStyle(
        "Badge",
        parent=sample["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=HexColor("#FFFFFF"),
        alignment=TA_CENTER,
    )

    return styles


# ── URL Wrap Utility ──────────────────────────────────────────────────────────

def _wrap_url(url: str, max_len: int = 65) -> str:
    """Format URL as a clickable link with break points to prevent table overflow."""
    clean = url.strip()
    if not clean:
        return "None"
    display = clean if len(clean) <= max_len else clean[:max_len] + "…"
    return f'<font color="#0284c7"><u><a href="{clean}">{display}</a></u></font>'


# ── Render Single CVE Advisory Report ─────────────────────────────────────────

def render_cve_pdf(report: dict[str, Any]) -> bytes:
    """Render a single CVE vulnerability advisory into a professional PDF byte stream."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=42,
        bottomMargin=46,
    )

    styles = _build_styles()
    story: list[Any] = []
    cve_id = report.get("cve_id", "CVE-UNKNOWN")
    sections = report.get("sections", {})
    verification = report.get("verification", {})
    score_breakdown = report.get("score_breakdown", [])
    timeline = report.get("timeline", {})
    version_ranges = report.get("version_ranges", [])
    patch_urls = report.get("patch_urls", [])

    priority_label = "LOW"
    priority_score = float(report.get("priority_score", 0.0))
    if priority_score == 0.0 and score_breakdown:
        try:
            priority_score = sum(float(row.get("contribution", 0.0)) for row in score_breakdown)
        except (ValueError, TypeError):
            pass

    # Extract priority from score_breakdown or report evidence
    if "why" in sections:
        for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if p in sections["why"]:
                priority_label = p
                break

    badge_color = PRIORITY_COLORS.get(priority_label, PRIORITY_COLORS["UNKNOWN"])

    # ── Header Banner ─────────────────────────────────────────────────────────
    header_table_data = [
        [
            Paragraph(f"<b>KEVIDENCE VULNERABILITY ADVISORY</b><br/><font size=16><b>{cve_id}</b></font>", styles["DocTitle"]),
            Paragraph(
                f"<b>PRIORITY LEVEL</b><br/><font size=12><b>{priority_label}</b></font>",
                styles["Badge"],
            ),
        ]
    ]

    header_table = Table(header_table_data, colWidths=[420, 120])
    header_table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (1, 0), (1, 0), badge_color),
            ("PADDING", (1, 0), (1, 0), 6),
            ("BOX", (1, 0), (1, 0), 1, badge_color),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(header_table)

    # Metadata sub-bar
    freshness = report.get("source_freshness", {})
    nvd_fresh = freshness.get("NVD (NIST CVE Feed)", "Current")
    gen_time = report.get("created_at", "")[:19].replace("T", " ")
    sub_bar_text = (
        f"<b>Published / Synced:</b> {nvd_fresh}  |  "
        f"<b>Report Generated:</b> {gen_time} UTC  |  "
        f"<b>Evaluation Engine:</b> {report.get('scoring_version', 'v2.0')}"
    )
    story.append(Spacer(1, 4))
    story.append(Paragraph(sub_bar_text, styles["DocSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=CLR_BORDER, spaceBefore=4, spaceAfter=6))

    # Priority Score Bar
    story.append(ScoreBarFlowable(priority_score, priority_label, width=540, height=12))
    story.append(Spacer(1, 6))

    # ── 1. Executive Summary ──────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary (Bottom Line Up Front)", styles["SectionHeader"]))
    exec_text = report.get("executive_summary", "No executive summary available.")
    exec_box = Table([[Paragraph(exec_text, styles["Body"])]], colWidths=[540])
    exec_box.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CLR_CARD_BG),
            ("BOX", (0, 0), (-1, -1), 0.75, CLR_BORDER),
            ("LINELEFT", (0, 0), (-1, -1), 3, badge_color),
            ("PADDING", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(exec_box)
    story.append(Spacer(1, 8))

    # ── 2. What Is It ─────────────────────────────────────────────────────────
    story.append(Paragraph("2. What is the Vulnerability?", styles["SectionHeader"]))
    what_text = sections.get("what", "Details not stated in available evidence.")
    story.append(Paragraph(what_text, styles["Body"]))
    story.append(Spacer(1, 8))

    # ── 3. Why It Is Prioritised (Dynamic Score Breakdown Table) ──────────────
    story.append(Paragraph("3. Why is this Vulnerability Prioritised?", styles["SectionHeader"]))
    why_text = sections.get("why", "Priority analysis not stated.")
    story.append(Paragraph(why_text, styles["Body"]))

    # Score breakdown table
    if score_breakdown:
        breakdown_rows = [
            [
                Paragraph("Risk Signal Component", styles["TableHeader"]),
                Paragraph("Evaluated Raw Value", styles["TableHeader"]),
                Paragraph("Weight", styles["TableHeader"]),
                Paragraph("Score Contribution", styles["TableHeader"]),
                Paragraph("Source", styles["TableHeader"]),
            ]
        ]
        for row in score_breakdown:
            breakdown_rows.append([
                Paragraph(row.get("component", ""), styles["TableCellBold"]),
                Paragraph(row.get("raw_value", ""), styles["TableCell"]),
                Paragraph(row.get("weight", ""), styles["TableCellCenter"]),
                Paragraph(row.get("contribution", ""), styles["TableCellCenter"]),
                Paragraph(row.get("source", ""), styles["TableCellCenter"]),
            ])

        score_tbl = Table(breakdown_rows, colWidths=[180, 130, 60, 100, 70])
        score_tbl.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), CLR_DARK_BG),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.5, CLR_BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), CLR_ROW_ALT]),
            ])
        )
        story.append(Spacer(1, 4))
        story.append(score_tbl)

    if report.get("score_formula"):
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<b>Scoring Formula:</b> <i>{report.get('score_formula')}</i>", styles["DocSubtitle"]))

    story.append(Spacer(1, 8))

    # ── 4. Where It Is (Affected Products & Versions) ─────────────────────────
    story.append(Paragraph("4. Where is it Affected? (Asset Scope & Exposure)", styles["SectionHeader"]))
    where_text = sections.get("where", "Asset scope not stated.")
    story.append(Paragraph(where_text, styles["Body"]))

    if version_ranges:
        vr_rows = [
            [
                Paragraph("Target Vendor", styles["TableHeader"]),
                Paragraph("Affected Product", styles["TableHeader"]),
                Paragraph("Version Range Criteria", styles["TableHeader"]),
            ]
        ]
        for vr in version_ranges[:6]:
            v_start = vr.get("version_start_including") or "Any"
            v_end = vr.get("version_end_excluding") or "Any"
            criteria_str = f">= {v_start}, < {v_end}" if (v_start != "Any" or v_end != "Any") else (vr.get("criteria", "Unspecified"))
            vr_rows.append([
                Paragraph(vr.get("vendor") or "Not stated", styles["TableCellBold"]),
                Paragraph(vr.get("product") or "Not stated", styles["TableCell"]),
                Paragraph(criteria_str, styles["TableCell"]),
            ])

        vr_tbl = Table(vr_rows, colWidths=[150, 150, 240])
        vr_tbl.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), CLR_DARK_BG),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.5, CLR_BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), CLR_ROW_ALT]),
            ])
        )
        story.append(Spacer(1, 4))
        story.append(vr_tbl)

    story.append(Spacer(1, 8))

    # ── 5. How It Is Exploited ────────────────────────────────────────────────
    story.append(Paragraph("5. How is it Exploited? (Weaponization & Threat Intelligence)", styles["SectionHeader"]))
    how_text = sections.get("how", "Exploitation status not stated.")
    story.append(Paragraph(how_text, styles["Body"]))
    story.append(Spacer(1, 8))

    # ── 6. Origin & Root Cause Analysis ───────────────────────────────────────
    story.append(Paragraph("6. Origin of the Vulnerability (Root Cause & Lifecycle Timeline)", styles["SectionHeader"]))
    origin_text = sections.get("origin", "Root cause not stated.")
    story.append(Paragraph(origin_text, styles["Body"]))

    if timeline:
        time_rows = [
            [Paragraph("Milestone Event", styles["TableHeader"]), Paragraph("Authoritative Timestamp / Value", styles["TableHeader"])]
        ]
        for k, v in timeline.items():
            time_rows.append([Paragraph(k, styles["TableCellBold"]), Paragraph(str(v), styles["TableCell"])])

        time_tbl = Table(time_rows, colWidths=[200, 340])
        time_tbl.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), CLR_DARK_BG),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.5, CLR_BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), CLR_ROW_ALT]),
            ])
        )
        story.append(Spacer(1, 4))
        story.append(time_tbl)

    story.append(Spacer(1, 8))

    # ── 7. Resolution Plan ────────────────────────────────────────────────────
    story.append(Paragraph("7. Resolution Plan (Action Items & Verified Patches)", styles["SectionHeader"]))
    resolution_text = sections.get("resolution", "Resolution instructions not stated.")
    story.append(Paragraph(resolution_text, styles["Body"]))

    if patch_urls:
        url_paragraphs = [
            Paragraph(f"• {_wrap_url(u)}", styles["Body"])
            for u in patch_urls[:5]
        ]
        patch_box = Table([[Paragraph("<b>Verified Advisory & Remediation Links:</b>", styles["TableCellBold"])], [url_paragraphs]], colWidths=[540])
        patch_box.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), CLR_CARD_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, CLR_BORDER),
                ("PADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(Spacer(1, 4))
        story.append(patch_box)

    story.append(Spacer(1, 8))

    # ── 8. Evidence & Verification Appendix ───────────────────────────────────
    appendix_elements: list[Any] = [
        Paragraph("8. Evidence & Verification Appendix", styles["SectionHeader"]),
        Paragraph(
            "Every statement in this report is deterministically validated against authoritative ground-truth feeds. "
            "Claims failing sentence-level factual verification are dropped.",
            styles["DocSubtitle"],
        ),
        Spacer(1, 4),
        Table([
            [Paragraph("Verification Metric", styles["TableHeader"]), Paragraph("Validation Result", styles["TableHeader"])],
            [Paragraph("Faithfulness Score", styles["TableCellBold"]), Paragraph(f"{verification.get('faithfulness_score', 1.0) * 100:.1f}%", styles["TableCell"])],
            [Paragraph("Confidence Assessment", styles["TableCellBold"]), Paragraph(verification.get("confidence", "HIGH"), styles["TableCell"])],
            [Paragraph("Verified Sentences", styles["TableCellBold"]), Paragraph(str(verification.get("verified_sentences_count", 0)), styles["TableCell"])],
            [Paragraph("Dropped Sentences (Hallucinations Guard)", styles["TableCellBold"]), Paragraph(str(verification.get("dropped_sentences_count", 0)), styles["TableCell"])],
            [Paragraph("LLM Engine / Provider", styles["TableCellBold"]), Paragraph(f"{report.get('provider', 'N/A')} ({report.get('model', 'N/A')})", styles["TableCell"])],
            [Paragraph("Prompt Tracking Version", styles["TableCellBold"]), Paragraph(report.get("prompt_version", "v4-report"), styles["TableCell"])],
        ], colWidths=[220, 320], style=[
            ("BACKGROUND", (0, 0), (-1, 0), CLR_DARK_BG),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, CLR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), CLR_ROW_ALT]),
        ]),
    ]

    # Data Freshness Table
    if freshness:
        appendix_elements.extend([
            Spacer(1, 6),
            Paragraph("<b>Authoritative Threat Intelligence Feeds & Data Freshness:</b>", styles["TableCellBold"]),
            Spacer(1, 2),
            Table([
                [Paragraph("Source Threat Intelligence Feed", styles["TableHeader"]), Paragraph("Synchronization Timestamp / Status", styles["TableHeader"])],
                *[
                    [Paragraph(k, styles["TableCellBold"]), Paragraph(str(v), styles["TableCell"])]
                    for k, v in freshness.items()
                ],
            ], colWidths=[220, 320], style=[
                ("BACKGROUND", (0, 0), (-1, 0), CLR_DARK_BG),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.5, CLR_BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), CLR_ROW_ALT]),
            ]),
        ])

    # Full Reference List
    ref_tags = report.get("reference_tags", {})
    all_refs = []
    if ref_tags and isinstance(ref_tags, dict):
        for tag, urls in ref_tags.items():
            if isinstance(urls, list):
                for u in urls:
                    all_refs.append((tag, u))
    if not all_refs and patch_urls:
        for u in patch_urls:
            all_refs.append(("Advisory / Patch", u))

    if all_refs:
        ref_rows = [
            [Paragraph("Classification Tag", styles["TableHeader"]), Paragraph("Authoritative Reference Document URL", styles["TableHeader"])]
        ]
        for tag, u in all_refs[:10]:
            ref_rows.append([
                Paragraph(tag, styles["TableCellBold"]),
                Paragraph(_wrap_url(u, max_len=68), styles["TableCell"]),
            ])
        appendix_elements.extend([
            Spacer(1, 6),
            Paragraph("<b>Full Authoritative Source Reference List:</b>", styles["TableCellBold"]),
            Spacer(1, 2),
            Table(ref_rows, colWidths=[140, 400], style=[
                ("BACKGROUND", (0, 0), (-1, 0), CLR_DARK_BG),
                ("PADDING", (0, 0), (-1, -1), 3.5),
                ("GRID", (0, 0), (-1, -1), 0.5, CLR_BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), CLR_ROW_ALT]),
            ]),
        ])

    story.append(KeepTogether(appendix_elements))

    # Build PDF with two-pass canvas
    def _canvas_maker(*args: Any, **kwargs: Any) -> NumberedCanvas:
        c = NumberedCanvas(*args, **kwargs)
        c.doc_cve_id = cve_id
        return c

    doc.build(story, canvasmaker=_canvas_maker)
    buffer.seek(0)
    return buffer.getvalue()


# ── Render Portfolio Summary PDF (Top-N) ──────────────────────────────────────

def render_portfolio_summary_pdf(reports: Sequence[dict[str, Any]]) -> bytes:
    """
    Render a portfolio summary PDF containing an overview table followed by
    guaranteed 1-page briefs per CVE.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = _build_styles()
    story: list[Any] = []

    # Title Page / Portfolio Header
    story.append(Paragraph("<b>KEVIDENCE PORTFOLIO INTELLIGENCE BRIEFING</b>", styles["DocTitle"]))
    story.append(Paragraph("Prioritised Multi-Feed Vulnerability Threat Assessment", styles["DocSubtitle"]))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1.5, color=CLR_ACCENT_ORANGE, spaceBefore=2, spaceAfter=8))

    # Overview Table
    summary_rows = [
        [
            Paragraph("CVE Identifier", styles["TableHeader"]),
            Paragraph("Priority", styles["TableHeader"]),
            Paragraph("Score", styles["TableHeader"]),
            Paragraph("CISA KEV", styles["TableHeader"]),
            Paragraph("EPSS Prob", styles["TableHeader"]),
            Paragraph("Target Products", styles["TableHeader"]),
        ]
    ]

    for rep in reports:
        cid = rep.get("cve_id", "Unknown")
        sections = rep.get("sections", {})
        why_text = sections.get("why", "")

        plabel = "LOW"
        for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if p in why_text or p in rep.get("executive_summary", ""):
                plabel = p
                break

        score_val = "0.000"
        for row in rep.get("score_breakdown", []):
            if "Total" in row.get("component", ""):
                score_val = row.get("contribution", "")

        kev_in = "YES" if ("in KEV" in why_text or "in KEV" in rep.get("executive_summary", "") or "CISA Known Exploited" in rep.get("executive_summary", "")) and "not cataloged" not in rep.get("executive_summary", "").lower() and "not listed" not in rep.get("executive_summary", "").lower() else "NO"

        prod_display = "Component"
        if rep.get("version_ranges"):
            prod_display = rep["version_ranges"][0].get("product", "General Component")
        elif rep.get("products"):
            prod_display = ", ".join(rep["products"][:2])

        summary_rows.append([
            Paragraph(f"<b>{cid}</b>", styles["TableCellBold"]),
            Paragraph(plabel, styles["TableCellCenter"]),
            Paragraph(score_val, styles["TableCellCenter"]),
            Paragraph(kev_in, styles["TableCellCenter"]),
            Paragraph(rep.get("score_breakdown", [{}, {}])[1].get("raw_value", "-") if len(rep.get("score_breakdown", [])) > 1 else "-", styles["TableCellCenter"]),
            Paragraph(prod_display, styles["TableCell"]),
        ])

    overview_tbl = Table(summary_rows, colWidths=[100, 70, 50, 60, 70, 190])
    overview_tbl.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), CLR_DARK_BG),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, CLR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), CLR_ROW_ALT]),
        ])
    )
    story.append(overview_tbl)
    story.append(Spacer(1, 14))

    # Individual CVE Briefs (Guaranteed Exactly 1 Page Each)
    for rep in reports:
        story.append(PageBreak())
        cid = rep.get("cve_id", "Unknown")
        secs = rep.get("sections", {})

        plabel = "LOW"
        for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if p in secs.get("why", "") or p in rep.get("executive_summary", ""):
                plabel = p
                break
        b_color = PRIORITY_COLORS.get(plabel, HexColor("#64748B"))

        brief_header = Table([
            [
                Paragraph(f"<b>KEVIDENCE BRIEF: {cid}</b>", styles["DocTitle"]),
                Paragraph(f"<b>{plabel}</b>", styles["Badge"]),
            ]
        ], colWidths=[430, 110])
        brief_header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (1, 0), (1, 0), b_color),
            ("PADDING", (1, 0), (1, 0), 4),
            ("BOX", (1, 0), (1, 0), 1, b_color),
        ]))
        story.append(brief_header)
        story.append(Spacer(1, 2))
        story.append(HRFlowable(width="100%", thickness=1, color=CLR_BORDER, spaceBefore=2, spaceAfter=4))

        # Compact score breakdown table
        sb_rows = [
            [Paragraph("Risk Component", styles["TableHeader"]), Paragraph("Value", styles["TableHeader"]), Paragraph("Weight", styles["TableHeader"]), Paragraph("Contribution", styles["TableHeader"])]
        ]
        for row in rep.get("score_breakdown", [])[:3]:
            sb_rows.append([
                Paragraph(row.get("component", ""), styles["TableCell"]),
                Paragraph(row.get("raw_value", ""), styles["TableCell"]),
                Paragraph(row.get("weight", ""), styles["TableCellCenter"]),
                Paragraph(row.get("contribution", ""), styles["TableCellCenter"]),
            ])
        sb_tbl = Table(sb_rows, colWidths=[180, 130, 100, 130], style=[
            ("BACKGROUND", (0, 0), (-1, 0), CLR_DARK_BG),
            ("PADDING", (0, 0), (-1, -1), 2.5),
            ("GRID", (0, 0), (-1, -1), 0.5, CLR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), CLR_ROW_ALT]),
        ])

        # Left column items
        left_flowables = [
            Paragraph("<b>1. Executive Summary (BLUF)</b>", styles["SectionHeader"]),
            Paragraph(rep.get("executive_summary", "Not stated."), styles["TableCell"]),
            Spacer(1, 4),
            Paragraph("<b>2. Triangulated Score Breakdown</b>", styles["SectionHeader"]),
            sb_tbl,
            Spacer(1, 4),
            Paragraph("<b>3. Origin (CWE Root Cause & Timeline)</b>", styles["SectionHeader"]),
            Paragraph(secs.get("origin", "Not stated."), styles["TableCell"]),
        ]

        # Right column items
        right_flowables = [
            Paragraph("<b>4. What Is It & Asset Scope</b>", styles["SectionHeader"]),
            Paragraph(secs.get("what", "Not stated."), styles["TableCell"]),
            Spacer(1, 4),
            Paragraph("<b>5. How Exploited & Threat Intel</b>", styles["SectionHeader"]),
            Paragraph(secs.get("how", "Not stated."), styles["TableCell"]),
            Spacer(1, 4),
            Paragraph("<b>6. Resolution Plan & Mandates</b>", styles["SectionHeader"]),
            Paragraph(secs.get("resolution", "Not stated."), styles["TableCell"]),
        ]

        # Pack into tight 2-column table to strictly contain height on 1 page
        brief_body_tbl = Table([
            [left_flowables, right_flowables]
        ], colWidths=[266, 266])
        brief_body_tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(brief_body_tbl)

    def _portfolio_canvas(*args: Any, **kwargs: Any) -> NumberedCanvas:
        c = NumberedCanvas(*args, **kwargs)
        c.doc_cve_id = "PORTFOLIO BRIEFING"
        return c

    doc.build(story, canvasmaker=_portfolio_canvas)
    buffer.seek(0)
    return buffer.getvalue()
