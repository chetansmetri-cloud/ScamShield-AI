from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def build_pdf_report(report: dict[str, Any]) -> bytes:
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="ScamShield AI Investigation Report",
        author="ScamShield AI",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Brand",
            parent=styles["Title"],
            textColor=colors.HexColor("#087eaa"),
            alignment=TA_LEFT,
            fontSize=22,
            leading=26,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Section",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#087eaa"),
            spaceBefore=12,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            wordWrap="CJK",
        )
    )

    def paragraph(value: Any, style: str = "BodyText") -> Paragraph:
        return Paragraph(escape(str(value or "")), styles[style])

    story = [
        paragraph("SCAMSHIELD AI", "Brand"),
        paragraph("Investigation intelligence report", "Heading2"),
        Spacer(1, 8),
    ]
    summary_rows = [
        [paragraph("Investigation ID", "SmallBody"), paragraph(report.get("id"), "SmallBody")],
        [paragraph("Created", "SmallBody"), paragraph(report.get("created_at"), "SmallBody")],
        [paragraph("Type / target", "SmallBody"), paragraph(f"{report.get('investigation_type')} · {report.get('target')}", "SmallBody")],
        [paragraph("Risk", "SmallBody"), paragraph(f"{report.get('risk_score')}/100 · {report.get('risk_category')}", "SmallBody")],
        [paragraph("Confidence / completeness", "SmallBody"), paragraph(f"{report.get('confidence')} · {report.get('information_completeness')}", "SmallBody")],
        [paragraph("Method / live research", "SmallBody"), paragraph(f"{report.get('analysis_method')} · {report.get('live_research')}", "SmallBody")],
    ]
    summary = Table(summary_rows, colWidths=[1.65 * inch, 5.2 * inch])
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eaf5fa")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d3e1e8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend(
        [
            summary,
            Spacer(1, 12),
            paragraph("Score calculation", "Section"),
            paragraph(report.get("scoring_explanation"), "SmallBody"),
        ]
    )

    job_verification = report.get("job_verification")
    if isinstance(job_verification, dict):
        story.append(paragraph("Job & internship verification", "Section"))
        for label, key in (
            ("Submitted company", "submitted_company"),
            ("Submitted offer URL", "submitted_offer_url"),
            ("Final fetched URL", "final_fetched_url"),
            ("Company on page", "page_company"),
            ("Page title", "page_title"),
            ("Job title", "job_title"),
            ("Submitted job ID", "submitted_job_id"),
            ("Fetched job ID", "job_id"),
            ("Company match", "company_name_match"),
            ("Role match", "role_details_match"),
            ("Job ID match", "job_id_match"),
            ("Company status", "company_status"),
            ("Listing status", "exact_listing_status"),
            ("Hosting status", "hosting_status"),
            ("Recruitment platform", "recruitment_platform"),
            ("Official careers domain", "official_careers_domain_status"),
            ("Application details", "application_details"),
            ("Application URL", "application_url"),
            ("Explanation", "explanation"),
        ):
            story.append(paragraph(f"{label}: {job_verification.get(key)}", "SmallBody"))
        recruiter = job_verification.get("recruiter")
        if isinstance(recruiter, dict):
            story.append(
                paragraph(
                    f"Recruiter status: {recruiter.get('status')}; "
                    f"email domain: {recruiter.get('email_domain')}; "
                    f"{recruiter.get('explanation')}",
                    "SmallBody",
                )
            )
        for item in report.get("positive_indicators", []):
            story.extend(
                [
                    paragraph(
                        f"Positive evidence: {item.get('name')} · no score reduction",
                        "Heading4",
                    ),
                    paragraph(item.get("explanation"), "SmallBody"),
                    paragraph(f"Evidence: {item.get('evidence')}", "SmallBody"),
                ]
            )

    indicators = report.get("indicators", [])
    if indicators:
        story.append(paragraph("Indicators", "Section"))
        for item in indicators:
            story.extend(
                [
                    paragraph(
                        f"{item.get('name')} · +{item.get('score_contribution')} · {item.get('classification')}",
                        "Heading4",
                    ),
                    paragraph(item.get("explanation"), "SmallBody"),
                    paragraph(f"Evidence: {item.get('evidence')}", "SmallBody"),
                ]
            )

    evidence = report.get("evidence", [])
    if evidence:
        story.append(paragraph("Evidence and sources", "Section"))
        for item in evidence:
            story.extend(
                [
                    paragraph(item.get("title") or item.get("source_type") or "Source", "Heading4"),
                    paragraph(f"URL: {item.get('url')}", "SmallBody"),
                    paragraph(item.get("excerpt"), "SmallBody"),
                    paragraph(
                        f"Provider: {', '.join(item.get('providers', []))}"
                        if isinstance(item.get("providers"), list)
                        else f"Provider: {item.get('provider', 'not recorded')}",
                        "SmallBody",
                    ),
                    Spacer(1, 5),
                ]
            )

    for heading, key in (
        ("Recommended actions", "recommended_next_steps"),
        ("Information gaps", "missing_information"),
    ):
        values = report.get(key, [])
        if values:
            story.append(paragraph(heading, "Section"))
            story.extend(paragraph(f"• {value}", "SmallBody") for value in values)

    story.extend(
        [
            Spacer(1, 12),
            HRFlowable(width="100%", color=colors.HexColor("#d3e1e8")),
            Spacer(1, 6),
            paragraph(report.get("disclaimer"), "SmallBody"),
        ]
    )
    document.build(story)
    return output.getvalue()
