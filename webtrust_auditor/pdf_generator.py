from datetime import datetime, timezone
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from webtrust_auditor import __version__
from webtrust_auditor.scoring import calculate_score, count_findings_by_severity


PRIMARY_COLOR = colors.HexColor("#0F172A")
BORDER_COLOR = colors.HexColor("#CBD5E1")
LIGHT_BACKGROUND = colors.HexColor("#F8FAFC")

SEVERITY_BACKGROUND_COLORS = {
    "High": colors.HexColor("#FEE2E2"),
    "Medium": colors.HexColor("#FFEDD5"),
    "Low": colors.HexColor("#FEF9C3"),
    "Info": colors.HexColor("#DBEAFE"),
}

SEVERITY_TEXT_COLORS = {
    "High": colors.HexColor("#991B1B"),
    "Medium": colors.HexColor("#9A3412"),
    "Low": colors.HexColor("#854D0E"),
    "Info": colors.HexColor("#1E40AF"),
}


def generate_pdf_report(
    website_result: dict | None,
    email_result: dict | None,
    repository_result: dict | None,
    output_path: str,
) -> str:
    """
    Generates a human-readable PDF security readiness report.
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_file),
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    styles = build_styles()
    story = []

    add_title_page(story, styles)
    add_executive_summary(
        story,
        styles,
        website_result,
        email_result,
        repository_result,
    )

    add_component_section(story, styles, "Website Security", website_result)
    add_component_section(story, styles, "Email / Domain Security", email_result)
    add_component_section(story, styles, "Repository Hygiene", repository_result)

    add_safety_notice(story, styles)

    doc.build(
        story,
        onFirstPage=add_footer,
        onLaterPages=add_footer,
    )

    return str(output_file)


def build_styles() -> dict:
    """
    Builds paragraph styles used by the PDF report.
    """
    sample_styles = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "CustomTitle",
            parent=sample_styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=30,
            textColor=PRIMARY_COLOR,
            spaceAfter=16,
        ),
        "subtitle": ParagraphStyle(
            "CustomSubtitle",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=16,
            textColor=colors.HexColor("#475569"),
            spaceAfter=14,
        ),
        "heading": ParagraphStyle(
            "CustomHeading",
            parent=sample_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=PRIMARY_COLOR,
            spaceBefore=16,
            spaceAfter=10,
        ),
        "subheading": ParagraphStyle(
            "CustomSubheading",
            parent=sample_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=PRIMARY_COLOR,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "CustomBody",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1E293B"),
            spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "CustomSmall",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748B"),
        ),
        "table_header": ParagraphStyle(
            "CustomTableHeader",
            parent=sample_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
        ),
        "table": ParagraphStyle(
            "CustomTable",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A"),
        ),
        "table_bold": ParagraphStyle(
            "CustomTableBold",
            parent=sample_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A"),
        ),
    }


def add_title_page(story: list, styles: dict) -> None:
    """
    Adds the PDF title and report metadata.
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story.append(Paragraph("WebTrust Auditor Report", styles["title"]))
    story.append(
        Paragraph(
            "Defensive website, email/domain and repository security readiness report.",
            styles["subtitle"],
        )
    )

    metadata = [
        ["Tool", "WebTrust Auditor"],
        ["Version", __version__],
        ["Generated At", generated_at],
        ["Report Type", "Passive security readiness assessment"],
    ]

    story.append(make_key_value_table(metadata, styles))
    story.append(Spacer(1, 16))

    story.append(
        Paragraph(
            "This report summarizes passive security checks. It does not prove that a "
            "target is secure or insecure. Findings should be reviewed manually before "
            "being used for production decisions.",
            styles["body"],
        )
    )

    story.append(Spacer(1, 12))


def add_executive_summary(
    story: list,
    styles: dict,
    website_result: dict | None,
    email_result: dict | None,
    repository_result: dict | None,
) -> None:
    """
    Adds a high-level score overview.
    """
    story.append(Paragraph("Executive Summary", styles["heading"]))

    rows = [
        [
            Paragraph("Component", styles["table_header"]),
            Paragraph("Status", styles["table_header"]),
            Paragraph("Score", styles["table_header"]),
            Paragraph("Rating", styles["table_header"]),
            Paragraph("Findings", styles["table_header"]),
        ]
    ]

    rows.append(build_summary_row("Website", website_result, styles))
    rows.append(build_summary_row("Email / Domain", email_result, styles))
    rows.append(build_summary_row("Repository", repository_result, styles))

    table = Table(
        rows,
        colWidths=[4.0 * cm, 3.0 * cm, 2.8 * cm, 2.2 * cm, 2.5 * cm],
    )
    table.setStyle(build_default_table_style(header=True))
    story.append(table)
    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "Severity scoring: High findings reduce the score by 25 points, Medium by "
            "10 points, Low by 5 points and Info by 0 points.",
            styles["small"],
        )
    )


def build_summary_row(component_name: str, result: dict | None, styles: dict) -> list:
    """
    Builds one row for the executive summary table.
    """
    if result is None:
        return [
            Paragraph(component_name, styles["table"]),
            Paragraph("Skipped", styles["table"]),
            Paragraph("-", styles["table"]),
            Paragraph("-", styles["table"]),
            Paragraph("-", styles["table"]),
        ]

    if result.get("error"):
        return [
            Paragraph(component_name, styles["table"]),
            Paragraph("Failed", styles["table"]),
            Paragraph("-", styles["table"]),
            Paragraph("-", styles["table"]),
            Paragraph("Error", styles["table"]),
        ]

    findings = result.get("findings", [])
    score_result = calculate_score(findings)

    return [
        Paragraph(component_name, styles["table"]),
        Paragraph("Completed", styles["table"]),
        Paragraph(f"{score_result['score']} / 100", styles["table"]),
        Paragraph(score_result["rating"], styles["table"]),
        Paragraph(str(len(findings)), styles["table"]),
    ]


def add_component_section(
    story: list,
    styles: dict,
    title: str,
    result: dict | None,
) -> None:
    """
    Adds one component section: website, email/domain or repository.
    """
    story.append(Spacer(1, 12))
    story.append(Paragraph(title, styles["heading"]))

    if result is None:
        story.append(Paragraph("This component was not scanned.", styles["body"]))
        return

    if result.get("error"):
        story.append(Paragraph(f"Scan failed: {safe_text(result.get('error'))}", styles["body"]))
        return

    add_component_score(story, styles, result)
    add_component_summary(story, styles, title, result)
    add_findings_table(story, styles, result.get("findings", []))


def add_component_score(story: list, styles: dict, result: dict) -> None:
    """
    Adds score and severity count table for a component.
    """
    findings = result.get("findings", [])
    score_result = calculate_score(findings)
    severity_counts = count_findings_by_severity(findings)

    rows = [
        [
            Paragraph("Score", styles["table_header"]),
            Paragraph("Rating", styles["table_header"]),
            Paragraph("High", styles["table_header"]),
            Paragraph("Medium", styles["table_header"]),
            Paragraph("Low", styles["table_header"]),
            Paragraph("Info", styles["table_header"]),
        ],
        [
            Paragraph(f"{score_result['score']} / 100", styles["table"]),
            Paragraph(score_result["rating"], styles["table"]),
            Paragraph(str(severity_counts["High"]), styles["table"]),
            Paragraph(str(severity_counts["Medium"]), styles["table"]),
            Paragraph(str(severity_counts["Low"]), styles["table"]),
            Paragraph(str(severity_counts["Info"]), styles["table"]),
        ],
    ]

    table = Table(
        rows,
        colWidths=[3.0 * cm, 2.2 * cm, 2.0 * cm, 2.3 * cm, 2.0 * cm, 2.0 * cm],
    )
    table.setStyle(build_default_table_style(header=True))
    story.append(table)
    story.append(Spacer(1, 10))


def add_component_summary(story: list, styles: dict, title: str, result: dict) -> None:
    """
    Adds short metadata table depending on component type.
    """
    story.append(Paragraph("Scan Summary", styles["subheading"]))

    if title == "Website Security":
        ssl_info = result.get("ssl_certificate", {})

        rows = [
            ["Target URL", result.get("target_url")],
            ["Final URL", result.get("final_url")],
            ["Status Code", result.get("status_code")],
            ["HTTPS", "Yes" if result.get("is_https") else "No"],
        ]

        if ssl_info.get("checked"):
            rows.append(["SSL Expires", ssl_info.get("not_after")])
            rows.append(["SSL Days Left", ssl_info.get("days_until_expiry")])

    elif title == "Email / Domain Security":
        rows = [
            ["Domain", result.get("domain")],
            ["MX Records", len(result.get("mx_records", []))],
            ["SPF Records", len(result.get("spf_records", []))],
            ["DMARC Record", "Yes" if result.get("dmarc_record") else "No"],
            ["DMARC Policy", result.get("dmarc_policy") or "N/A"],
            ["DKIM Selector", result.get("dkim_selector") or "N/A"],
            ["DKIM Record", "Yes" if result.get("dkim_record") else "No"],
        ]

    else:
        summary = result.get("summary", {})
        rows = [
            ["Repository Path", result.get("repo_path")],
            ["Files Checked", result.get("files_checked")],
            [".gitignore", "Yes" if summary.get("gitignore_exists") else "No"],
            ["README.md", "Yes" if summary.get("readme_exists") else "No"],
            ["Dockerfile", "Yes" if summary.get("dockerfile_exists") else "No"],
            [".dockerignore", "Yes" if summary.get("dockerignore_exists") else "No"],
            ["Sensitive Files", summary.get("sensitive_files_found")],
            ["Database Files", summary.get("database_files_found")],
            ["Secret Hits", summary.get("secret_keyword_hits")],
        ]

    story.append(make_key_value_table(rows, styles))
    story.append(Spacer(1, 10))


def add_findings_table(story: list, styles: dict, findings: list) -> None:
    """
    Adds findings table with severity, evidence and recommendation.
    """
    story.append(Paragraph("Findings", styles["subheading"]))

    if not findings:
        story.append(Paragraph("No findings were detected for this component.", styles["body"]))
        return

    rows = [
        [
            Paragraph("Severity", styles["table_header"]),
            Paragraph("Finding", styles["table_header"]),
            Paragraph("Evidence", styles["table_header"]),
            Paragraph("Recommendation", styles["table_header"]),
        ]
    ]

    for finding in findings:
        severity = finding.get("severity")

        rows.append(
            [
                Paragraph(
                    safe_text(severity),
                    build_severity_style(severity, styles),
                ),
                Paragraph(safe_text(finding.get("title", "")), styles["table"]),
                Paragraph(safe_text(finding.get("evidence", "")), styles["table"]),
                Paragraph(safe_text(finding.get("recommendation", "")), styles["table"]),
            ]
        )

    table = Table(
        rows,
        colWidths=[2.2 * cm, 4.0 * cm, 4.8 * cm, 4.8 * cm],
        repeatRows=1,
    )
    table.setStyle(build_findings_table_style(findings))
    story.append(table)
    story.append(Spacer(1, 10))


def add_safety_notice(story: list, styles: dict) -> None:
    """
    Adds safety and scope information.
    """
    story.append(PageBreak())
    story.append(Paragraph("Safety Notice", styles["heading"]))
    story.append(
        Paragraph(
            "WebTrust Auditor is a defensive and passive security tool. It does not exploit "
            "vulnerabilities, brute-force logins, bypass authentication, upload files or "
            "modify remote systems.",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            "Website checks are based on normal HTTP requests and response headers. "
            "Email/domain checks are based on public DNS records. Repository checks are "
            "based on local file names and selected local text files.",
            styles["body"],
        )
    )


def make_key_value_table(rows: list, styles: dict) -> Table:
    """
    Creates a reusable two-column key/value table.
    """
    table_data = []

    for key, value in rows:
        table_data.append(
            [
                Paragraph(safe_text(key), styles["table_bold"]),
                Paragraph(safe_text(value if value is not None else "N/A"), styles["table"]),
            ]
        )

    table = Table(table_data, colWidths=[4.2 * cm, 11.0 * cm])
    table.setStyle(build_default_table_style(header=False))
    return table


def build_default_table_style(header: bool = False) -> TableStyle:
    """
    Returns default table styling.
    """
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.35, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
    ]

    if header:
        commands.extend(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY_COLOR),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ]
        )

    return TableStyle(commands)


def build_findings_table_style(findings: list) -> TableStyle:
    """
    Builds table style for findings table with soft severity colors.
    """
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.35, BORDER_COLOR),
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY_COLOR),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]

    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity")
        severity_background = SEVERITY_BACKGROUND_COLORS.get(
            severity,
            LIGHT_BACKGROUND,
        )

        commands.append(
            ("BACKGROUND", (0, index), (0, index), severity_background)
        )

    return TableStyle(commands)


def build_severity_style(severity: str | None, styles: dict) -> ParagraphStyle:
    """
    Builds a severity-specific paragraph style.
    """
    severity_color = SEVERITY_TEXT_COLORS.get(
        severity,
        colors.HexColor("#334155"),
    )

    return ParagraphStyle(
        f"Severity{severity or 'Default'}",
        parent=styles["table_bold"],
        textColor=severity_color,
    )


def safe_text(value) -> str:
    """
    Escapes text for ReportLab Paragraph rendering.
    """
    if value is None:
        return "N/A"

    return escape(str(value))


def add_footer(canvas, doc) -> None:
    """
    Adds a footer with page number.
    """
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(
        1.5 * cm,
        1.0 * cm,
        "WebTrust Auditor - Passive Security Readiness Report",
    )
    canvas.drawRightString(19.5 * cm, 1.0 * cm, f"Page {doc.page}")
    canvas.restoreState()