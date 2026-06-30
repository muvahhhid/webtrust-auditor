from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from webtrust_auditor import __version__


PRIMARY_COLOR = colors.HexColor("#0F172A")
BORDER_COLOR = colors.HexColor("#CBD5E1")
HEADER_BG = colors.HexColor("#E2E8F0")
SOFT_BG = colors.HexColor("#F8FAFC")

SEVERITY_COLORS = {
    "High": colors.HexColor("#FEE2E2"),
    "Medium": colors.HexColor("#FFEDD5"),
    "Low": colors.HexColor("#FEF9C3"),
    "Info": colors.HexColor("#DBEAFE"),
}


def generate_pdf_report(
    output_path: str,
    website_result: dict | None = None,
    email_result: dict | None = None,
    repo_result: dict | None = None,
) -> None:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    document = SimpleDocTemplate(
        str(output_file),
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    styles = build_styles()
    story = []

    story.append(Paragraph("WebTrust Auditor Report", styles["TitleCustom"]))
    story.append(Paragraph(f"Generated at: {datetime.utcnow().isoformat()}Z", styles["Small"]))
    story.append(Paragraph(f"Tool version: v{__version__}", styles["Small"]))
    story.append(Spacer(1, 0.4 * cm))

    story.append(
        Paragraph(
            "Defensive website, domain and repository security readiness report. "
            "Full website checks, when enabled, use a fixed curated list of low-impact GET-only checks and must only be used on websites you own or are authorized to test.",
            styles["Body"],
        )
    )

    story.append(Spacer(1, 0.6 * cm))

    add_summary(story, styles, website_result, email_result, repo_result)
    add_component(story, styles, "Website Security", website_result, build_website_rows)
    add_component(story, styles, "Email / Domain Security", email_result, build_email_rows)
    add_component(story, styles, "Repository Hygiene", repo_result, build_repo_rows)

    story.append(PageBreak())
    story.append(Paragraph("Safety Notice", styles["Heading1Custom"]))
    story.append(
        Paragraph(
            "WebTrust Auditor is intended for defensive security review, learning and authorized assessments. "
            "Default website checks are basic readiness checks. Full website checks, when enabled, are intended only for websites you own or are authorized to test.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            "The tool does not perform directory brute-forcing, crawling, fuzzing, exploitation, authentication bypass, POST requests or destructive actions.",
            styles["Body"],
        )
    )

    document.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)


def build_styles() -> dict:
    sample = getSampleStyleSheet()

    styles = {
        "TitleCustom": ParagraphStyle(
            "TitleCustom",
            parent=sample["Title"],
            textColor=PRIMARY_COLOR,
            fontSize=22,
            leading=26,
            spaceAfter=12,
        ),
        "Heading1Custom": ParagraphStyle(
            "Heading1Custom",
            parent=sample["Heading1"],
            textColor=PRIMARY_COLOR,
            fontSize=16,
            leading=20,
            spaceBefore=12,
            spaceAfter=8,
        ),
        "Heading2Custom": ParagraphStyle(
            "Heading2Custom",
            parent=sample["Heading2"],
            textColor=PRIMARY_COLOR,
            fontSize=13,
            leading=16,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=sample["BodyText"],
            fontSize=9,
            leading=12,
        ),
        "Small": ParagraphStyle(
            "Small",
            parent=sample["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#475569"),
        ),
    }

    return styles


def add_summary(story: list, styles: dict, website_result: dict | None, email_result: dict | None, repo_result: dict | None) -> None:
    story.append(Paragraph("Executive Summary", styles["Heading1Custom"]))

    data = [["Component", "Score", "Rating", "Findings", "Observations", "Status"]]
    data.append(build_summary_row("Website", website_result))
    data.append(build_summary_row("Email / Domain", email_result))
    data.append(build_summary_row("Repository", repo_result))

    table = Table(data, colWidths=[4.0 * cm, 2.6 * cm, 2.0 * cm, 2.3 * cm, 2.5 * cm, 2.6 * cm])
    table.setStyle(base_table_style())
    story.append(table)
    story.append(Spacer(1, 0.5 * cm))


def build_summary_row(name: str, result: dict | None) -> list:
    if not result:
        return [name, "Not scanned", "-", "-", "-", "Skipped"]

    score = result.get("score", 0)
    status = "Good" if score >= 75 else "Needs review"

    return [
        name,
        f"{score} / 100",
        result.get("rating", "-"),
        str(len(result.get("findings", []))),
        str(len(result.get("observations", []))),
        status,
    ]


def add_component(story: list, styles: dict, title: str, result: dict | None, row_builder) -> None:
    story.append(Paragraph(title, styles["Heading1Custom"]))

    if not result:
        story.append(Paragraph("This component was not scanned.", styles["Body"]))
        story.append(Spacer(1, 0.3 * cm))
        return

    rows = row_builder(result)
    table = Table([["Item", "Value"]] + rows, colWidths=[5.0 * cm, 11.0 * cm])
    table.setStyle(base_table_style())
    story.append(table)
    story.append(Spacer(1, 0.3 * cm))

    add_score(story, styles, result)
    add_findings(story, styles, result)
    add_observations(story, styles, result)


def build_website_rows(result: dict) -> list:
    ssl_data = result.get("ssl", {}) or {}
    ssl_value = "Not checked"

    if ssl_data.get("checked"):
        ssl_value = f"{ssl_data.get('not_after')} ({ssl_data.get('days_until_expiry')} days left)"

    rows = [
        ["Target URL", result.get("target_url") or "N/A"],
        ["Final URL", result.get("final_url") or "N/A"],
        ["Status Code", str(result.get("status_code") or "N/A")],
        ["HTTPS", "Yes" if result.get("https") else "No"],
        ["SSL Expires", ssl_value],
        ["Full Check", "Enabled" if result.get("full_check_enabled") else "Disabled"],
    ]

    if result.get("full_check_enabled"):
        rows.append(["Paths Tested", str(result.get("full_check_paths_tested", 0))])

    return rows


def build_email_rows(result: dict) -> list:
    return [
        ["Domain", result.get("domain") or "N/A"],
        ["MX Records", str(len(result.get("mx_records", [])))],
        ["SPF Records", str(len(result.get("spf_records", [])))],
        ["DMARC Record", "Yes" if result.get("dmarc_record") else "No"],
        ["DMARC Policy", result.get("dmarc_policy") or "N/A"],
        ["DKIM Selector", result.get("dkim_selector") or "N/A"],
        ["DKIM Record", "Yes" if result.get("dkim_record") else "No"],
    ]


def build_repo_rows(result: dict) -> list:
    return [
        ["Repository Path", result.get("path") or result.get("repository_path") or "N/A"],
        ["Files Checked", str(result.get("files_checked", 0))],
        [".gitignore", "Yes" if result.get("has_gitignore") else "No"],
        ["README.md", "Yes" if result.get("has_readme") else "No"],
        ["Dockerfile", "Yes" if result.get("has_dockerfile") else "No"],
        [".dockerignore", "Yes" if result.get("has_dockerignore") else "No"],
        ["Sensitive Files", str(len(result.get("sensitive_files", [])))],
        ["Database Files", str(len(result.get("database_files", [])))],
        ["Secret Hits", str(len(result.get("secret_hits", [])))],
    ]


def add_score(story: list, styles: dict, result: dict) -> None:
    counts = result.get("severity_counts", {})

    story.append(Paragraph("Score", styles["Heading2Custom"]))

    data = [
        ["Score", "Rating", "High", "Medium", "Low", "Info"],
        [
            f"{result.get('score', 0)} / 100",
            result.get("rating", "-"),
            str(counts.get("High", 0)),
            str(counts.get("Medium", 0)),
            str(counts.get("Low", 0)),
            str(counts.get("Info", 0)),
        ],
    ]

    table = Table(data, colWidths=[3.0 * cm, 2.0 * cm, 2.0 * cm, 2.0 * cm, 2.0 * cm, 2.0 * cm])
    table.setStyle(base_table_style())
    story.append(table)
    story.append(Spacer(1, 0.3 * cm))


def add_findings(story: list, styles: dict, result: dict) -> None:
    findings = result.get("findings", [])

    story.append(Paragraph("Findings", styles["Heading2Custom"]))

    if not findings:
        story.append(Paragraph("No security findings found.", styles["Body"]))
        story.append(Spacer(1, 0.3 * cm))
        return

    for index, finding in enumerate(findings, start=1):
        story.append(Paragraph(f"{index}. {safe_text(finding.get('title', 'N/A'))}", styles["Heading2Custom"]))

        data = [
            ["Severity", finding.get("severity", "Info")],
            ["Category", finding.get("category", "N/A")],
            ["Evidence", finding.get("evidence", "N/A")],
            ["Why it matters", finding.get("why", "N/A")],
            ["Recommendation", finding.get("recommendation", "N/A")],
            ["OWASP", finding.get("owasp", "Not directly mapped")],
            ["CWE", finding.get("cwe", "Not directly mapped")],
        ]

        references = finding.get("references", [])

        if references:
            data.append(["References", "\n".join(references)])

        table = Table(
            [[safe_text(left), safe_text(right)] for left, right in data],
            colWidths=[4.0 * cm, 12.0 * cm],
        )
        table.setStyle(finding_table_style(finding.get("severity", "Info")))
        story.append(table)
        story.append(Spacer(1, 0.25 * cm))


def add_observations(story: list, styles: dict, result: dict) -> None:
    observations = result.get("observations", [])

    if not observations:
        return

    story.append(Paragraph("Observations", styles["Heading2Custom"]))

    data = [["Observation", "Details"]]

    for observation in observations:
        data.append(
            [
                safe_text(observation.get("title", "N/A")),
                safe_text(observation.get("details", "N/A")),
            ]
        )

    table = Table(data, colWidths=[5.0 * cm, 11.0 * cm])
    table.setStyle(base_table_style())
    story.append(table)
    story.append(Spacer(1, 0.3 * cm))


def base_table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), PRIMARY_COLOR),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER_COLOR),
            ("BACKGROUND", (0, 1), (-1, -1), SOFT_BG),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def finding_table_style(severity: str) -> TableStyle:
    bg_color = SEVERITY_COLORS.get(severity, SOFT_BG)

    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (0, -1), bg_color),
            ("BACKGROUND", (1, 0), (1, -1), SOFT_BG),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER_COLOR),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def safe_text(value) -> str:
    return escape(str(value or ""))


def draw_footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(1.5 * cm, 1.0 * cm, f"WebTrust Auditor v{__version__}")
    canvas.drawRightString(19.5 * cm, 1.0 * cm, f"Page {document.page}")
    canvas.restoreState()