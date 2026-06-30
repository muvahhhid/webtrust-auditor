from datetime import datetime
from pathlib import Path

from webtrust_auditor import __version__


def generate_markdown_report(
    output_path: str,
    website_result: dict | None = None,
    email_result: dict | None = None,
    repo_result: dict | None = None,
) -> None:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    content = build_markdown_report(website_result, email_result, repo_result)

    output_file.write_text(content, encoding="utf-8")


def build_markdown_report(
    website_result: dict | None,
    email_result: dict | None,
    repo_result: dict | None,
) -> str:
    lines = []

    lines.append("# WebTrust Auditor Report")
    lines.append("")
    lines.append(f"Generated at: `{datetime.utcnow().isoformat()}Z`")
    lines.append(f"Tool version: `v{__version__}`")
    lines.append("")
    lines.append("> WebTrust Auditor is a defensive security readiness checker. Full website checks, when enabled, use a fixed curated list of low-impact GET-only checks and must only be used on websites you own or are authorized to test.")
    lines.append("")

    add_summary(lines, website_result, email_result, repo_result)
    add_website_section(lines, website_result)
    add_email_section(lines, email_result)
    add_repository_section(lines, repo_result)
    add_safety_notice(lines)

    return "\n".join(lines)


def add_summary(lines: list[str], website_result: dict | None, email_result: dict | None, repo_result: dict | None) -> None:
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Component | Score | Rating | Findings | Observations | Status |")
    lines.append("|---|---:|---|---:|---:|---|")
    add_summary_row(lines, "Website", website_result)
    add_summary_row(lines, "Email / Domain", email_result)
    add_summary_row(lines, "Repository", repo_result)
    lines.append("")


def add_summary_row(lines: list[str], name: str, result: dict | None) -> None:
    if not result:
        lines.append(f"| {name} | Not scanned | - | - | - | Skipped |")
        return

    score = result.get("score", 0)
    status = "Good" if score >= 75 else "Needs review"

    lines.append(
        f"| {name} | {score} / 100 | {result.get('rating', '-')} | "
        f"{len(result.get('findings', []))} | {len(result.get('observations', []))} | {status} |"
    )


def add_website_section(lines: list[str], result: dict | None) -> None:
    lines.append("## Website Security")
    lines.append("")

    if not result:
        lines.append("Website scan was not requested.")
        lines.append("")
        return

    ssl_data = result.get("ssl", {}) or {}

    lines.append("| Item | Value |")
    lines.append("|---|---|")
    lines.append(f"| Target URL | `{result.get('target_url')}` |")
    lines.append(f"| Final URL | `{result.get('final_url')}` |")
    lines.append(f"| Status Code | `{result.get('status_code')}` |")
    lines.append(f"| HTTPS | {'Yes' if result.get('https') else 'No'} |")

    if ssl_data.get("checked"):
        lines.append(f"| SSL Expires | `{ssl_data.get('not_after')}` ({ssl_data.get('days_until_expiry')} days left) |")
    else:
        lines.append("| SSL Expires | Not checked |")

    lines.append(f"| Full Check | {'Enabled' if result.get('full_check_enabled') else 'Disabled'} |")

    if result.get("full_check_enabled"):
        lines.append(f"| Paths Tested | `{result.get('full_check_paths_tested', 0)}` |")

    lines.append("")

    add_score(lines, result)
    add_findings(lines, result)
    add_observations(lines, result)


def add_email_section(lines: list[str], result: dict | None) -> None:
    lines.append("## Email / Domain Security")
    lines.append("")

    if not result:
        lines.append("Email/domain scan was not requested.")
        lines.append("")
        return

    lines.append("| Item | Value |")
    lines.append("|---|---|")
    lines.append(f"| Domain | `{result.get('domain')}` |")
    lines.append(f"| MX Records | `{len(result.get('mx_records', []))}` |")
    lines.append(f"| SPF Records | `{len(result.get('spf_records', []))}` |")
    lines.append(f"| DMARC Record | {'Yes' if result.get('dmarc_record') else 'No'} |")
    lines.append(f"| DMARC Policy | `{result.get('dmarc_policy') or 'N/A'}` |")
    lines.append(f"| DKIM Selector | `{result.get('dkim_selector') or 'N/A'}` |")
    lines.append(f"| DKIM Record | {'Yes' if result.get('dkim_record') else 'No'} |")
    lines.append("")

    add_score(lines, result)
    add_findings(lines, result)
    add_observations(lines, result)


def add_repository_section(lines: list[str], result: dict | None) -> None:
    lines.append("## Repository Hygiene")
    lines.append("")

    if not result:
        lines.append("Repository scan was not requested.")
        lines.append("")
        return

    lines.append("| Item | Value |")
    lines.append("|---|---|")
    lines.append(f"| Repository Path | `{result.get('path') or result.get('repository_path') or 'N/A'}` |")
    lines.append(f"| Files Checked | `{result.get('files_checked', 0)}` |")
    lines.append(f"| .gitignore | {'Yes' if result.get('has_gitignore') else 'No'} |")
    lines.append(f"| README.md | {'Yes' if result.get('has_readme') else 'No'} |")
    lines.append(f"| Dockerfile | {'Yes' if result.get('has_dockerfile') else 'No'} |")
    lines.append(f"| .dockerignore | {'Yes' if result.get('has_dockerignore') else 'No'} |")
    lines.append(f"| Sensitive Files | `{len(result.get('sensitive_files', []))}` |")
    lines.append(f"| Database Files | `{len(result.get('database_files', []))}` |")
    lines.append(f"| Secret Hits | `{len(result.get('secret_hits', []))}` |")
    lines.append("")

    add_score(lines, result)
    add_findings(lines, result)
    add_observations(lines, result)


def add_score(lines: list[str], result: dict) -> None:
    counts = result.get("severity_counts", {})

    lines.append("### Score")
    lines.append("")
    lines.append("| Score | Rating | High | Medium | Low | Info |")
    lines.append("|---:|---|---:|---:|---:|---:|")
    lines.append(
        f"| {result.get('score', 0)} / 100 | {result.get('rating', '-')} | "
        f"{counts.get('High', 0)} | {counts.get('Medium', 0)} | {counts.get('Low', 0)} | {counts.get('Info', 0)} |"
    )
    lines.append("")


def add_findings(lines: list[str], result: dict) -> None:
    findings = result.get("findings", [])

    lines.append("### Findings")
    lines.append("")

    if not findings:
        lines.append("No security findings found.")
        lines.append("")
        return

    for index, finding in enumerate(findings, start=1):
        lines.append(f"#### {index}. {finding.get('title', 'N/A')}")
        lines.append("")
        lines.append(f"- **Severity:** {finding.get('severity', 'Info')}")
        lines.append(f"- **Category:** {finding.get('category', 'N/A')}")
        lines.append(f"- **Evidence:** {finding.get('evidence', 'N/A')}")
        lines.append(f"- **Why it matters:** {finding.get('why', 'N/A')}")
        lines.append(f"- **Recommendation:** {finding.get('recommendation', 'N/A')}")
        lines.append(f"- **OWASP:** {finding.get('owasp', 'Not directly mapped')}")
        lines.append(f"- **CWE:** {finding.get('cwe', 'Not directly mapped')}")

        references = finding.get("references", [])

        if references:
            lines.append("- **References:**")

            for reference in references:
                lines.append(f"  - {reference}")

        lines.append("")


def add_observations(lines: list[str], result: dict) -> None:
    observations = result.get("observations", [])

    if not observations:
        return

    lines.append("### Observations")
    lines.append("")
    lines.append("| Observation | Details |")
    lines.append("|---|---|")

    for observation in observations:
        lines.append(f"| {observation.get('title', 'N/A')} | {observation.get('details', 'N/A')} |")

    lines.append("")


def add_safety_notice(lines: list[str]) -> None:
    lines.append("## Safety Notice")
    lines.append("")
    lines.append("WebTrust Auditor is intended for defensive security review, learning and authorized assessments.")
    lines.append("")
    lines.append("Default website checks are basic readiness checks. Full website checks, when enabled, are intended only for websites you own or are authorized to test.")
    lines.append("")
    lines.append("The tool does not perform directory brute-forcing, crawling, fuzzing, exploitation, authentication bypass, POST requests or destructive actions.")
    lines.append("")