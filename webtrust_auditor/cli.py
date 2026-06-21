import argparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from webtrust_auditor.website_scanner import scan_website
from webtrust_auditor.email_scanner import scan_email_domain
from webtrust_auditor.repo_scanner import scan_repository
from webtrust_auditor.report_generator import generate_markdown_report
from webtrust_auditor.scoring import calculate_score, count_findings_by_severity


console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="WebTrust Auditor - defensive security readiness checker."
    )

    parser.add_argument(
        "--url",
        help="Website URL to scan, for example: https://example.com"
    )

    parser.add_argument(
        "--domain",
        help="Email/domain name to check, for example: example.com"
    )

    parser.add_argument(
        "--dkim-selector",
        help="Optional DKIM selector, for example: google"
    )

    parser.add_argument(
        "--repo",
        help="Local repository/project path to check."
    )

    parser.add_argument(
        "--output",
        default="reports/webtrust-report.md",
        help="Path where the Markdown report should be saved."
    )

    args = parser.parse_args()

    console.print(
        Panel.fit(
            "WebTrust Auditor\n"
            "Defensive website, domain and repository security readiness checker.",
            title="Starting"
        )
    )

    if not args.url and not args.domain and not args.repo:
        console.print("[yellow]No URL, domain or repository path provided yet.[/yellow]")
        console.print("Examples:")
        console.print("[cyan]python webtrust.py --url https://example.com[/cyan]")
        console.print("[cyan]python webtrust.py --domain example.com[/cyan]")
        console.print("[cyan]python webtrust.py --repo C:\\path\\to\\project[/cyan]")
        console.print(
            "[cyan]python webtrust.py --url https://example.com "
            "--domain example.com --repo C:\\path\\to\\project[/cyan]"
        )
        return

    website_result = None
    email_result = None
    repository_result = None

    if args.url:
        website_result = scan_website(args.url)
        display_website_result(website_result)

    if args.domain:
        email_result = scan_email_domain(args.domain, args.dkim_selector)
        display_email_result(email_result)

    if args.repo:
        repository_result = scan_repository(args.repo)
        display_repository_result(repository_result)

    report_path = generate_markdown_report(
        website_result,
        email_result,
        repository_result,
        args.output
    )

    console.print("")
    console.print(f"[green]Markdown report saved to:[/green] {report_path}")


def display_website_result(result: dict):
    console.print("\n[bold cyan]Website Scan Result[/bold cyan]")

    if result["error"]:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
        return

    summary_table = Table(title="Target Summary")
    summary_table.add_column("Item", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Target URL", result["target_url"])
    summary_table.add_row("Final URL", result["final_url"])
    summary_table.add_row("Status Code", str(result["status_code"]))
    summary_table.add_row("HTTPS", "Yes" if result["is_https"] else "No")

    console.print(summary_table)

    findings = result["findings"]
    display_score_table(findings, "Website Security Score")

    if not findings:
        console.print("[green]No basic website findings found.[/green]")
        return

    display_findings_table(findings)
    display_detailed_findings(findings)


def display_email_result(result: dict):
    console.print("\n[bold cyan]Email / Domain Scan Result[/bold cyan]")

    if result["error"]:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
        return

    summary_table = Table(title="DNS Summary")
    summary_table.add_column("Item", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Domain", result["domain"])
    summary_table.add_row("MX Records", str(len(result["mx_records"])))
    summary_table.add_row("SPF Records", str(len(result["spf_records"])))
    summary_table.add_row("DMARC Record", "Yes" if result["dmarc_record"] else "No")
    summary_table.add_row("DMARC Policy", result["dmarc_policy"] or "N/A")
    summary_table.add_row("DKIM Selector", result["dkim_selector"] or "N/A")
    summary_table.add_row("DKIM Record", "Yes" if result["dkim_record"] else "No")

    console.print(summary_table)

    findings = result["findings"]
    display_score_table(findings, "Email Domain Security Score")

    if not findings:
        console.print("[green]No basic email/domain findings found.[/green]")
        return

    display_findings_table(findings)
    display_detailed_findings(findings)


def display_repository_result(result: dict):
    console.print("\n[bold cyan]Repository Hygiene Scan Result[/bold cyan]")

    if result["error"]:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
        return

    summary = result["summary"]

    summary_table = Table(title="Repository Summary")
    summary_table.add_column("Item", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Repository Path", result["repo_path"])
    summary_table.add_row("Files Checked", str(result["files_checked"]))
    summary_table.add_row(".gitignore", "Yes" if summary["gitignore_exists"] else "No")
    summary_table.add_row("README.md", "Yes" if summary["readme_exists"] else "No")
    summary_table.add_row("Dockerfile", "Yes" if summary["dockerfile_exists"] else "No")
    summary_table.add_row(".dockerignore", "Yes" if summary["dockerignore_exists"] else "No")
    summary_table.add_row("Sensitive Files", str(summary["sensitive_files_found"]))
    summary_table.add_row("Database Files", str(summary["database_files_found"]))
    summary_table.add_row("Secret Keyword Hits", str(summary["secret_keyword_hits"]))

    console.print(summary_table)

    findings = result["findings"]
    display_score_table(findings, "Repository Hygiene Score")

    if not findings:
        console.print("[green]No basic repository hygiene findings found.[/green]")
        return

    display_findings_table(findings)
    display_detailed_findings(findings)


def display_score_table(findings: list, title: str):
    score_result = calculate_score(findings)
    severity_counts = count_findings_by_severity(findings)

    score_table = Table(title=title)
    score_table.add_column("Item", style="cyan")
    score_table.add_column("Value", style="white")

    score_table.add_row("Score", f"{score_result['score']} / 100")
    score_table.add_row("Rating", score_result["rating"])
    score_table.add_row("High Findings", str(severity_counts["High"]))
    score_table.add_row("Medium Findings", str(severity_counts["Medium"]))
    score_table.add_row("Low Findings", str(severity_counts["Low"]))
    score_table.add_row("Info Findings", str(severity_counts["Info"]))
    score_table.add_row("Total Penalty", f"-{score_result['total_penalty']}")

    console.print(score_table)


def display_findings_table(findings: list):
    findings_table = Table(title="Findings")
    findings_table.add_column("Severity", style="red")
    findings_table.add_column("Finding", style="white")
    findings_table.add_column("Recommendation", style="green")

    for finding in findings:
        findings_table.add_row(
            finding["severity"],
            finding["title"],
            finding["recommendation"]
        )

    console.print(findings_table)


def display_detailed_findings(findings: list):
    console.print("\n[bold]Detailed Explanation[/bold]")

    for index, finding in enumerate(findings, start=1):
        console.print(f"\n[bold]{index}. {finding['title']}[/bold]")
        console.print(f"[red]Severity:[/red] {finding['severity']}")
        console.print(f"[yellow]Evidence:[/yellow] {finding['evidence']}")
        console.print(f"[cyan]Why it matters:[/cyan] {finding['why']}")
        console.print(f"[green]Recommendation:[/green] {finding['recommendation']}")