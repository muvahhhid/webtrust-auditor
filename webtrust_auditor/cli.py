import argparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from webtrust_auditor import __version__
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
        help="Optional path where the Markdown report should be saved."
    )

    parser.add_argument(
        "--details",
        action="store_true",
        help="Show detailed explanations for every finding in the terminal."
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"WebTrust Auditor {__version__}"
    )

    args = parser.parse_args()

    console.print(
        Panel.fit(
            f"[bold]WebTrust Auditor[/bold] [cyan]v{__version__}[/cyan]\n"
            "Defensive website, domain and repository security readiness checker.",
            title="Starting",
            border_style="cyan"
        )
    )

    if not args.url and not args.domain and not args.repo:
        show_examples()
        return

    website_result = None
    email_result = None
    repository_result = None

    if args.url:
        website_result = scan_website(args.url)
        display_website_result(website_result, args.details)

    if args.domain:
        email_result = scan_email_domain(args.domain, args.dkim_selector)
        display_email_result(email_result, args.details)

    if args.repo:
        repository_result = scan_repository(args.repo)
        display_repository_result(repository_result, args.details)

    display_final_summary(website_result, email_result, repository_result)

    if args.output:
        report_path = generate_markdown_report(
            website_result,
            email_result,
            repository_result,
            args.output
        )

        console.print("")
        console.print(f"[green]Markdown report saved to:[/green] {report_path}")
    else:
        console.print("")
        console.print(
            "[dim]Tip: add --output reports/report.md if you also want a Markdown report.[/dim]"
        )


def show_examples():
    console.print("[yellow]No URL, domain or repository path provided yet.[/yellow]")
    console.print("")
    console.print("[bold]Examples:[/bold]")
    console.print("[cyan]python webtrust.py --url https://example.com[/cyan]")
    console.print("[cyan]python webtrust.py --domain example.com[/cyan]")
    console.print("[cyan]python webtrust.py --repo .[/cyan]")
    console.print(
        "[cyan]python webtrust.py --url https://example.com "
        "--domain example.com --repo .[/cyan]"
    )


def display_website_result(result: dict, show_details: bool):
    console.print("\n[bold cyan]Website Security[/bold cyan]")

    if result["error"]:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
        return

    summary_table = Table(title="Target", box=box.ROUNDED)
    summary_table.add_column("Item", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Target URL", result["target_url"])
    summary_table.add_row("Final URL", result["final_url"])
    summary_table.add_row("Status Code", str(result["status_code"]))
    summary_table.add_row("HTTPS", "Yes" if result["is_https"] else "No")

    console.print(summary_table)

    findings = result["findings"]
    display_score_table(findings, "Website Score")

    if findings:
        display_findings_table(findings)
        display_top_recommendations(findings)

        if show_details:
            display_detailed_findings(findings)
    else:
        console.print("[green]No basic website findings found.[/green]")


def display_email_result(result: dict, show_details: bool):
    console.print("\n[bold cyan]Email / Domain Security[/bold cyan]")

    if result["error"]:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
        return

    summary_table = Table(title="DNS Summary", box=box.ROUNDED)
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
    display_score_table(findings, "Email Domain Score")

    if findings:
        display_findings_table(findings)
        display_top_recommendations(findings)

        if show_details:
            display_detailed_findings(findings)
    else:
        console.print("[green]No basic email/domain findings found.[/green]")


def display_repository_result(result: dict, show_details: bool):
    console.print("\n[bold cyan]Repository Hygiene[/bold cyan]")

    if result["error"]:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
        return

    summary = result["summary"]

    summary_table = Table(title="Repository Summary", box=box.ROUNDED)
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
    summary_table.add_row("Secret Hits", str(summary["secret_keyword_hits"]))

    console.print(summary_table)

    findings = result["findings"]
    display_score_table(findings, "Repository Score")

    if findings:
        display_findings_table(findings)
        display_top_recommendations(findings)

        if show_details:
            display_detailed_findings(findings)
    else:
        console.print("[green]No basic repository hygiene findings found.[/green]")


def display_score_table(findings: list, title: str):
    score_result = calculate_score(findings)
    severity_counts = count_findings_by_severity(findings)

    score_table = Table(title=title, box=box.SIMPLE_HEAVY)
    score_table.add_column("Score", style="bold cyan")
    score_table.add_column("Rating", style="bold white")
    score_table.add_column("High", justify="center")
    score_table.add_column("Medium", justify="center")
    score_table.add_column("Low", justify="center")
    score_table.add_column("Info", justify="center")

    score_table.add_row(
        f"{score_result['score']} / 100",
        score_result["rating"],
        str(severity_counts["High"]),
        str(severity_counts["Medium"]),
        str(severity_counts["Low"]),
        str(severity_counts["Info"])
    )

    console.print(score_table)


def display_findings_table(findings: list):
    findings_table = Table(title="Findings", box=box.ROUNDED)
    findings_table.add_column("Severity", style="red", width=10)
    findings_table.add_column("Finding", style="white")
    findings_table.add_column("Recommendation", style="green")

    for finding in findings:
        findings_table.add_row(
            finding["severity"],
            finding["title"],
            finding["recommendation"]
        )

    console.print(findings_table)


def display_top_recommendations(findings: list):
    actionable_findings = [
        finding for finding in findings
        if finding.get("severity") in {"High", "Medium", "Low"}
    ]

    if not actionable_findings:
        return

    console.print("[bold]Recommended next steps:[/bold]")

    for index, finding in enumerate(actionable_findings[:5], start=1):
        console.print(f"{index}. {finding['recommendation']}")


def display_detailed_findings(findings: list):
    console.print("\n[bold]Detailed Explanation[/bold]")

    for index, finding in enumerate(findings, start=1):
        console.print(f"\n[bold]{index}. {finding['title']}[/bold]")
        console.print(f"[red]Severity:[/red] {finding['severity']}")
        console.print(f"[yellow]Evidence:[/yellow] {finding['evidence']}")
        console.print(f"[cyan]Why it matters:[/cyan] {finding['why']}")
        console.print(f"[green]Recommendation:[/green] {finding['recommendation']}")


def display_final_summary(
    website_result: dict | None,
    email_result: dict | None,
    repository_result: dict | None
):
    summary_table = Table(title="Final Summary", box=box.DOUBLE_EDGE)
    summary_table.add_column("Component", style="cyan")
    summary_table.add_column("Score", style="bold white")
    summary_table.add_column("Rating", style="bold white")
    summary_table.add_column("Findings", justify="center")
    summary_table.add_column("Status", style="green")

    add_summary_row(summary_table, "Website", website_result)
    add_summary_row(summary_table, "Email / Domain", email_result)
    add_summary_row(summary_table, "Repository", repository_result)

    console.print("\n")
    console.print(summary_table)


def add_summary_row(table: Table, component_name: str, result: dict | None):
    if result is None:
        table.add_row(component_name, "Not scanned", "-", "-", "Skipped")
        return

    if result.get("error"):
        table.add_row(component_name, "Error", "-", "-", "Failed")
        return

    findings = result.get("findings", [])
    score_result = calculate_score(findings)

    status = "Good" if score_result["score"] >= 90 else "Needs review"

    table.add_row(
        component_name,
        f"{score_result['score']} / 100",
        score_result["rating"],
        str(len(findings)),
        status
    )