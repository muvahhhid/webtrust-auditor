import argparse
import json
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from webtrust_auditor import __version__
from webtrust_auditor.email_scanner import scan_email_domain
from webtrust_auditor.pdf_generator import generate_pdf_report
from webtrust_auditor.references import enrich_result_references
from webtrust_auditor.report_generator import generate_markdown_report
from webtrust_auditor.repo_scanner import scan_repository
from webtrust_auditor.scoring import calculate_score
from webtrust_auditor.website_scanner import scan_website


console = Console()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        console.print(f"WebTrust Auditor v{__version__}")
        return

    website_result = None
    email_result = None
    repo_result = None

    console.print(
        Panel(
            f"WebTrust Auditor v{__version__}\n"
            "Defensive website, domain and repository security readiness checker.",
            title="Starting",
            border_style="cyan",
            box=box.ASCII,
            expand=False,
        )
    )

    if args.full_check and not args.url:
        console.print("[bold red]Error:[/bold red] --full-check requires --url.")
        return

    if args.url and args.full_check:
        console.print(
            Panel(
                "Full website check enabled.\n"
                "Use only for websites you own or are authorized to test.\n"
                "Fixed GET-only checklist. No brute-force, crawling, fuzzing, POST, exploit or bypass.",
                title="Authorized Full Check",
                border_style="yellow",
                box=box.ASCII,
                expand=False,
            )
        )

    if args.url:
        

        with console.status("[red]Checking website, please wait...[/red]", spinner="aesthetic"):
            website_result = scan_website(args.url, full_check=args.full_check)

        website_result = enrich_result_references(website_result)
        apply_score(website_result)

        console.print("[green]Website checks completed.[/green]")
        print_website_result(website_result, args.details)

    if args.domain:
        console.print("[cyan]Running email/domain checks...[/cyan]")

        with console.status("[bold cyan]Checking email/domain, please wait...[/bold cyan]", spinner="dots"):
            email_result = scan_email_domain(args.domain, args.dkim_selector)

        email_result = enrich_result_references(email_result)
        apply_score(email_result)

        console.print("[green]Email/domain checks completed.[/green]")
        print_email_result(email_result, args.details)

    if args.repo:
        console.print("[cyan]Running repository checks...[/cyan]")

        with console.status("[bold cyan]Checking repository, please wait...[/bold cyan]", spinner="dots"):
            repo_result = scan_repository(args.repo)

        repo_result = normalize_repository_display(repo_result, args.repo)
        repo_result = enrich_result_references(repo_result)
        apply_score(repo_result)

        console.print("[green]Repository checks completed.[/green]")
        print_repository_result(repo_result, args.details)

    print_final_summary(website_result, email_result, repo_result)

    if args.output:
        generate_markdown_report(
            output_path=args.output,
            website_result=website_result,
            email_result=email_result,
            repo_result=repo_result,
        )
        console.print(f"\n[green]Markdown report saved to:[/green] {Path(args.output).resolve()}")

    if args.json_output:
        save_json_output(
            output_path=args.json_output,
            website_result=website_result,
            email_result=email_result,
            repo_result=repo_result,
        )
        console.print(f"\n[green]JSON report saved to:[/green] {args.json_output}")

    if args.pdf_output:
        generate_pdf_report(
            output_path=args.pdf_output,
            website_result=website_result,
            email_result=email_result,
            repo_result=repo_result,
        )
        console.print(f"\n[green]PDF report saved to:[/green] {args.pdf_output}")

    if not args.output and not args.json_output and not args.pdf_output:
        console.print(
            "\n[dim]Tip: add --output reports/report.md, --json-output reports/result.json "
            "or --pdf-output reports/report.pdf if you also want a report file.[/dim]"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Defensive website, email/domain and repository security readiness checker."
    )

    parser.add_argument("--url", help="Website URL to scan.")
    parser.add_argument("--domain", help="Email/domain name or email address to scan.")
    parser.add_argument("--dkim-selector", help="Optional DKIM selector for domain checks.")
    parser.add_argument("--repo", help="Local repository path to scan.")
    parser.add_argument("--output", help="Save Markdown report to this path.")
    parser.add_argument("--json-output", help="Save JSON report to this path.")
    parser.add_argument("--pdf-output", help="Save PDF report to this path.")
    parser.add_argument("--details", action="store_true", help="Show detailed explanations.")
    parser.add_argument(
        "--full-check",
        action="store_true",
        help=(
            "Enable owner-authorized full website check. Uses a fixed curated list "
            "of low-impact GET-only exposure checks."
        ),
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit.")

    return parser


def normalize_repository_display(result: dict | None, repo_path: str) -> dict | None:
    if not result:
        return result

    resolved_path = Path(repo_path).resolve()

    result["display_path"] = str(resolved_path)

    if "has_gitignore" not in result:
        result["has_gitignore"] = (resolved_path / ".gitignore").exists()

    if "has_readme" not in result:
        result["has_readme"] = (
            (resolved_path / "README.md").exists()
            or (resolved_path / "readme.md").exists()
        )

    if "has_dockerfile" not in result:
        result["has_dockerfile"] = (
            (resolved_path / "Dockerfile").exists()
            or (resolved_path / "dockerfile").exists()
        )

    if "has_dockerignore" not in result:
        result["has_dockerignore"] = (resolved_path / ".dockerignore").exists()

    return result


def apply_score(result: dict | None) -> None:
    if not result:
        return

    score_data = calculate_score(result.get("findings", []))
    result["score"] = score_data["score"]
    result["rating"] = score_data["rating"]
    result["severity_counts"] = score_data["severity_counts"]


def get_first_value(result: dict, keys: list[str], default="N/A"):
    for key in keys:
        value = result.get(key)

        if value not in [None, ""]:
            return value

    return default


def get_bool_value(result: dict, keys: list[str]) -> bool:
    for key in keys:
        if result.get(key) is True:
            return True

    return False


def print_website_result(result: dict, show_details: bool = False) -> None:
    console.print("\n[bold cyan]Website Security[/bold cyan]")

    ssl_data = result.get("ssl", {}) or {}

    target_table = Table(title="Target", box=box.ASCII, header_style="bold cyan", show_lines=False)
    target_table.add_column("Item", style="bold")
    target_table.add_column("Value")

    target_table.add_row("Target URL", str(result.get("target_url") or "N/A"))
    target_table.add_row("Final URL", str(result.get("final_url") or "N/A"))
    target_table.add_row("Status Code", str(result.get("status_code") or "N/A"))
    target_table.add_row("HTTPS", "[green]Yes[/green]" if result.get("https") else "[red]No[/red]")

    if ssl_data.get("checked"):
        expires = ssl_data.get("not_after")
        days = ssl_data.get("days_until_expiry")
        target_table.add_row("SSL Expires", f"{expires} ({days} days left)")
    else:
        target_table.add_row("SSL Expires", "Not checked")

    target_table.add_row(
        "Full Check",
        "[yellow]Enabled[/yellow]" if result.get("full_check_enabled") else "Disabled",
    )

    if result.get("full_check_enabled"):
        target_table.add_row("Paths Tested", str(result.get("full_check_paths_tested", 0)))

    console.print(target_table)

    print_score_table("Website Score", result)
    print_findings(result)
    print_observations(result)

    if show_details:
        print_detailed_explanation(result)


def print_email_result(result: dict, show_details: bool = False) -> None:
    console.print("\n[bold cyan]Email / Domain Security[/bold cyan]")

    table = Table(title="DNS Summary", box=box.ASCII, header_style="bold cyan", show_lines=False)
    table.add_column("Item", style="bold")
    table.add_column("Value")

    table.add_row("Domain", str(result.get("domain") or "N/A"))
    table.add_row("MX Records", str(len(result.get("mx_records", []))))
    table.add_row("SPF Records", str(len(result.get("spf_records", []))))
    table.add_row("DMARC Record", "[green]Yes[/green]" if result.get("dmarc_record") else "[red]No[/red]")
    table.add_row("DMARC Policy", str(result.get("dmarc_policy") or "N/A"))
    table.add_row("DKIM Selector", str(result.get("dkim_selector") or "N/A"))
    table.add_row("DKIM Record", "[green]Yes[/green]" if result.get("dkim_record") else "No")

    console.print(table)

    print_score_table("Email Domain Score", result)
    print_findings(result)
    print_observations(result)

    if show_details:
        print_detailed_explanation(result)


def print_repository_result(result: dict, show_details: bool = False) -> None:
    console.print("\n[bold cyan]Repository Hygiene[/bold cyan]")

    table = Table(title="Repository Summary", box=box.ASCII, header_style="bold cyan", show_lines=False)
    table.add_column("Item", style="bold")
    table.add_column("Value")

    table.add_row(
        "Repository Path",
        str(get_first_value(result, ["display_path", "path", "repo_path", "repository_path", "target_path"])),
    )
    table.add_row("Files Checked", str(result.get("files_checked", 0)))
    table.add_row(
        ".gitignore",
        "[green]Yes[/green]"
        if get_bool_value(result, ["has_gitignore", "gitignore_exists", "gitignore_present", "gitignore"])
        else "[red]No[/red]",
    )
    table.add_row(
        "README.md",
        "[green]Yes[/green]"
        if get_bool_value(result, ["has_readme", "readme_exists", "readme_present", "readme"])
        else "[red]No[/red]",
    )
    table.add_row(
        "Dockerfile",
        "[green]Yes[/green]"
        if get_bool_value(result, ["has_dockerfile", "dockerfile_exists", "dockerfile_present", "dockerfile"])
        else "No",
    )
    table.add_row(
        ".dockerignore",
        "[green]Yes[/green]"
        if get_bool_value(result, ["has_dockerignore", "dockerignore_exists", "dockerignore_present", "dockerignore"])
        else "No",
    )
    table.add_row("Sensitive Files", str(len(result.get("sensitive_files", []))))
    table.add_row("Database Files", str(len(result.get("database_files", []))))
    table.add_row("Secret Hits", str(len(result.get("secret_hits", []))))

    console.print(table)

    print_score_table("Repository Score", result)
    print_findings(result)
    print_observations(result)

    if show_details:
        print_detailed_explanation(result)


def print_score_table(title: str, result: dict) -> None:
    counts = result.get("severity_counts", {})
    score = int(result.get("score", 0))

    table = Table(title=title, box=box.ASCII, header_style="bold cyan", show_lines=False)
    table.add_column("Score")
    table.add_column("Rating")
    table.add_column("High")
    table.add_column("Medium")
    table.add_column("Low")
    table.add_column("Info")

    table.add_row(
        format_score(score),
        str(result.get("rating", "-")),
        f"[bold red]{counts.get('High', 0)}[/bold red]",
        f"[bold yellow]{counts.get('Medium', 0)}[/bold yellow]",
        f"[bold blue]{counts.get('Low', 0)}[/bold blue]",
        f"[dim]{counts.get('Info', 0)}[/dim]",
    )

    console.print(table)


def print_findings(result: dict) -> None:
    findings = result.get("findings", [])

    if not findings:
        console.print("\n[bold green]No security findings found.[/bold green]")
        return

    table = Table(title="Findings", box=box.ASCII, header_style="bold cyan", show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Finding")
    table.add_column("Recommendation")

    for finding in findings:
        severity = str(finding.get("severity", "Info"))
        table.add_row(
            format_severity(severity),
            str(finding.get("title", "N/A")),
            str(finding.get("recommendation", "N/A")),
        )

    console.print(table)

    actionable = []
    seen_recommendations = set()

    for finding in findings:
        recommendation = finding.get("recommendation")

        if finding.get("severity") not in ["High", "Medium", "Low"]:
            continue

        if not recommendation:
            continue

        if recommendation in seen_recommendations:
            continue

        seen_recommendations.add(recommendation)
        actionable.append(recommendation)

    if actionable:
        console.print("[bold]Recommended next steps:[/bold]")

        for index, recommendation in enumerate(actionable, start=1):
            console.print(f"[cyan]{index}.[/cyan] {recommendation}")


def print_observations(result: dict) -> None:
    observations = result.get("observations", [])

    if not observations:
        return

    table = Table(title="Observations", box=box.ASCII, header_style="bold cyan", show_lines=False)
    table.add_column("Observation", style="bold")
    table.add_column("Details")

    for observation in observations:
        table.add_row(
            str(observation.get("title", "N/A")),
            str(observation.get("details", "N/A")),
        )

    console.print(table)


def print_detailed_explanation(result: dict) -> None:
    findings = result.get("findings", [])

    if not findings:
        return

    console.print("\n[bold cyan]Detailed Explanation[/bold cyan]")

    for index, finding in enumerate(findings, start=1):
        console.print(f"\n[bold]{index}. {finding.get('title', 'N/A')}[/bold]")
        console.print(f"Severity: {format_severity(finding.get('severity', 'Info'))}")
        console.print(f"Category: {finding.get('category', 'N/A')}")
        console.print(f"Evidence: {finding.get('evidence', 'N/A')}")
        console.print(f"Why it matters: {finding.get('why', 'N/A')}")
        console.print(f"Recommendation: {finding.get('recommendation', 'N/A')}")
        console.print(f"OWASP: {finding.get('owasp', 'Not directly mapped')}")
        console.print(f"CWE: {finding.get('cwe', 'Not directly mapped')}")

        references = finding.get("references", [])

        if references:
            console.print("References:")

            for reference in references:
                console.print(f"- {reference}")


def print_final_summary(website_result: dict | None, email_result: dict | None, repo_result: dict | None) -> None:
    table = Table(title="Final Summary", box=box.ASCII, header_style="bold cyan", show_lines=False)
    table.add_column("Component")
    table.add_column("Score")
    table.add_column("Rating")
    table.add_column("Findings")
    table.add_column("Status")

    add_summary_row(table, "Website", website_result)
    add_summary_row(table, "Email / Domain", email_result)
    add_summary_row(table, "Repository", repo_result)

    console.print("\n")
    console.print(table)


def add_summary_row(table: Table, name: str, result: dict | None) -> None:
    if not result:
        table.add_row(name, "Not scanned", "-", "-", "[dim]Skipped[/dim]")
        return

    score = int(result.get("score", 0))
    rating = result.get("rating", "-")
    findings_count = len(result.get("findings", []))
    status = "[green]Good[/green]" if score >= 75 else "[yellow]Needs review[/yellow]"

    table.add_row(
        name,
        format_score(score),
        str(rating),
        str(findings_count),
        status,
    )


def format_score(score: int) -> str:
    if score >= 90:
        return f"[bold green]{score} / 100[/bold green]"

    if score >= 75:
        return f"[green]{score} / 100[/green]"

    if score >= 40:
        return f"[yellow]{score} / 100[/yellow]"

    return f"[bold red]{score} / 100[/bold red]"


def format_severity(severity: str) -> str:
    styles = {
        "High": "[bold red]High[/bold red]",
        "Medium": "[bold yellow]Medium[/bold yellow]",
        "Low": "[bold blue]Low[/bold blue]",
        "Info": "[dim]Info[/dim]",
    }

    return styles.get(severity, severity)


def save_json_output(
    output_path: str,
    website_result: dict | None,
    email_result: dict | None,
    repo_result: dict | None,
) -> None:
    payload = {
        "tool": "WebTrust Auditor",
        "version": __version__,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "components": {
            "website": build_json_component(website_result),
            "email_domain": build_json_component(email_result),
            "repository": build_json_component(repo_result),
        },
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)


def build_json_component(result: dict | None) -> dict:
    if not result:
        return {
            "status": "skipped",
            "score": None,
            "rating": None,
            "severity_counts": None,
            "findings_count": None,
            "observations_count": None,
            "raw_result": None,
        }

    return {
        "status": "scanned",
        "score": result.get("score"),
        "rating": result.get("rating"),
        "severity_counts": result.get("severity_counts"),
        "findings_count": len(result.get("findings", [])),
        "observations_count": len(result.get("observations", [])),
        "raw_result": result,
    }