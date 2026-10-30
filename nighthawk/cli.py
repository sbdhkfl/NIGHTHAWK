"""NIGHTHAWK OSINT terminal interface.

Rich-powered CLI for running intelligence modules and managing investigations.
"""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from nighthawk.core.engine import Engine
from nighthawk.core.logging import get_logger

app = typer.Typer(
    name="nighthawk",
    help="NIGHTHAWK OSINT — See the public footprint.",
    no_args_is_help=True,
)
console = Console()
logger = get_logger("nighthawk.cli")

ASCII_LOGO = r"""
███╗   ███╗ █████╗ ███╗   ██╗██╗   ██╗ █████╗  ██████╗ ████████╗
████╗ ████║██╔══██╗████╗  ██║██║   ██║██╔══██╗██╔══██╗╚══██╔══╝
██╔████╔██║███████║██╔██╗ ██║██║   ██║███████║████████║   ██║
██║╚██╔╝██║██╔══██║██║╚██╗██║██║   ██║██╔══██║██╔══██║   ██║
██║ ╚═╝ ██║██║  ██║██║ ╚████║╚██████╔╝██║  ██║██║  ██║   ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
  See the public footprint.  v1.0.0
"""


def _show_banner() -> None:
    console.print(f"[green]{ASCII_LOGO}[/green]")


def _findings_table(title: str, rows: list[tuple[str, str, str, str]]) -> Table:
    table = Table(title=title, header_style="green")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Module")
    table.add_column("Target")
    table.add_column("Confidence")
    table.add_column("Source")
    for row in rows:
        table.add_row(*row)
    return table


@app.command()
def username(value: str) -> None:
    """Check a username against public profile URLs."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"username check: {value}")
    findings = engine.run_module(inv.id, "username", value, "username")
    _print_findings(findings)


@app.command()
def domain(value: str) -> None:
    """Run DNS and RDAP lookups for a domain."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"domain check: {value}")
    findings = engine.run_module(inv.id, "domain", value, "domain")
    _print_findings(findings)


@app.command()
def dns(value: str) -> None:
    """Resolve DNS records for a domain."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"dns check: {value}")
    findings = engine.run_module(inv.id, "dns", value, "dns")
    _print_findings(findings)


@app.command()
def subdomains(value: str) -> None:
    """Passively discover subdomains via Certificate Transparency (crt.sh)."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"subdomain check: {value}")
    findings = engine.run_module(inv.id, "subdomains", value, "subdomains")
    _print_findings(findings)


@app.command()
def ip(value: str) -> None:
    """Run IP intelligence (RDAP, reverse DNS, network range)."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"ip check: {value}")
    findings = engine.run_module(inv.id, "ip", value, "ip")
    _print_findings(findings)


@app.command()
def email(value: str) -> None:
    """Run email intelligence (syntax, MX, optional HIBP)."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"email check: {value}")
    findings = engine.run_module(inv.id, "email", value, "email")
    _print_findings(findings)


@app.command()
def cve(value: str) -> None:
    """Check a CVE identifier against CISA Known Exploited Vulnerabilities."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"CVE intelligence: {value}")
    try:
        findings = engine.run_module(inv.id, "cve", value, "kev")
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None
    _print_findings(findings)


@app.command()
def phone(value: str) -> None:
    """Inspect international phone-number numbering-plan metadata."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"phone metadata: {value}")
    try:
        findings = engine.run_module(inv.id, "phone", value, "phone")
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None
    _print_findings(findings)


@app.command()
def image(path: str) -> None:
    """Extract EXIF metadata from a local image file."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"image check: {path}")
    try:
        findings = engine.run_module(inv.id, "image", path, "image")
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None
    _print_findings(findings)


@app.command()
def search(query: str) -> None:
    """Search across configured public search providers."""
    _show_banner()
    engine = Engine()
    inv = engine.create_investigation(f"search: {query}")
    findings = engine.run_module(inv.id, "search", query, "search")
    _print_findings(findings)


@app.command()
def dashboard() -> None:
    """Launch the NIGHTHAWK web dashboard."""
    _show_banner()
    from nighthawk.dashboard.app import main

    console.print("[green]Starting dashboard at http://127.0.0.1:8000[/green]")
    main()


investigations_app = typer.Typer(name="investigations", help="Manage saved investigations.")
app.add_typer(investigations_app, name="investigations")


@investigations_app.command(name="list")
def investigations_list() -> None:
    """List saved investigations."""
    _show_banner()
    engine = Engine()
    invs = engine.list_investigations()
    table = Table(title="Investigations", header_style="green")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Targets", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Updated")
    for inv in invs:
        summary = engine.investigation_summary(inv.id) or {}
        table.add_row(
            str(inv.id),
            inv.name,
            str(summary.get("target_count", 0)),
            str(summary.get("finding_count", 0)),
            inv.updated_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


@investigations_app.command(name="view")
def investigations_view(investigation_id: int) -> None:
    """View details of a saved investigation."""
    _show_banner()
    engine = Engine()
    summary = engine.investigation_summary(investigation_id)
    if not summary:
        console.print(f"[red]Investigation {investigation_id} not found.[/red]")
        raise typer.Exit(code=1)
    console.print(f"[bold]{summary['name']}[/bold] ({summary['id']})")
    console.print(f"Targets: {summary['target_count']}  Findings: {summary['finding_count']}")
    rows = [
        (
            str(f["id"]),
            f["module"],
            f["target"],
            f["confidence"] or "none",
            f["source"] or "-",
        )
        for f in summary["findings"]
    ]
    console.print(_findings_table("Findings", rows))


@app.command(name="report")
def report_export(
    investigation_id: int = typer.Argument(..., help="Investigation ID"),
    format: str = typer.Option("json", "--format", "-f", help="json|csv|html"),
    output: str = typer.Option("nighthawk_report", "--output", "-o", help="output path"),
) -> None:
    """Export an investigation report."""
    _show_banner()
    from nighthawk.reporting import export_csv, export_html, export_json

    engine = Engine()
    if not engine.get_investigation(investigation_id):
        console.print(f"[red]Investigation {investigation_id} not found.[/red]")
        raise typer.Exit(code=1)

    fmt = format.lower()
    if fmt == "json":
        data = export_json(investigation_id, f"{output}.json" if not output.endswith(".json") else output)
        console.print(json.dumps(data, indent=2)[:2000])
        console.print("[green]Report written.[/green]")
    elif fmt == "csv":
        path = export_csv(investigation_id, f"{output}.csv" if not output.endswith(".csv") else output)
        console.print(f"[green]CSV report written to {path}[/green]")
    elif fmt == "html":
        path = export_html(investigation_id, f"{output}.html" if not output.endswith(".html") else output)
        console.print(f"[green]HTML report written to {path}[/green]")
    else:
        console.print(f"[red]Unknown format '{format}'. Use json, csv or html.[/red]")
        raise typer.Exit(code=1)


def _print_findings(findings: list[dict]) -> None:
    if not findings:
        console.print("[yellow]No findings.[/yellow]")
        return
    rows = [
        (
            str(f.get("id", "-")),
            f.get("module", "-"),
            f.get("target", "-"),
            f.get("confidence") or "none",
            f.get("source") or "-",
        )
        for f in findings
    ]
    console.print(_findings_table("Findings", rows))


if __name__ == "__main__":  # pragma: no cover
    _show_banner()
    app()
