"""POAM Generator CLI — poam demo | generate | validate."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

from .demo_data import DEMO_FINDINGS
from .generate import write_csv, write_excel
from .oscal import write_oscal_json, write_oscal_xml
from .models import Finding, SEVERITY_ORDER
from .validate import validate_findings

console = Console()

SEVERITY_STYLES = {
    "Critical": "bold red",
    "High": "bold yellow",
    "Medium": "yellow",
    "Low": "bold green",
}

STATUS_STYLES = {
    "Open": "red",
    "In Progress": "yellow",
    "Closed": "green",
    "Risk Accepted": "cyan",
}


def _build_table(findings: list[Finding]) -> Table:
    table = Table(
        title="[bold blue]Plan of Action & Milestones (POAM)[/bold blue]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on blue",
        expand=True,
    )
    table.add_column("#", style="dim", width=3, no_wrap=True)
    table.add_column("Weakness Name", min_width=22)
    table.add_column("Control", width=9, no_wrap=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Source", width=18, no_wrap=True)
    table.add_column("Status", width=14, no_wrap=True)
    table.add_column("Detection", width=12, no_wrap=True)
    table.add_column("Due Date", width=12, no_wrap=True)
    table.add_column("Office/Org", min_width=18)
    table.add_column("POC", min_width=16)

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    for i, f in enumerate(sorted_findings, start=1):
        sev_style = SEVERITY_STYLES.get(f.severity, "")
        status_style = STATUS_STYLES.get(f.status, "")
        table.add_row(
            str(i),
            f.weakness_name,
            f"[bold]{f.security_control}[/bold]",
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.source,
            f"[{status_style}]{f.status}[/{status_style}]",
            f.detection_date,
            f.scheduled_completion,
            f.office_org,
            f.point_of_contact,
        )

    return table


@click.group()
@click.version_option("0.2.0", prog_name="poam")
def cli():
    """POAM Generator — create FedRAMP/FISMA Plan of Action & Milestones documents."""


@cli.command()
def demo():
    """Load 5 built-in demo findings and display a color-coded table, then save to poam_output.csv."""
    findings = [Finding.from_dict(d) for d in DEMO_FINDINGS]

    table = _build_table(findings)
    console.print()
    console.print(table)
    console.print()

    output_path = Path("poam_output.csv")
    write_csv(findings, output_path)
    console.print(
        f"[bold green]Saved {len(findings)} findings to[/bold green] [cyan]{output_path}[/cyan]"
    )

    _print_summary(findings)


@cli.command()
@click.option("-i", "--input", "input_file", required=True, type=click.Path(exists=True), help="JSON findings file")
@click.option("-o", "--output", "output_file", required=True, help="Output file path")
@click.option(
    "--format", "fmt",
    type=click.Choice(["csv", "excel", "oscal", "oscal-xml"], case_sensitive=False),
    default="csv", show_default=True,
    help="Output format: csv, excel, oscal (JSON), or oscal-xml",
)
def generate(input_file: str, output_file: str, fmt: str):
    """Read a JSON findings file and write a formatted POAM to CSV, Excel, or OSCAL."""
    try:
        with open(input_file, encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON in '{input_file}': {e}")
        sys.exit(1)

    if isinstance(raw, dict):
        raw = [raw]

    errors = validate_findings(raw)
    if errors:
        console.print("[bold red]Validation errors found — fix before generating:[/bold red]")
        for err in errors:
            console.print(f"  [red]•[/red] {err}")
        sys.exit(1)

    findings = [Finding.from_dict(d) for d in raw]

    output_path = Path(output_file)
    fmt_lower = fmt.lower()
    if fmt_lower == "excel":
        write_excel(findings, output_path)
        label = "Excel"
    elif fmt_lower == "oscal":
        write_oscal_json(findings, output_path)
        label = "OSCAL JSON"
    elif fmt_lower == "oscal-xml":
        write_oscal_xml(findings, output_path)
        label = "OSCAL XML"
    else:
        write_csv(findings, output_path)
        label = "CSV"

    table = _build_table(findings)
    console.print()
    console.print(table)
    console.print()
    console.print(
        f"[bold green]Wrote {len(findings)} findings to {label}:[/bold green] [cyan]{output_path}[/cyan]"
    )
    _print_summary(findings)


@cli.command()
@click.option("-i", "--input", "input_file", required=True, type=click.Path(exists=True), help="JSON findings file to validate")
def validate(input_file: str):
    """Check a JSON findings file for missing fields and invalid values."""
    try:
        with open(input_file, encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON in '{input_file}': {e}")
        sys.exit(1)

    if isinstance(raw, dict):
        raw = [raw]

    errors = validate_findings(raw)

    if errors:
        console.print(f"[bold red]Found {len(errors)} validation error(s) in '{input_file}':[/bold red]\n")
        for err in errors:
            console.print(f"  [red]x[/red]  {err}")
        console.print()
        sys.exit(1)
    else:
        console.print(
            f"[bold green]OK All {len(raw)} finding(s) in '{input_file}' are valid.[/bold green]"
        )


def _print_summary(findings: list[Finding]) -> None:
    from collections import Counter

    sev_counts = Counter(f.severity for f in findings)
    status_counts = Counter(f.status for f in findings)

    console.print("[bold]Summary:[/bold]")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = sev_counts.get(sev, 0)
        if count:
            style = SEVERITY_STYLES.get(sev, "")
            console.print(f"  [{style}]{sev}[/{style}]: {count}")

    console.print()
    for status in ["Open", "In Progress", "Closed", "Risk Accepted"]:
        count = status_counts.get(status, 0)
        if count:
            style = STATUS_STYLES.get(status, "")
            console.print(f"  [{style}]{status}[/{style}]: {count}")
    console.print()
