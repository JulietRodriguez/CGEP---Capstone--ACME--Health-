"""Rich-powered command line interface for oscal-ssp-generator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .controls import control_title
from .generator import generate_ssp, summarize
from .parsers import ParseError, parse

console = Console()

BANNER = r"""
  ___  ____   ___    _    _       ____ ____  ____
 / _ \/ ___| / __|  / \  | |     / ___/ ___||  _ \
| | | \___ \| |    / _ \ | |     \___ \___ \| |_) |
| |_| |___) | |__ / ___ \| |___   ___) |__) |  __/
 \___/|____/ \___/_/   \_\_____| |____/____/|_|
"""


def _print_banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        f"[dim]OSCAL 1.1.2 SSP Generator · v{__version__} · "
        f"FedRAMP Moderate (NIST 800-53 Rev 5)[/dim]\n"
    )


def _render_summary(summary: dict) -> None:
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("System:", f"[cyan]{summary['system_name']}[/cyan]")
    header.add_row("Source:", summary["source"])
    header.add_row("Resources:", str(summary["resource_count"]))
    header.add_row(
        "Controls satisfied:",
        f"[green]{len(summary['controls_satisfied'])}[/green]",
    )
    header.add_row(
        "Controls planned:",
        f"[yellow]{len(summary['controls_planned'])}[/yellow]",
    )
    console.print(Panel(header, title="System Overview", border_style="cyan"))

    rtable = Table(title="Discovered Resources", header_style="bold magenta", expand=True)
    rtable.add_column("Resource Type", style="cyan")
    rtable.add_column("Count", justify="right", style="white")
    for rtype, count in summary["resource_types"].items():
        rtable.add_row(rtype, str(count))
    console.print(rtable)

    ctable = Table(
        title="FedRAMP Moderate Control Coverage",
        header_style="bold magenta",
        expand=True,
    )
    ctable.add_column("Control", style="cyan", no_wrap=True)
    ctable.add_column("Title", style="white")
    ctable.add_column("Status", justify="center")
    ctable.add_column("Evidence", style="dim")
    evidence = summary["control_evidence"]
    for control in summary["controls_satisfied"]:
        ctable.add_row(
            control,
            control_title(control),
            "[green]implemented[/green]",
            ", ".join(evidence.get(control, [])),
        )
    for control in summary["controls_planned"]:
        ctable.add_row(
            control,
            control_title(control),
            "[yellow]planned[/yellow]",
            "—",
        )
    console.print(ctable)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oscal-ssp-generator",
        description="Generate a draft OSCAL 1.1.2 SSP from AWS infrastructure inventory.",
    )
    parser.add_argument("input", nargs="?", help="Path to a Terraform state (*.tfstate) or JSON inventory file.")
    parser.add_argument(
        "-o",
        "--output",
        help="Write the OSCAL SSP JSON to this path (default: stdout when --json, else none).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the OSCAL SSP JSON to stdout instead of the formatted summary.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"oscal-ssp-generator {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.input:
        parser.print_help()
        return 1

    try:
        inventory = parse(args.input)
    except ParseError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    ssp = generate_ssp(inventory)
    summary = summarize(inventory)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(ssp, indent=2), encoding="utf-8")

    if args.json:
        console.print_json(json.dumps(ssp))
        return 0

    if not args.no_banner:
        _print_banner()
    _render_summary(summary)

    if args.output:
        console.print(
            f"\n[green]✓[/green] OSCAL 1.1.2 SSP written to [cyan]{args.output}[/cyan] "
            f"({len(ssp['system-security-plan']['control-implementation']['implemented-requirements'])} "
            f"implemented requirements)."
        )
    else:
        console.print(
            "\n[dim]Tip: pass [cyan]-o ssp.json[/cyan] to write the OSCAL document, "
            "or [cyan]--json[/cyan] to print it.[/dim]"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
