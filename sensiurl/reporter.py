from __future__ import annotations

from typing import Iterable, List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import Finding, Severity


def print_results(findings: List[Finding], base_count: int, total_candidates: int) -> None:
    console = Console()

    # Header
    console.print(
        Panel.fit(
            "SensiURL - Sensitive URL Scanner",
            style="bold cyan",
            border_style="cyan",
        )
    )

    if not findings:
        console.print("[green]No sensitive exposures found.[/green]")
        return

    # Summary
    sev_counts = {s: 0 for s in Severity}
    for f in findings:
        sev_counts[f.severity] += 1

    summary = Table.grid(expand=False)
    summary.add_column(justify="left")
    summary.add_column(justify="right")
    summary.add_row("Targets", str(base_count))
    summary.add_row("Candidates", str(total_candidates))
    summary.add_row("Critical", f"[red]{sev_counts[Severity.CRITICAL]}[/red]")
    summary.add_row("High", f"[magenta]{sev_counts[Severity.HIGH]}[/magenta]")
    summary.add_row("Medium", f"[yellow]{sev_counts[Severity.MEDIUM]}[/yellow]")
    summary.add_row("Low", f"[green]{sev_counts[Severity.LOW]}[/green]")

    console.print(Panel(summary, title="Summary", border_style="blue", box=box.ROUNDED))

    # Findings table
    table = Table(
        title="Findings",
        expand=True,
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        header_style="bold",
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("URL", overflow="fold")
    table.add_column("Reason", overflow="fold")
    table.add_column("Evidence", overflow="fold")

    for f in findings:
        sev_style = _sev_style(f.severity)
        table.add_row(
            f"[{sev_style}]{f.severity.value}[/]",
            f.category.value,
            str(f.status_code or ""),
            f.url,
            f.reason,
            (f.evidence or "").replace("\n", " "),
        )

    console.print(table)


def _sev_style(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH: "bold white on magenta",
        Severity.MEDIUM: "bold black on yellow",
        Severity.LOW: "bold black on green",
    }[sev]
