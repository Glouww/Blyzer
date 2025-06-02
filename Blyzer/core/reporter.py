"""
core/reporter.py

This module formats and displays an analysis's results from the analyser modules,
using the rich and colorama python libraries for a more readable output.
"""

from typing import List, Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from colorama import init as colorama_init

colorama_init(autoreset=True)

console = Console(theme=Theme({
    "banner": "bold magenta",
    "header": "bold cyan",
    "finding": "bold yellow",
    "label": "bold green",
    "summary": "bold white",
    "none": "bold green",
    "critical": "bold red",
    "warning": "bold yellow",
    "line": "dim",
}))


def printFindings(findings: Dict[str, List[Dict[str, Any]]]) -> None:
    """
    Prints formatted vulnerability findings.

    Args:
        findings (dict[str, list[dict]]): Dictionary of findings by analyzer type,
            where each analyzer's findings are a list of dicts with keys like
            'function_name', 'line_number', and 'issue_description'.
    """
    total_findings = sum(len(f) for f in findings.values())

    if total_findings == 0:
        console.print(Panel(Text("No vulnerabilities detected.", style="none"), style="green", expand=False))
        return

    console.print("\n[bold magenta]= ANALYSIS RESULTS =[/bold magenta]\n")

    for analyzer_type, analyzer_findings in findings.items():
        if not analyzer_findings:
            continue

        banner_text = f" {analyzer_type.replace('_', ' ').title()} Issues "
        console.print(Panel(banner_text, style="banner", expand=False))

        for idx, finding in enumerate(analyzer_findings, 1):
            table = Table.grid(padding=(0, 1))
            table.add_column(justify="right", style="label")
            table.add_column()
            table.add_row("[finding]Finding:[/finding]", f"[bold]{idx}[/bold]")
            table.add_row("[label]Function Name:[/label]", f"{finding.get('function_name', '<unknown>')}")
            table.add_row("[label]Line Number:[/label]", f"{finding.get('line_number', '<unknown>')}")
            # Optional: Add severity if present
            severity = finding.get("severity", None)
            if severity:
                sev_style = "critical" if severity.lower() == "critical" else "warning"
                table.add_row("[label]Severity[/label]", f"[{sev_style}]{severity.title()}[/{sev_style}]")
            table.add_row("[label]Description:[/label]", f"{finding.get('issue_description', '')}")
            console.print(table)
            console.print("[line]" + "-" * 60 + "[/line]")

    # Summary
    console.print("\n[summary]Summary:[/summary]")
    summary_table = Table(show_header=True, header_style="bold blue")
    summary_table.add_column("Analyzer Type", style="header")
    summary_table.add_column("Findings", style="header", justify="right")
    for analyzer_type, analyzer_findings in findings.items():
        summary_table.add_row(analyzer_type.replace('_', ' ').title(), str(len(analyzer_findings)))
    summary_table.add_row("[bold]Total[/bold]", f"[bold]{total_findings}[/bold]")
    console.print(summary_table)