"""Rich console output for CryptoRecon."""

from __future__ import annotations

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from crypto_recon.models.asset import Asset
from crypto_recon.models.finding import Finding, Severity
from crypto_recon.models.report import Report

SEVERITY_COLORS: dict[str, str] = {
    Severity.CRITICAL.value: "bold red",
    Severity.HIGH.value: "red",
    Severity.MEDIUM.value: "yellow",
    Severity.LOW.value: "cyan",
    Severity.INFO.value: "white",
}

SEVERITY_ICONS: dict[str, str] = {
    Severity.CRITICAL.value: "🔴",
    Severity.HIGH.value: "🟠",
    Severity.MEDIUM.value: "🟡",
    Severity.LOW.value: "🔵",
    Severity.INFO.value: "⚪",
}

_BANNER = r"""[cyan]
   ______                 __                                
  / ____/___  ____  _____/ /_____  ____ ___  ___  ____ ___ 
 / /   / __ \/ __ \/ ___/ __/ __ \/ __ `__ \/ _ \/ __ `__ \
/ /___/ /_/ / / / (__  ) /_/ /_/ / / / / / /  __/ / / / / /
\____/\____/_/ /_/____/\__/\____/_/ /_/ /_/\___/_/ /_/ /_/ 

              CryptoRecon v2.1 - CBOM Discovery Tool
[/cyan]"""


class ConsoleOutput:
    """Render findings and reports to a Rich-formatted terminal."""

    def __init__(self, no_color: bool = False) -> None:
        """Initialise the output handler.

        Args:
            no_color: If *True*, suppress colours and icons.
        """
        self.console = Console(highlight=False, no_color=no_color)

    def print_banner(self) -> None:
        """Print the CryptoRecon ASCII-art banner."""
        self.console.print(_BANNER)

    def print_findings(self, findings: List[Finding]) -> None:
        """Render a table of *findings* to the console.

        Args:
            findings: List of :class:`Finding` objects to display.
        """
        if not findings:
            self.console.print("[green]No findings.[/green]")
            return

        table = Table(
            title="Findings",
            show_lines=True,
            header_style="bold blue",
            expand=True,
        )
        table.add_column("Sev", style="bold", width=4, no_wrap=True)
        table.add_column("Category", width=12)
        table.add_column("Title")
        table.add_column("Evidence", overflow="fold")
        table.add_column("Conf", width=6)

        for finding in sorted(findings, key=lambda f: list(Severity).index(f.severity)):
            sev_val = finding.severity.value
            icon = SEVERITY_ICONS.get(sev_val, "")
            color = SEVERITY_COLORS.get(sev_val, "white")
            table.add_row(
                Text(f"{icon}", style=color),
                Text(finding.category.value, style="dim"),
                Text(finding.title, style=color),
                Text(finding.evidence.summary() if finding.evidence else "—", style="dim"),
                Text(finding.confidence.value, style="dim"),
            )

        self.console.print(table)

    def print_assets(self, assets: List[Asset]) -> None:
        """Render a table of *assets* to the console.

        Args:
            assets: List of :class:`Asset` objects to display.
        """
        if not assets:
            self.console.print("[green]No assets discovered.[/green]")
            return

        table = Table(
            title="Assets",
            show_lines=True,
            header_style="bold green",
            expand=True,
        )
        table.add_column("Type", width=16)
        table.add_column("Name")
        table.add_column("Evidence", overflow="fold")
        table.add_column("Conf", width=6)

        for asset in sorted(assets, key=lambda a: a.asset_type.value):
            table.add_row(
                Text(asset.asset_type.value, style="dim"),
                Text(asset.name, style="white"),
                Text(asset.evidence.summary() if asset.evidence else "—", style="dim"),
                Text(asset.confidence.value, style="dim"),
            )

        self.console.print(table)

    def print_summary(self, report: Report) -> None:
        """Render an executive summary panel.

        Args:
            report: Completed :class:`Report` to summarise.
        """
        summary = report.summary()
        by_sev = summary["by_severity"]

        lines: list[str] = [
            f"[bold]Target:[/bold]  {report.target}",
            f"[bold]Type:[/bold]    {report.scan_type}",
            f"[bold]Total:[/bold]   {summary['total_findings']} findings",
            f"[bold]Assets:[/bold]  {summary['total_assets']} assets",
            "",
        ]

        for sev in Severity:
            count = by_sev.get(sev.value, 0)
            color = SEVERITY_COLORS[sev.value]
            icon = SEVERITY_ICONS[sev.value]
            lines.append(f"  {icon} [{color}]{sev.value.upper():8s}[/{color}] {count}")

        asset_counts = summary.get("by_asset_type", {})
        if asset_counts:
            lines.append("")
            lines.append("[bold]Assets by type:[/bold]")
            for asset_type, count in sorted(asset_counts.items()):
                lines.append(f"  • {asset_type}: {count}")

        if summary.get("duration_seconds") is not None:
            lines.append(f"\n[bold]Duration:[/bold] {summary['duration_seconds']:.1f}s")

        self.console.print(
            Panel("\n".join(lines), title="[bold cyan]Scan Summary[/bold cyan]", expand=False)
        )

    def create_progress(self) -> Progress:
        """Return a configured :class:`~rich.progress.Progress` context manager.

        Returns:
            :class:`rich.progress.Progress` instance ready to use as a context manager.
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True,
        )
