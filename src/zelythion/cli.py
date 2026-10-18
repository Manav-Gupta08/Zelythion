"""
Zelythion CLI — entry point using Typer.

Commands:
    zelythion scan <URL>       Run a security scan against an authorized target.
    zelythion checks list      List all available security checks.
    zelythion --version        Print scanner version.
"""

from __future__ import annotations

import sys
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from zelythion import __version__, AUTHORIZATION_NOTICE
from zelythion.checks.cookies import ALL_COOKIE_CHECKS
from zelythion.checks.headers import ALL_HEADER_CHECKS
from zelythion.config import ScanConfig, ScanProfile, OutputFormat
from zelythion.scope import ScopeValidator, ScopeError

app = typer.Typer(
    name="zelythion",
    help="Zelythion — An evidence-driven web application security scanner.",
    add_completion=False,
    no_args_is_help=True,
)

checks_app = typer.Typer(name="checks", help="Manage and list security checks.", no_args_is_help=True)
app.add_typer(checks_app, name="checks")

console = Console(stderr=False)
err_console = Console(stderr=True)

# Severity colours for Rich output.
_SEVERITY_COLOUR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------

def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Zelythion v{__version__}")
        raise typer.Exit()


# ---------------------------------------------------------------------------
# zelythion scan
# ---------------------------------------------------------------------------

@app.command("scan")
def scan(
    target: Annotated[str, typer.Argument(help="Target URL to scan (must be an authorized target).")],
    profile: Annotated[
        ScanProfile,
        typer.Option("--profile", "-p", help="Scan profile: passive (default) or active."),
    ] = ScanProfile.passive,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: text (default), json, or html."),
    ] = OutputFormat.text,
    output: Annotated[
        Optional[str],
        typer.Option("--output", "-o", help="Write report to this file path."),
    ] = None,
    depth: Annotated[
        int,
        typer.Option("--depth", help="Maximum crawl depth.", min=0, max=10),
    ] = 2,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Per-request timeout in seconds.", min=1.0, max=120.0),
    ] = 10.0,
    max_pages: Annotated[
        int,
        typer.Option("--max-pages", help="Maximum pages to crawl.", min=1, max=500),
    ] = 50,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output.")] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip the authorization confirmation prompt."),
    ] = False,
) -> None:
    """Run a security scan against an authorized target URL."""

    # --- Authorization gate ---
    if not yes:
        console.print(
            Panel(
                Text(AUTHORIZATION_NOTICE, style="yellow"),
                title="[bold red]⚠ Authorization Required[/bold red]",
                border_style="red",
            )
        )
        confirmed = typer.confirm("Do you confirm you are authorized to scan this target?")
        if not confirmed:
            err_console.print("[red]Scan cancelled — authorization not confirmed.[/red]")
            raise typer.Exit(code=1)

    # --- Target scope pre-validation ---
    try:
        validator = ScopeValidator()
        normalized = validator.validate_target_url(target)
    except ScopeError as exc:
        err_console.print(f"[red][SCOPE ERROR][/red] {exc}")
        raise typer.Exit(code=2) from None

    # --- Build config ---
    config = ScanConfig(
        target=normalized,
        profile=profile,
        output_format=output_format,
        output_file=output,
        max_depth=depth,
        timeout=timeout,
        max_pages=max_pages,
        verbose=verbose,
    )

    if verbose:
        console.print(f"[dim]Target   :[/dim] {config.target}")
        console.print(f"[dim]Profile  :[/dim] {config.profile.value}")
        console.print(f"[dim]Format   :[/dim] {config.output_format.value}")
        console.print(f"[dim]Checks   :[/dim] {len(ALL_HEADER_CHECKS) + len(ALL_COOKIE_CHECKS)} enabled")
        console.print(f"[dim]Timeout  :[/dim] {config.timeout}s")

    if profile == ScanProfile.active:
        console.print(
            Panel(
                "[bold yellow]Active scanning is enabled.[/bold yellow]\n"
                "This will send additional test requests to the target.\n"
                "Ensure you have explicit authorization for active testing.",
                title="[bold orange1]Active Scan Mode[/bold orange1]",
                border_style="orange1",
            )
        )

    console.print(f"\n[bold green]Starting scan:[/bold green] {config.target}")
    console.print(f"[dim]Profile: {profile.value}[/dim]\n")

    # --- Run scan ---
    from zelythion.orchestrator import ScanOrchestrator
    from zelythion.reporting.json_report import generate_json_report, generate_json_report_to_file
    from rich.progress import Progress, SpinnerColumn, TextColumn

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning…", total=None)
        orchestrator = ScanOrchestrator(config)
        result = orchestrator.run()

    # --- Output ---
    if output_format == OutputFormat.json:
        report_str = generate_json_report(result)
        if output:
            generate_json_report_to_file(result, output)
            console.print(f"[green]Report written to:[/green] {output}")
        else:
            console.print(report_str)

    else:
        # Text output — rich summary table
        _print_text_summary(result)
        if output:
            # Write JSON even when text is the display format, if a file is requested.
            generate_json_report_to_file(result, output)
            console.print(f"\n[green]JSON report written to:[/green] {output}")

    # Exit code reflects highest severity found.
    exit_code = _exit_code(result)
    raise typer.Exit(code=exit_code)


def _print_text_summary(result: object) -> None:
    """Print a Rich-formatted scan summary to the console."""
    from zelythion.models import ScanResult
    assert isinstance(result, ScanResult)

    counts = result.summary_counts()
    duration = result.stats.duration_seconds

    console.print(f"[bold]Scan complete[/bold] in {duration:.1f}s — "
                  f"{result.stats.total_requests} request(s), "
                  f"{result.stats.checks_executed} check(s) run\n")

    if result.errors:
        for err in result.errors:
            console.print(f"[yellow]⚠ {err}[/yellow]")
        console.print()

    if not result.findings:
        console.print("[green]✓ No findings detected.[/green]")
        console.print("[dim]Note: absence of findings is not proof of security.[/dim]")
        return

    # Findings table
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Severity", width=10)
    table.add_column("ID", width=9)
    table.add_column("Title", width=55)
    table.add_column("URL")

    from zelythion.models import Severity as Sev
    order = [Sev.critical, Sev.high, Sev.medium, Sev.low, Sev.info]
    grouped = result.findings_by_severity()

    for sev in order:
        for f in grouped.get(sev.value, []):
            colour = _SEVERITY_COLOUR.get(sev.value, "white")
            table.add_row(
                f"[{colour}]{sev.value.upper()}[/{colour}]",
                f.check_id,
                f.title[:55],
                f.affected_url,
            )

    console.print(table)
    console.print()

    # Summary line
    parts = []
    for sev in order:
        n = counts.get(sev.value, 0)
        if n:
            colour = _SEVERITY_COLOUR.get(sev.value, "white")
            parts.append(f"[{colour}]{n} {sev.value}[/{colour}]")
    console.print("Findings: " + "  ".join(parts))


def _exit_code(result: object) -> int:
    """Return a shell exit code based on the highest finding severity."""
    from zelythion.models import ScanResult, Severity as Sev
    assert isinstance(result, ScanResult)
    counts = result.summary_counts()
    if counts.get(Sev.critical.value, 0):
        return 5
    if counts.get(Sev.high.value, 0):
        return 4
    if counts.get(Sev.medium.value, 0):
        return 3
    if counts.get(Sev.low.value, 0):
        return 2
    if counts.get(Sev.info.value, 0):
        return 1
    return 0


# ---------------------------------------------------------------------------
# zelythion checks list
# ---------------------------------------------------------------------------

@checks_app.command("list")
def checks_list() -> None:
    """List all available security checks."""
    table = Table(title="Available Security Checks", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Name", width=40)
    table.add_column("OWASP", width=10)
    table.add_column("Mode", width=9)
    table.add_column("Status", width=11)

    active_checks = [
        ("HDR-001", "Missing Content-Security-Policy", "A02:2025", "Passive", "[green]Active[/green]"),
        ("HDR-002", "Missing X-Content-Type-Options", "A02:2025", "Passive", "[green]Active[/green]"),
        ("HDR-003", "Missing X-Frame-Options", "A02:2025", "Passive", "[green]Active[/green]"),
        ("HDR-004", "Missing HSTS", "A04:2025", "Passive", "[green]Active[/green]"),
        ("HDR-005", "Missing Referrer-Policy", "A02:2025", "Passive", "[green]Active[/green]"),
        ("HDR-006", "Missing Permissions-Policy", "A02:2025", "Passive", "[green]Active[/green]"),
        ("HDR-007", "Server version disclosure", "A02:2025", "Passive", "[green]Active[/green]"),
        ("CKI-001", "Cookie missing Secure flag", "A02:2025", "Passive", "[green]Active[/green]"),
        ("CKI-002", "Cookie missing HttpOnly flag", "A02:2025", "Passive", "[green]Active[/green]"),
        ("CKI-003", "Cookie missing/weak SameSite", "A02:2025", "Passive", "[green]Active[/green]"),
        ("TLS-001", "HTTP instead of HTTPS", "A04:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("TLS-002", "Certificate validity check", "A04:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("DSC-001", "Directory listing exposed", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
    ]

    for row in active_checks:
        table.add_row(*row)

    console.print(table)
    console.print(
        f"\n[dim]{sum(1 for r in active_checks if 'Active' in r[4])} active checks  |  "
        f"{sum(1 for r in active_checks if 'Planned' in r[4])} planned checks[/dim]"
    )


# ---------------------------------------------------------------------------
# Root --version flag
# ---------------------------------------------------------------------------

@app.callback(invoke_without_command=True)
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Zelythion — An extensible, evidence-driven web application security scanner."""


if __name__ == "__main__":
    app()
