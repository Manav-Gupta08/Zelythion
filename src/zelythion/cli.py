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
        typer.Option("--format", "-f", help="Output format: text (default) or json."),
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

    # --- Target scope validation ---
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
        console.print(f"[dim]Depth    :[/dim] {config.max_depth}")
        console.print(f"[dim]Timeout  :[/dim] {config.timeout}s")
        console.print(f"[dim]MaxPages :[/dim] {config.max_pages}")

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
    console.print(f"[dim]Profile: {profile.value} | Checks: loading…[/dim]\n")

    # Scanning engine not yet implemented — placeholder output
    _run_placeholder_scan(config)


def _run_placeholder_scan(config: ScanConfig) -> None:
    """Placeholder scan runner used before the engine is implemented."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import time

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Reconnaissance…", total=None)
        time.sleep(0.4)
        progress.update(task, description="Checking security headers…")
        time.sleep(0.3)
        progress.update(task, description="Inspecting cookies…")
        time.sleep(0.3)
        progress.update(task, description="Finalizing…")
        time.sleep(0.2)

    console.print(
        Panel(
            "[bold yellow]Scan engine not yet implemented.[/bold yellow]\n\n"
            "Phase 0 establishes the project skeleton, CLI, config, scope enforcement,\n"
            "and finding models. The HTTP client and security checks are implemented\n"
            "in Phase 1 and Phase 2 respectively.\n\n"
            f"[dim]Target: {config.target}[/dim]",
            title="[bold]Zelythion — Phase 0[/bold]",
            border_style="blue",
        )
    )
    console.print("\n[dim]No findings produced — engine not yet active.[/dim]")


# ---------------------------------------------------------------------------
# zelythion checks list
# ---------------------------------------------------------------------------

@checks_app.command("list")
def checks_list() -> None:
    """List all available security checks."""
    table = Table(title="Available Security Checks", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim", width=20)
    table.add_column("Name", width=35)
    table.add_column("OWASP", width=12)
    table.add_column("Mode", width=10)
    table.add_column("Status", width=12)

    planned_checks = [
        ("HDR-001", "Missing Content-Security-Policy", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("HDR-002", "Missing X-Content-Type-Options", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("HDR-003", "Missing X-Frame-Options", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("HDR-004", "Missing HSTS", "A04:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("HDR-005", "Missing Referrer-Policy", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("HDR-006", "Missing Permissions-Policy", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("CKI-001", "Cookie missing Secure flag", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("CKI-002", "Cookie missing HttpOnly flag", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("CKI-003", "Cookie missing SameSite attribute", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("TLS-001", "HTTP used instead of HTTPS", "A04:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("TLS-002", "Certificate validity check", "A04:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("DSC-001", "Server version disclosure", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
        ("DSC-002", "Directory listing exposed", "A02:2025", "Passive", "[yellow]Planned[/yellow]"),
    ]

    for row in planned_checks:
        table.add_row(*row)

    console.print(table)
    console.print(
        "\n[dim]Checks marked [yellow]Planned[/yellow] are scheduled for Phase 2+. "
        "Run [bold]zelythion scan <URL>[/bold] to execute implemented checks.[/dim]"
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
