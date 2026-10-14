"""Command-line interface for Purple-Team Cyber Range using Typer and Rich."""

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from purple_range import __version__
from purple_range.advisor.advisor import DetectionTuningAdvisor
from purple_range.analytics.reporter import HeatmapReporter
from purple_range.config.settings import get_settings
from purple_range.db.connection import DatabaseManager
from purple_range.db.repository import PurpleRangeRepository
from purple_range.detection.normalizer import AlertNormalizer
from purple_range.emulation.catalog import TechniqueRegistry
from purple_range.models.enums import MitreTactic, TechniqueSeverity
from purple_range.orchestrator.service import CampaignOrchestrator

app = typer.Typer(
    name="purple",
    help="Purple-Team Cyber Range CLI: Adversary Emulation and Detection Verification.",
    no_args_is_help=True,
)
console = Console()

techniques_app = typer.Typer(help="Manage and inspect MITRE ATT&CK adversary techniques.")
playbooks_app = typer.Typer(help="Inspect and run adversary scenario playbooks.")
telemetry_app = typer.Typer(help="Ingest and view defensive sensor alerts.")

app.add_typer(techniques_app, name="techniques")
app.add_typer(playbooks_app, name="playbooks")
app.add_typer(telemetry_app, name="telemetry")


def _get_repository() -> PurpleRangeRepository:
    """Initialize repository from settings."""
    settings = get_settings()
    manager = DatabaseManager(settings.db_path, timeout_seconds=settings.db_timeout_seconds)
    repo = PurpleRangeRepository(manager)
    repo.initialize_schema()
    return repo


@app.command("version")
def show_version() -> None:
    """Print Purple-Team Cyber Range platform version."""
    console.print(
        Panel.fit(
            f"[bold magenta]Purple-Team Cyber Range[/bold magenta] v{__version__}\n"
            "[dim]Adversary Emulation & MITRE ATT&CK Detection Verification[/dim]",
            border_style="cyan",
        )
    )


# --- Techniques Commands ---
@techniques_app.command("list")
def list_techniques(
    tactic: Annotated[
        MitreTactic | None,
        typer.Option("--tactic", "-t", help="Filter techniques by MITRE tactic"),
    ] = None,
) -> None:
    """List registered adversary techniques mapped to MITRE ATT&CK."""
    registry = TechniqueRegistry()
    techs = registry.filter_by_tactic(tactic) if tactic else registry.list_all()

    table = Table(
        title="[bold cyan]MITRE ATT&CK Emulation Catalog[/bold cyan]",
        header_style="bold white on navy_blue",
    )
    table.add_column("Technique ID", style="bold yellow", width=14)
    table.add_column("Technique Name", style="white", min_width=24)
    table.add_column("Tactic", style="dim cyan", width=20)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Platform", justify="center", width=10)

    for tech in sorted(techs, key=lambda t: (t.tactic.value, t.technique_id)):
        table.add_row(
            tech.technique_id,
            tech.name,
            tech.tactic.value,
            tech.severity.value,
            tech.platform.value,
        )

    console.print(table)


@techniques_app.command("show")
def show_technique(
    technique_id: Annotated[str, typer.Argument(help="Technique ID (e.g. T1087.001)")],
) -> None:
    """Display comprehensive technical specifications for a single technique."""
    registry = TechniqueRegistry()
    tech = registry.get(technique_id)
    if not tech:
        console.print(f"[bold red]Error:[/bold red] Technique '{technique_id}' not found.")
        raise typer.Exit(code=1)

    cmd_template = f"  [green]{tech.command_template}[/green]"
    cleanup_cmd = f"  [red]{tech.cleanup_command or 'None'}[/red]"
    ds_str = ", ".join(ds.value for ds in tech.data_sources)
    details = (
        f"[bold yellow]ID:[/bold yellow] {tech.technique_id}\n"
        f"[bold yellow]Name:[/bold yellow] {tech.name}\n"
        f"[bold yellow]Tactic:[/bold yellow] {tech.tactic.value}\n"
        f"[bold yellow]Severity:[/bold yellow] {tech.severity.value}\n"
        f"[bold yellow]Description:[/bold yellow] {tech.description}\n"
        f"[bold yellow]Command Template:[/bold yellow]\n{cmd_template}\n"
        f"[bold yellow]Cleanup Command:[/bold yellow]\n{cleanup_cmd}\n"
        f"[bold yellow]Data Sources:[/bold yellow] {ds_str}"
    )
    console.print(
        Panel(
            details,
            title=f"Technique Details: {tech.technique_id}",
            border_style="blue",
        )
    )


# --- Playbooks Commands ---
@playbooks_app.command("list")
def list_playbooks() -> None:
    """List registered adversary attack scenario playbooks."""
    repo = _get_repository()
    playbooks = repo.list_playbooks()

    table = Table(
        title="[bold magenta]Adversary Scenario Playbooks[/bold magenta]",
        header_style="bold white on dark_green",
    )
    table.add_column("Playbook ID", style="bold yellow", width=26)
    table.add_column("Playbook Name", style="white", min_width=24)
    table.add_column("Techniques Count", justify="right", width=16)
    table.add_column("Author", style="dim", width=24)

    for pb in playbooks:
        table.add_row(
            pb.playbook_id,
            pb.name,
            str(len(pb.technique_ids)),
            pb.author,
        )

    console.print(table)


@playbooks_app.command("show")
def show_playbook(
    playbook_id: Annotated[str, typer.Argument(help="Playbook ID (e.g. ransomware-killchain)")],
) -> None:
    """Display ordered technique sequence for a specific playbook."""
    repo = _get_repository()
    pb = repo.get_playbook(playbook_id)
    if not pb:
        console.print(f"[bold red]Error:[/bold red] Playbook '{playbook_id}' not found.")
        raise typer.Exit(code=1)

    seq_str = "\n".join(
        f"  {idx + 1}. [cyan]{tid}[/cyan]" for idx, tid in enumerate(pb.technique_ids)
    )
    console.print(
        Panel(
            f"[bold yellow]Name:[/bold yellow] {pb.name}\n"
            f"[bold yellow]Description:[/bold yellow] {pb.description}\n"
            f"[bold yellow]Author:[/bold yellow] {pb.author}\n"
            f"[bold yellow]Chained Techniques Sequence:[/bold yellow]\n{seq_str}",
            title=f"Playbook: {pb.playbook_id}",
            border_style="magenta",
        )
    )


# --- Campaign Execution Command ---
@app.command("run")
def run_drill(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="Name for the purple-team drill run"),
    ] = "Adversary Emulation Drill",
    playbook: Annotated[
        str | None,
        typer.Option("--playbook", "-p", help="Scenario playbook ID to execute"),
    ] = None,
    techniques: Annotated[
        str | None,
        typer.Option("--techniques", "-t", help="Comma-separated MITRE technique IDs"),
    ] = None,
    operator: Annotated[
        str,
        typer.Option("--operator", "-o", help="Operator identifier"),
    ] = "purple_operator",
    target_host: Annotated[
        str,
        typer.Option("--target-host", "-h", help="Target host where emulations execute"),
    ] = "localhost",
) -> None:
    """Execute adversary emulation drill, verify sensor detections, and evaluate coverage."""
    tech_seq: list[str] | None = None
    if techniques:
        tech_seq = [t.strip() for t in techniques.split(",") if t.strip()]

    if not playbook and not tech_seq:
        playbook = "ransomware-killchain"

    repo = _get_repository()
    orchestrator = CampaignOrchestrator(repository=repo)

    console.print(
        f"[bold cyan]Launching Purple Drill:[/bold cyan] [white]{name}[/white] "
        f"on host [yellow]{target_host}[/yellow]..."
    )

    campaign, heatmap, sigma_rules = asyncio.run(
        orchestrator.async_run_campaign(
            name=name,
            playbook_id=playbook,
            technique_ids=tech_seq,
            operator=operator,
            target_host=target_host,
        )
    )

    console.print(
        f"\n[bold green]Drill Complete![/bold green] "
        f"Campaign ID: [yellow]{campaign.campaign_id}[/yellow]"
    )
    console.print(HeatmapReporter.render_rich_table(heatmap))

    console.print(
        f"\n[bold white]Overall Detection Coverage Rate (DCR):[/bold white] "
        f"[bold cyan]{campaign.detection_coverage_rate}%[/bold cyan] "
        f"([green]{campaign.detected_count} Detected[/green], "
        f"[blue]{campaign.blocked_count} Blocked[/blue], "
        f"[red]{campaign.missed_count} Missed[/red])"
    )

    if sigma_rules:
        console.print(
            f"[bold yellow]Advisor Alert:[/bold yellow] Synthesized "
            f"[cyan]{len(sigma_rules)}[/cyan] Sigma remediation rules for undetected blind spots."
        )


# --- Matrix & Gap Analysis Command ---
@app.command("matrix")
def show_matrix(
    campaign_id: Annotated[
        str | None,
        typer.Option("--campaign", "-c", help="Specific campaign ID (defaults to latest)"),
    ] = None,
) -> None:
    """Display colored ATT&CK Detection Matrix Heatmap and gap metrics."""
    repo = _get_repository()
    heatmap = repo.get_latest_heatmap(campaign_id=campaign_id)
    if not heatmap:
        console.print(
            "[bold red]No heatmap data found.[/bold red] Run a drill first (`purple run`)."
        )
        raise typer.Exit(code=1)

    console.print(HeatmapReporter.render_rich_table(heatmap))
    blind_str = ", ".join(heatmap.blind_spots) or "None"
    console.print(
        f"[bold white]Total Evaluated:[/bold white] {heatmap.total_techniques} | "
        f"[bold green]Detected:[/bold green] {heatmap.detected_count} | "
        f"[bold blue]Blocked:[/bold blue] {heatmap.blocked_count} | "
        f"[bold red]Blind Spots (MISSED):[/bold red] {len(heatmap.blind_spots)} ({blind_str})"
    )


# --- Telemetry Commands ---
@telemetry_app.command("ingest")
def ingest_telemetry_alert(
    sensor: Annotated[str, typer.Option("--sensor", "-s", help="Sensor name (e.g. sysmon, edr)")],
    signature: Annotated[
        str, typer.Option("--signature", help="Alert signature or detection rule title")
    ],
    technique: Annotated[
        str | None, typer.Option("--technique", "-t", help="Attributed MITRE ID")
    ] = None,
    host: Annotated[str, typer.Option("--host", "-h", help="Target host")] = "localhost",
    severity: Annotated[
        TechniqueSeverity, typer.Option("--severity", help="Alert severity")
    ] = TechniqueSeverity.MEDIUM,
    command: Annotated[
        str | None, typer.Option("--command", "-c", help="Observed command line")
    ] = None,
) -> None:
    """Ingest a security alert from defensive sensors into the cyber range."""
    repo = _get_repository()
    raw = {
        "sensor_name": sensor,
        "host": host,
        "alert_signature": signature,
        "technique_id": technique,
        "severity": severity.value,
        "command_line": command,
    }
    alert = AlertNormalizer.normalize_raw_log(raw, sensor_name=sensor)
    repo.save_alert(alert)
    console.print(
        f"[bold green]Alert ingested successfully![/bold green] "
        f"Alert ID: [yellow]{alert.alert_id}[/yellow]"
    )


@telemetry_app.command("list")
def list_telemetry_alerts(
    limit: Annotated[int, typer.Option("--limit", "-l", help="Max alerts to retrieve")] = 20,
) -> None:
    """List recent defensive telemetry alerts."""
    repo = _get_repository()
    alerts = repo.list_alerts(limit=limit)

    table = Table(
        title="[bold blue]Recent Defensive Telemetry Alerts[/bold blue]",
        header_style="bold white on dark_blue",
    )
    table.add_column("Alert ID", style="bold yellow", width=12)
    table.add_column("Sensor", style="cyan", width=12)
    table.add_column("Technique", style="magenta", width=12)
    table.add_column("Signature", style="white", min_width=24)
    table.add_column("Host", style="dim", width=12)

    for a in alerts:
        table.add_row(
            a.alert_id[:8],
            a.sensor_name,
            a.technique_id or "N/A",
            a.alert_signature,
            a.host,
        )

    console.print(table)


# --- Advisor Commands ---
@app.command("advisor")
def show_advisor(
    export_path: Annotated[
        Path | None,
        typer.Option("--export", "-e", help="File path to save exported YAML Sigma bundle"),
    ] = None,
) -> None:
    """View and export synthesized Sigma rules for defensive blind spots."""
    repo = _get_repository()
    rules = repo.list_sigma_rules()

    if not rules:
        console.print(
            "[yellow]No Sigma remediation rules currently stored. "
            "Run a drill with missed techniques.[/yellow]"
        )
        return

    table = Table(
        title="[bold green]Detection Tuning Advisor: Synthesized Sigma Rules[/bold green]",
        header_style="bold white on dark_green",
    )
    table.add_column("Rule ID", style="yellow", width=12)
    table.add_column("Title", style="white", min_width=30)
    table.add_column("Level", style="cyan", width=10)
    table.add_column("Logsource Product", style="magenta", width=18)

    for r in rules:
        table.add_row(
            r.id[:8],
            r.title,
            r.level,
            r.logsource.get("product", "generic"),
        )

    console.print(table)

    if export_path:
        bundle_yaml = DetectionTuningAdvisor.export_rules_bundle(rules)
        export_path.write_text(bundle_yaml, encoding="utf-8")
        console.print(
            f"[bold green]Exported {len(rules)} Sigma rule(s) to[/bold green] "
            f"[yellow]{export_path}[/yellow]"
        )
