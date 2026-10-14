"""Presentation and reporting utilities for Purple Team Matrix Heatmaps."""

from rich.table import Table

from purple_range.models.enums import DetectionVerdict
from purple_range.models.heatmap import PurpleMatrixHeatmap


class HeatmapReporter:
    """Renders visual terminal dashboards and markdown summaries of gap analysis."""

    @classmethod
    def render_rich_table(cls, heatmap: PurpleMatrixHeatmap) -> Table:
        """Create a styled Rich Table visualization of the ATT&CK coverage heatmap."""
        table = Table(
            title=(
                f"[bold magenta]Purple-Team ATT&CK Detection Matrix[/bold magenta] "
                f"(DCR: [bold cyan]{heatmap.detection_coverage_rate}%[/bold cyan])"
            ),
            header_style="bold white on navy_blue",
            show_lines=True,
        )

        table.add_column("Technique ID", style="bold yellow", width=14)
        table.add_column("Technique Name", style="white", min_width=24)
        table.add_column("MITRE Tactic", style="dim cyan", width=20)
        table.add_column("Execs", justify="right", width=6)
        table.add_column("Verdict", justify="center", width=12)
        table.add_column("Avg Latency", justify="right", width=12)

        verdict_styles = {
            DetectionVerdict.DETECTED: "[bold green]DETECTED[/bold green]",
            DetectionVerdict.BLOCKED: "[bold blue]BLOCKED[/bold blue]",
            DetectionVerdict.MISSED: "[bold red]MISSED (GAP)[/bold red]",
        }

        for cell in sorted(heatmap.cells, key=lambda c: (c.tactic.value, c.technique_id)):
            verdict_str = verdict_styles.get(cell.verdict, str(cell.verdict))
            latency_str = (
                f"{cell.avg_latency_seconds:.2f}s"
                if cell.avg_latency_seconds is not None
                else "N/A"
            )

            table.add_row(
                cell.technique_id,
                cell.technique_name,
                cell.tactic.value,
                str(cell.execution_count),
                verdict_str,
                latency_str,
            )

        return table

    @classmethod
    def generate_markdown_summary(cls, heatmap: PurpleMatrixHeatmap) -> str:
        """Generate GitHub-flavored markdown report summarizing range drill outcomes."""
        lines = [
            "# Purple-Team Detection Verification Summary",
            "",
            f"- **Detection Coverage Rate (DCR)**: `{heatmap.detection_coverage_rate}%`",
            f"- **Total Techniques Evaluated**: `{heatmap.total_techniques}`",
            f"- **Detected**: `{heatmap.detected_count}`",
            f"- **Blocked**: `{heatmap.blocked_count}`",
            f"- **Missed (Gaps)**: `{heatmap.missed_count}`",
            "",
            "## Defensive Blind Spots",
        ]

        if heatmap.blind_spots:
            for bs in heatmap.blind_spots:
                lines.append(f"- **`{bs}`**: Immediate detection tuning required")
        else:
            lines.append("- *Zero blind spots detected across evaluated techniques.*")

        lines.extend(
            [
                "",
                "## Tactic Breakdown",
                "",
                "| Tactic | Tested | Detected | Blocked | Missed | Coverage Rate |",
                "| :--- | :---: | :---: | :---: | :---: | :---: |",
            ]
        )

        for tac_name, summary in sorted(heatmap.tactic_summaries.items()):
            if summary.total_tested > 0:
                lines.append(
                    f"| `{tac_name}` | {summary.total_tested} | "
                    f"{summary.detected} | {summary.blocked} | {summary.missed} | "
                    f"`{summary.coverage_rate}%` |"
                )

        return "\n".join(lines) + "\n"
