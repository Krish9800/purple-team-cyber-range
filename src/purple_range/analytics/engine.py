"""Purple Team Gap Analysis and MITRE ATT&CK Matrix Heatmap Engine."""

from datetime import UTC, datetime

from purple_range.models.detection import DetectionEvidence
from purple_range.models.emulation import EmulationStep
from purple_range.models.enums import DetectionVerdict, MitreTactic
from purple_range.models.heatmap import (
    PurpleMatrixHeatmap,
    TacticSummary,
    TechniqueCoverageCell,
)


class GapAnalysisEngine:
    """Computes Detection Coverage Rates, mean alert latencies, and ATT&CK matrix heatmaps."""

    def generate_heatmap(
        self,
        steps: list[EmulationStep],
        evidences: list[DetectionEvidence],
        campaign_id: str | None = None,
    ) -> PurpleMatrixHeatmap:
        """Aggregate emulation steps and verification evidence into a full ATT&CK Heatmap."""
        evidence_by_exec: dict[str, DetectionEvidence] = {ev.execution_id: ev for ev in evidences}

        # Group steps by technique_id to track execution counts and latest verdicts
        tech_steps: dict[str, list[EmulationStep]] = {}
        for step in steps:
            tech_steps.setdefault(step.technique_id, []).append(step)

        cells: list[TechniqueCoverageCell] = []
        blind_spots: list[str] = []
        tactic_counts: dict[str, dict[str, int]] = {}

        for tech_id, step_list in tech_steps.items():
            latest_step = max(step_list, key=lambda s: s.started_at)
            step_evidences = [
                evidence_by_exec[s.execution_id]
                for s in step_list
                if s.execution_id in evidence_by_exec
            ]

            # Determine dominant/latest verdict
            if step_evidences:
                latest_evidence = max(step_evidences, key=lambda e: e.matched_at)
                verdict = latest_evidence.verdict
                valid_latencies = [
                    e.detection_latency_seconds
                    for e in step_evidences
                    if e.detection_latency_seconds is not None
                ]
                avg_latency = (
                    round(sum(valid_latencies) / len(valid_latencies), 3)
                    if valid_latencies
                    else None
                )
            else:
                verdict = DetectionVerdict.MISSED
                avg_latency = None

            tactic_key = latest_step.tactic.value
            tactic_stat = tactic_counts.setdefault(
                tactic_key, {"tested": 0, "detected": 0, "blocked": 0, "missed": 0}
            )
            tactic_stat["tested"] += 1

            if verdict == DetectionVerdict.DETECTED:
                tactic_stat["detected"] += 1
            elif verdict == DetectionVerdict.BLOCKED:
                tactic_stat["blocked"] += 1
            else:
                tactic_stat["missed"] += 1
                blind_spots.append(tech_id)

            cell = TechniqueCoverageCell(
                technique_id=tech_id,
                technique_name=latest_step.technique_name,
                tactic=latest_step.tactic,
                verdict=verdict,
                execution_count=len(step_list),
                avg_latency_seconds=avg_latency,
                last_tested=latest_step.started_at,
            )
            cells.append(cell)

        # Build tactic summaries
        tactic_summaries: dict[str, TacticSummary] = {}
        for tac in MitreTactic:
            stats = tactic_counts.get(
                tac.value, {"tested": 0, "detected": 0, "blocked": 0, "missed": 0}
            )
            total = stats["tested"]
            cov_rate = (
                round(((stats["detected"] + stats["blocked"]) / total) * 100.0, 2)
                if total > 0
                else 0.0
            )
            tactic_summaries[tac.value] = TacticSummary(
                tactic=tac,
                total_tested=total,
                detected=stats["detected"],
                blocked=stats["blocked"],
                missed=stats["missed"],
                coverage_rate=cov_rate,
            )

        total_techniques = len(cells)
        detected_count = sum(1 for c in cells if c.verdict == DetectionVerdict.DETECTED)
        blocked_count = sum(1 for c in cells if c.verdict == DetectionVerdict.BLOCKED)
        missed_count = sum(1 for c in cells if c.verdict == DetectionVerdict.MISSED)

        global_dcr = (
            round(((detected_count + blocked_count) / total_techniques) * 100.0, 2)
            if total_techniques > 0
            else 0.0
        )

        return PurpleMatrixHeatmap(
            campaign_id=campaign_id,
            generated_at=datetime.now(UTC),
            total_techniques=total_techniques,
            detected_count=detected_count,
            blocked_count=blocked_count,
            missed_count=missed_count,
            detection_coverage_rate=global_dcr,
            tactic_summaries=tactic_summaries,
            cells=cells,
            blind_spots=sorted(blind_spots),
            metadata={"cells_count": len(cells)},
        )
