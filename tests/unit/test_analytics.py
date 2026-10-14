"""Unit tests for Phase 5: Gap analysis engine, heatmap matrix, and report generator."""

from datetime import UTC, datetime, timedelta

from rich.table import Table

from purple_range.analytics import GapAnalysisEngine, HeatmapReporter
from purple_range.models import (
    DetectionEvidence,
    DetectionVerdict,
    EmulationStatus,
    EmulationStep,
    MitreTactic,
)


def test_gap_analysis_engine_empty() -> None:
    """Verify empty input produces empty matrix with 0% DCR."""
    engine = GapAnalysisEngine()
    heatmap = engine.generate_heatmap(steps=[], evidences=[])
    assert heatmap.total_techniques == 0
    assert heatmap.detection_coverage_rate == 0.0
    assert len(heatmap.cells) == 0
    assert len(heatmap.blind_spots) == 0


def test_gap_analysis_engine_aggregation_and_dcr() -> None:
    """Verify multi-step aggregation, average latency, and DCR computation."""
    engine = GapAnalysisEngine()
    now = datetime.now(UTC)

    # Technique 1 (T1087): 2 executions, both detected
    step1_a = EmulationStep(
        campaign_id="c1",
        technique_id="T1087.001",
        technique_name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="cat /etc/passwd",
        started_at=now,
        status=EmulationStatus.COMPLETED,
    )
    ev1_a = DetectionEvidence(
        execution_id=step1_a.execution_id,
        technique_id="T1087.001",
        verdict=DetectionVerdict.DETECTED,
        detection_latency_seconds=1.5,
    )

    step1_b = EmulationStep(
        campaign_id="c1",
        technique_id="T1087.001",
        technique_name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="cat /etc/passwd",
        started_at=now + timedelta(seconds=10),
        status=EmulationStatus.COMPLETED,
    )
    ev1_b = DetectionEvidence(
        execution_id=step1_b.execution_id,
        technique_id="T1087.001",
        verdict=DetectionVerdict.DETECTED,
        detection_latency_seconds=2.5,
    )

    # Technique 2 (T1548): 1 execution, BLOCKED
    step2 = EmulationStep(
        campaign_id="c1",
        technique_id="T1548.003",
        technique_name="Sudo Check",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        command_executed="sudo -l",
        started_at=now + timedelta(seconds=20),
        status=EmulationStatus.COMPLETED,
    )
    ev2 = DetectionEvidence(
        execution_id=step2.execution_id,
        technique_id="T1548.003",
        verdict=DetectionVerdict.BLOCKED,
        detection_latency_seconds=0.1,
    )

    # Technique 3 (T1003): 1 execution, MISSED
    step3 = EmulationStep(
        campaign_id="c1",
        technique_id="T1003.008",
        technique_name="OS Credential Dumping",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        command_executed="cat /etc/shadow",
        started_at=now + timedelta(seconds=30),
        status=EmulationStatus.COMPLETED,
    )
    ev3 = DetectionEvidence(
        execution_id=step3.execution_id,
        technique_id="T1003.008",
        verdict=DetectionVerdict.MISSED,
        detection_latency_seconds=None,
    )

    steps = [step1_a, step1_b, step2, step3]
    evidences = [ev1_a, ev1_b, ev2, ev3]

    heatmap = engine.generate_heatmap(steps=steps, evidences=evidences, campaign_id="c1")

    assert heatmap.total_techniques == 3
    assert heatmap.detected_count == 1
    assert heatmap.blocked_count == 1
    assert heatmap.missed_count == 1
    # DCR = (1 detected + 1 blocked) / 3 = 66.67%
    assert heatmap.detection_coverage_rate == 66.67
    assert heatmap.blind_spots == ["T1003.008"]

    # Verify T1087 cell aggregation (2 executions, avg latency = (1.5+2.5)/2 = 2.0s)
    cell_t1087 = next(c for c in heatmap.cells if c.technique_id == "T1087.001")
    assert cell_t1087.execution_count == 2
    assert cell_t1087.avg_latency_seconds == 2.0
    assert cell_t1087.verdict == DetectionVerdict.DETECTED

    # Verify tactic summaries
    disc_summary = heatmap.tactic_summaries[MitreTactic.DISCOVERY.value]
    assert disc_summary.total_tested == 1
    assert disc_summary.coverage_rate == 100.0

    cred_summary = heatmap.tactic_summaries[MitreTactic.CREDENTIAL_ACCESS.value]
    assert cred_summary.total_tested == 1
    assert cred_summary.coverage_rate == 0.0


def test_gap_analysis_step_without_evidence() -> None:
    """Verify steps missing explicit evidence default to MISSED verdict."""
    engine = GapAnalysisEngine()
    step = EmulationStep(
        campaign_id="c-noev",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="ss -tuln",
    )
    heatmap = engine.generate_heatmap(steps=[step], evidences=[])
    assert heatmap.total_techniques == 1
    assert heatmap.missed_count == 1
    assert heatmap.blind_spots == ["T1046"]


def test_heatmap_reporter_rich_table_and_markdown() -> None:
    """Verify Rich table building and Markdown summary generation."""
    engine = GapAnalysisEngine()
    step = EmulationStep(
        campaign_id="c-rep",
        technique_id="T1087.001",
        technique_name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="whoami",
    )
    ev = DetectionEvidence(
        execution_id=step.execution_id,
        technique_id="T1087.001",
        verdict=DetectionVerdict.DETECTED,
        detection_latency_seconds=1.2,
    )
    heatmap = engine.generate_heatmap(steps=[step], evidences=[ev])

    # 1. Rich Table
    rich_table = HeatmapReporter.render_rich_table(heatmap)
    assert isinstance(rich_table, Table)
    assert len(rich_table.columns) == 6

    # 2. Markdown Report
    md = HeatmapReporter.generate_markdown_summary(heatmap)
    assert "# Purple-Team Detection Verification Summary" in md
    assert "DCR" in md
    assert "Zero blind spots detected" in md
    assert "`discovery`" in md

    # 3. Markdown with blind spots
    step_blind = EmulationStep(
        campaign_id="c-rep",
        technique_id="T1003",
        technique_name="Credential Dumping",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        command_executed="cat /etc/shadow",
    )
    heatmap_with_blind = engine.generate_heatmap(steps=[step, step_blind], evidences=[ev])
    md_blind = HeatmapReporter.generate_markdown_summary(heatmap_with_blind)
    assert "**`T1003`**: Immediate detection tuning required" in md_blind
