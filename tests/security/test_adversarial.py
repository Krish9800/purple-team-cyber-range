"""Security and adversarial testbed for Purple-Team Cyber Range."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from purple_range.db import DatabaseManager, PurpleRangeRepository
from purple_range.detection.correlator import DetectionCorrelator
from purple_range.detection.evaluator import DetectionCoverageEvaluator
from purple_range.detection.normalizer import AlertNormalizer
from purple_range.emulation import (
    AdversaryEmulationEngine,
    EmulationSafetyError,
    PreFlightValidator,
)
from purple_range.models import (
    DetectionAlert,
    DetectionVerdict,
    EmulationStatus,
    EmulationStep,
    MitreTactic,
    MitreTechnique,
    PurpleCampaign,
    TechniqueSeverity,
)


@pytest.mark.parametrize(
    "malicious_payload",
    [
        "rm -rf /",
        "rm -Rf /",
        "rm -rf /*",
        ":(){ :|:& };:",
        "mkfs /dev/sda",
        "dd if=/dev/urandom of=/dev/sda",
        "shutdown -r now",
        "reboot -f",
        "init 0",
    ],
)
def test_preflight_blocks_critical_destructive_payloads(malicious_payload: str) -> None:
    """Verify PreFlightValidator rejects destructive payload injections."""
    with pytest.raises(EmulationSafetyError, match="unsafe pattern"):
        PreFlightValidator.validate_command(malicious_payload)


@pytest.mark.asyncio
async def test_adversary_engine_blocks_command_injection_in_parameters() -> None:
    """Verify parameters containing destructive shell injection are halted before execution."""
    engine = AdversaryEmulationEngine()
    tech = MitreTechnique(
        technique_id="T1087.001",
        name="Param Injection Test",
        tactic=MitreTactic.DISCOVERY,
        command_template="cat {target}",
        description="Testing parameter containment",
    )
    step = await engine.async_execute_technique(
        technique=tech,
        campaign_id="camp-inject-1",
        custom_params={"target": "/etc/passwd && rm -rf /"},
    )
    assert step.status == EmulationStatus.FAILED
    assert step.exit_code == 126
    assert "Preflight validation failed" in str(step.error_message)


def test_correlator_resists_temporal_spoofing() -> None:
    """Verify correlator rejects telemetry alerts with forged timestamps outside window."""
    correlator = DetectionCorrelator(correlation_window_seconds=60, clock_skew_tolerance_seconds=2)
    now = datetime.now(UTC)

    step = EmulationStep(
        campaign_id="camp-sec-1",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="ss -tuln",
        started_at=now,
        completed_at=now + timedelta(seconds=1),
    )

    # Forged alert 1 hour prior
    spoofed_early = DetectionAlert(
        sensor_name="sysmon",
        technique_id="T1046",
        timestamp=now - timedelta(hours=1),
        host="localhost",
        alert_signature="Port Scan",
    )
    assert correlator.correlate(step, spoofed_early) is False

    # Forged alert 1 hour after
    spoofed_late = DetectionAlert(
        sensor_name="sysmon",
        technique_id="T1046",
        timestamp=now + timedelta(hours=1),
        host="localhost",
        alert_signature="Port Scan",
    )
    assert correlator.correlate(step, spoofed_late) is False


def test_correlator_resists_host_spoofing() -> None:
    """Verify correlator rejects telemetry alerts originating from untargeted external hosts."""
    correlator = DetectionCorrelator()
    now = datetime.now(UTC)

    step = EmulationStep(
        campaign_id="camp-sec-2",
        technique_id="T1003.008",
        technique_name="OS Credential Dumping",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        target_host="range-isolated-node",
        command_executed="cat /etc/shadow",
        started_at=now,
    )

    foreign_alert = DetectionAlert(
        sensor_name="edr",
        technique_id="T1003.008",
        timestamp=now,
        host="corp-domain-controller.external",
        alert_signature="Credential Dumping",
    )
    assert correlator.correlate(step, foreign_alert) is False


@pytest.mark.asyncio
async def test_denial_of_service_timeout_termination() -> None:
    """Verify runaway or infinite command processes are forcibly killed after timeout."""
    engine = AdversaryEmulationEngine(default_timeout_seconds=2)
    hang_tech = MitreTechnique(
        technique_id="T1087.001",
        name="Runaway Hang Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_template="sleep 30",
        description="Emulates hanging command",
    )

    step = await engine.async_execute_technique(
        technique=hang_tech,
        campaign_id="camp-dos",
        timeout_seconds=1,
    )
    assert step.status == EmulationStatus.TIMED_OUT
    assert step.exit_code == 124
    assert step.duration_ms < 3000  # Terminated within 1-2s


def test_fuzzed_alert_ingestion_payload_handling() -> None:
    """Verify normalizer gracefully digests corrupt, partial, or malformed sensor telemetry."""
    fuzzed_payloads: list[dict[str, Any]] = [
        {},
        {"timestamp": None, "host": None, "pid": "NOT_AN_INT"},
        {"timestamp": "2026-10-14 99:99:99", "severity": "UNRECOGNIZED_SEV"},
        {"process_pid": -100, "mitre_id": "T9999.999", "command_line": None},
    ]

    for payload in fuzzed_payloads:
        alert = AlertNormalizer.normalize_raw_log(payload, sensor_name="fuzz_sensor")
        assert alert.sensor_name == "fuzz_sensor"
        assert alert.timestamp is not None
        assert alert.host is not None
        assert alert.severity == TechniqueSeverity.MEDIUM


def test_evaluator_unmonitored_technique_guaranteed_missed() -> None:
    """Verify that when no sensors emit telemetry, verdict strictly classifies as MISSED."""
    evaluator = DetectionCoverageEvaluator()
    step = EmulationStep(
        campaign_id="camp-unmonitored",
        technique_id="T1070.004",
        technique_name="Indicator Removal",
        tactic=MitreTactic.DEFENSE_EVASION,
        command_executed="rm -f /tmp/test.log",
        exit_code=0,
    )
    evidence = evaluator.evaluate_step(step)
    assert evidence.verdict == DetectionVerdict.MISSED
    assert len(evidence.matched_alerts) == 0


def test_sqlite_persistence_journal_integrity(temp_db_path: Path) -> None:
    """Verify execution steps are permanently recorded in SQLite WAL journal."""
    manager = DatabaseManager(temp_db_path)
    repo = PurpleRangeRepository(manager)
    repo.initialize_schema()

    campaign = PurpleCampaign(
        campaign_id="camp-audit",
        name="Audit Integrity Campaign",
    )
    repo.save_campaign(campaign)

    step = EmulationStep(
        execution_id="journal-audit-001",
        campaign_id="camp-audit",
        technique_id="T1087.001",
        technique_name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="whoami",
        stdout="purpleteam",
        exit_code=0,
        status=EmulationStatus.COMPLETED,
    )
    repo.save_emulation_step(step)

    records = repo.get_steps_for_campaign("camp-audit")
    assert len(records) == 1
    assert records[0].execution_id == "journal-audit-001"
    assert records[0].stdout == "purpleteam"
    assert records[0].exit_code == 0
