"""Unit tests for Phase 4: Detection verification engine and coverage evaluator."""

from datetime import UTC, datetime, timedelta

from purple_range.detection import (
    AlertNormalizer,
    DetectionCorrelator,
    DetectionCoverageEvaluator,
)
from purple_range.models import (
    DetectionAlert,
    DetectionVerdict,
    EmulationStatus,
    EmulationStep,
    MitreTactic,
    TechniqueSeverity,
)


def test_alert_normalizer_iso_and_epoch_timestamps() -> None:
    """Verify normalizer handles ISO 8601 strings, unix epochs, and missing fields."""
    iso_log = {
        "timestamp": "2026-10-14T08:00:00Z",
        "hostname": "range-host-1",
        "process": "nmap",
        "pid": "4321",
        "cmd": "nmap -sT 127.0.0.1",
        "mitre_id": "1046",
        "rule_name": "Suspicious Port Scan",
        "severity": "HIGH",
    }
    alert_iso = AlertNormalizer.normalize_raw_log(iso_log, "sysmon")
    assert alert_iso.host == "range-host-1"
    assert alert_iso.process_pid == 4321
    assert alert_iso.technique_id == "T1046"
    assert alert_iso.severity == TechniqueSeverity.HIGH
    assert alert_iso.timestamp.year == 2026

    epoch_log = {
        "timestamp": 1760428800,  # 2025/2026 epoch
        "host": "localhost",
        "process_name": "sudo",
        "severity": "CRITICAL",
    }
    alert_epoch = AlertNormalizer.normalize_raw_log(epoch_log, "auditd")
    assert alert_epoch.host == "localhost"
    assert alert_epoch.severity == TechniqueSeverity.CRITICAL

    fallback_log = {"invalid_time": "none"}
    alert_fallback = AlertNormalizer.normalize_raw_log(fallback_log, "edr")
    assert alert_fallback.host == "localhost"
    assert alert_fallback.alert_signature == "EDR Security Event"

    bad_iso_log = {"timestamp": "NOT_AN_ISO_DATE"}
    alert_bad_iso = AlertNormalizer.normalize_raw_log(bad_iso_log, "edr")
    assert alert_bad_iso.timestamp is not None


def test_correlator_temporal_and_host_matching() -> None:
    """Verify temporal window limits and host alias matching."""
    correlator = DetectionCorrelator(correlation_window_seconds=60, clock_skew_tolerance_seconds=2)
    now = datetime.now(UTC)

    step = EmulationStep(
        campaign_id="camp-1",
        technique_id="T1087.001",
        technique_name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        target_host="127.0.0.1",
        command_executed="cat /etc/passwd",
        started_at=now,
        completed_at=now + timedelta(seconds=1),
    )

    # Correlated alert inside window
    alert_in = DetectionAlert(
        sensor_name="sysmon",
        technique_id="T1087.001",
        host="localhost",
        timestamp=now + timedelta(seconds=5),
        alert_signature="Account Discovery",
    )
    assert correlator.correlate(step, alert_in) is True

    # Alert too early (beyond skew)
    alert_early = DetectionAlert(
        sensor_name="sysmon",
        technique_id="T1087.001",
        host="localhost",
        timestamp=now - timedelta(seconds=10),
        alert_signature="Account Discovery",
    )
    assert correlator.correlate(step, alert_early) is False

    # Alert too late (beyond window)
    alert_late = DetectionAlert(
        sensor_name="sysmon",
        technique_id="T1087.001",
        host="localhost",
        timestamp=now + timedelta(seconds=70),
        alert_signature="Account Discovery",
    )
    assert correlator.correlate(step, alert_late) is False

    # Host mismatch
    alert_diff_host = DetectionAlert(
        sensor_name="sysmon",
        technique_id="T1087.001",
        host="remote-host-99",
        timestamp=now + timedelta(seconds=5),
        alert_signature="Account Discovery",
    )
    assert correlator.correlate(step, alert_diff_host) is False


def test_correlator_attribute_matching() -> None:
    """Verify attribute matching on PID, command line substring, and signature."""
    correlator = DetectionCorrelator()
    now = datetime.now(UTC)

    step = EmulationStep(
        campaign_id="camp-2",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic=MitreTactic.DISCOVERY,
        target_host="localhost",
        command_executed="ss -tulpn",
        process_pid=9876,
        started_at=now,
        completed_at=now + timedelta(seconds=1),
    )

    # PID match
    alert_pid = DetectionAlert(
        sensor_name="auditd",
        host="localhost",
        timestamp=now,
        process_pid=9876,
        alert_signature="Unknown Activity",
    )
    assert correlator.is_attribute_correlated(step, alert_pid) is True

    # Command line match
    alert_cmd = DetectionAlert(
        sensor_name="sysmon",
        host="localhost",
        timestamp=now,
        command_line="ss -tulpn --listening",
        alert_signature="Generic Socket Query",
    )
    assert correlator.is_attribute_correlated(step, alert_cmd) is True

    # Unrelated alert
    alert_unrelated = DetectionAlert(
        sensor_name="sysmon",
        technique_id="T1003",
        host="localhost",
        timestamp=now,
        process_pid=1111,
        command_line="cat /etc/shadow",
        alert_signature="Credential Dumping",
    )
    assert correlator.is_attribute_correlated(step, alert_unrelated) is False


def test_evaluator_verdicts_and_dcr() -> None:
    """Verify DETECTED, BLOCKED, MISSED outcomes and DCR calculations."""
    evaluator = DetectionCoverageEvaluator(correlation_window_seconds=60)
    now = datetime.now(UTC)

    # Ingest detection alert for T1087
    evaluator.ingest_alert(
        DetectionAlert(
            sensor_name="sysmon",
            technique_id="T1087.001",
            host="localhost",
            timestamp=now + timedelta(seconds=2),
            alert_signature="T1087 Discovery Alert",
        )
    )

    # Step 1: Detected
    step_detected = EmulationStep(
        campaign_id="camp-eval",
        technique_id="T1087.001",
        technique_name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="cat /etc/passwd",
        started_at=now,
        completed_at=now + timedelta(seconds=1),
        status=EmulationStatus.COMPLETED,
    )
    ev_detected = evaluator.evaluate_step(step_detected)
    assert ev_detected.verdict == DetectionVerdict.DETECTED
    assert ev_detected.detection_latency_seconds == 2.0

    # Step 2: Blocked by security control
    step_blocked = EmulationStep(
        campaign_id="camp-eval",
        technique_id="T1003.008",
        technique_name="OS Credential Dumping",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        command_executed="cat /etc/shadow",
        stdout="EACCES: /etc/shadow permission denied",
        exit_code=1,
        started_at=now,
        completed_at=now + timedelta(seconds=1),
        status=EmulationStatus.COMPLETED,
    )
    ev_blocked = evaluator.evaluate_step(step_blocked)
    assert ev_blocked.verdict == DetectionVerdict.BLOCKED

    # Step 3: Missed (no alerts and not blocked)
    step_missed = EmulationStep(
        campaign_id="camp-eval",
        technique_id="T1070.004",
        technique_name="File Deletion",
        tactic=MitreTactic.DEFENSE_EVASION,
        command_executed="rm -f /tmp/dummy.log",
        exit_code=0,
        started_at=now,
        completed_at=now + timedelta(seconds=1),
        status=EmulationStatus.COMPLETED,
    )
    ev_missed = evaluator.evaluate_step(step_missed)
    assert ev_missed.verdict == DetectionVerdict.MISSED
    assert ev_missed.detection_latency_seconds is None

    # DCR calculation: 2 covered (1 detected + 1 blocked) out of 3 = 66.67%
    evidences = [ev_detected, ev_blocked, ev_missed]
    dcr = DetectionCoverageEvaluator.calculate_dcr(evidences)
    assert dcr == 66.67
    assert DetectionCoverageEvaluator.calculate_dcr([]) == 0.0

    # Test clear_alerts and batch evaluate
    assert len(evaluator.get_alerts()) == 1
    evaluator.clear_alerts()
    assert len(evaluator.get_alerts()) == 0

    # Ingest via ingest_raw_log with blocking sensor alert
    evaluator.ingest_raw_log(
        {
            "technique_id": "T1548.003",
            "message": "EDR Process Blocked: Unauthorized Sudo Escalation Attempt",
            "process_name": "sudo",
        },
        "edr",
    )
    step_sensor_blocked = EmulationStep(
        campaign_id="camp-eval",
        technique_id="T1548.003",
        technique_name="Abuse Elevation Control",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        command_executed="sudo -l",
        status=EmulationStatus.COMPLETED,
    )
    ev_sensor_blocked = evaluator.evaluate_step(step_sensor_blocked)
    assert ev_sensor_blocked.verdict == DetectionVerdict.BLOCKED
    assert ev_sensor_blocked.detection_latency_seconds is not None

    batch_ev = evaluator.evaluate_campaign_steps([step_missed])
    assert len(batch_ev) == 1
    assert batch_ev[0].verdict == DetectionVerdict.MISSED
