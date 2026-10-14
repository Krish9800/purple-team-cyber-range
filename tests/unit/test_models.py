"""Unit tests for Phase 2: Domain models, ATT&CK enums, and Sigma export."""

import pytest
from pydantic import ValidationError

from purple_range.models import (
    CampaignPlaybook,
    DataSource,
    DetectionAlert,
    DetectionEvidence,
    DetectionVerdict,
    EmulationStatus,
    EmulationStep,
    MitreTactic,
    MitreTechnique,
    Platform,
    PurpleCampaign,
    PurpleMatrixHeatmap,
    SigmaRule,
    TacticSummary,
    TechniqueCoverageCell,
    TechniqueSeverity,
)


def test_enums_values() -> None:
    """Verify enum members and values."""
    assert MitreTactic.CREDENTIAL_ACCESS.value == "credential-access"
    assert MitreTactic.DISCOVERY.value == "discovery"
    assert DetectionVerdict.DETECTED.value == "DETECTED"
    assert DetectionVerdict.BLOCKED.value == "BLOCKED"
    assert DetectionVerdict.MISSED.value == "MISSED"
    assert EmulationStatus.COMPLETED.value == "COMPLETED"
    assert TechniqueSeverity.HIGH.value == "HIGH"
    assert Platform.LINUX.value == "linux"
    assert DataSource.PROCESS_MONITORING.value == "process_monitoring"


def test_mitre_technique_validation() -> None:
    """Verify MitreTechnique fields and regex validation."""
    tech = MitreTechnique(
        technique_id="T1087.001",
        name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        severity=TechniqueSeverity.LOW,
        platform=Platform.LINUX,
        description="Adversaries may attempt to find a list of local system accounts.",
        command_template="cat /etc/passwd",
        cleanup_command=None,
        data_sources=[DataSource.COMMAND_EXECUTION, DataSource.PROCESS_MONITORING],
    )
    assert tech.technique_id == "T1087.001"
    assert tech.safe_payload is True

    # Invalid technique ID pattern
    with pytest.raises(ValidationError):
        MitreTechnique(
            technique_id="INVALID_ID",
            name="Bad",
            tactic=MitreTactic.DISCOVERY,
            description="desc",
            command_template="cmd",
        )


def test_emulation_step_creation() -> None:
    """Verify EmulationStep defaults and immutability."""
    step = EmulationStep(
        campaign_id="camp-123",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="nmap -sT -p 22,80 127.0.0.1",
        stdout="PORT 22/tcp open",
        exit_code=0,
        status=EmulationStatus.COMPLETED,
        duration_ms=15.5,
    )
    assert step.campaign_id == "camp-123"
    assert step.execution_id is not None
    assert step.target_host == "localhost"
    assert step.status == EmulationStatus.COMPLETED

    # Check immutability (frozen=True)
    with pytest.raises(ValidationError):
        step.status = EmulationStatus.FAILED


def test_detection_alert_and_evidence() -> None:
    """Verify DetectionAlert and correlation Evidence creation."""
    alert = DetectionAlert(
        sensor_name="sysmon",
        technique_id="T1046",
        host="localhost",
        process_name="nmap",
        command_line="nmap -sT -p 22,80 127.0.0.1",
        alert_signature="Port Scan Activity Detected",
        severity=TechniqueSeverity.HIGH,
    )
    assert alert.sensor_name == "sysmon"

    evidence = DetectionEvidence(
        execution_id="exec-456",
        technique_id="T1046",
        verdict=DetectionVerdict.DETECTED,
        matched_alerts=[alert],
        detection_latency_seconds=1.25,
    )
    assert evidence.verdict == DetectionVerdict.DETECTED
    assert len(evidence.matched_alerts) == 1
    assert evidence.detection_latency_seconds == 1.25


def test_campaign_and_playbook() -> None:
    """Verify CampaignPlaybook and PurpleCampaign creation."""
    playbook = CampaignPlaybook(
        playbook_id="ransomware-chain",
        name="Ransomware Kill Chain",
        description="Simulates account discovery, privilege escalation, and defense evasion.",
        technique_ids=["T1087", "T1548", "T1070"],
    )
    assert playbook.playbook_id == "ransomware-chain"
    assert len(playbook.technique_ids) == 3

    campaign = PurpleCampaign(
        name="Q4 Enterprise Range Drill",
        playbook_id=playbook.playbook_id,
        operator="red_lead_01",
        total_techniques=3,
        detected_count=2,
        blocked_count=0,
        missed_count=1,
        detection_coverage_rate=66.67,
    )
    assert campaign.detection_coverage_rate == 66.67
    assert campaign.operator == "red_lead_01"


def test_heatmap_models() -> None:
    """Verify Matrix Heatmap and summary cells."""
    cell = TechniqueCoverageCell(
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        verdict=DetectionVerdict.MISSED,
        execution_count=1,
        avg_latency_seconds=None,
    )
    summary = TacticSummary(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        total_tested=1,
        detected=0,
        blocked=0,
        missed=1,
        coverage_rate=0.0,
    )
    heatmap = PurpleMatrixHeatmap(
        total_techniques=1,
        detected_count=0,
        blocked_count=0,
        missed_count=1,
        detection_coverage_rate=0.0,
        tactic_summaries={MitreTactic.CREDENTIAL_ACCESS.value: summary},
        cells=[cell],
        blind_spots=["T1003"],
    )
    assert heatmap.blind_spots == ["T1003"]
    assert heatmap.detection_coverage_rate == 0.0


def test_sigma_rule_yaml_export() -> None:
    """Verify Sigma rule modeling and YAML generation."""
    sigma = SigmaRule(
        title="Suspicious /etc/passwd Read via Shell",
        id="a1b2c3d4-1111-2222-3333-444455556666",
        description="Detects reading /etc/passwd via cat or head",
        date="2026-10-14",
        references=["https://attack.mitre.org/techniques/T1087/001/"],
        tags=["attack.discovery", "attack.t1087.001"],
        logsource={"category": "process_creation", "product": "linux"},
        detection={
            "selection": {
                "Image|endswith": ["/cat", "/head"],
                "CommandLine|contains": "/etc/passwd",
            }
        },
        falsepositives=["System administration audits"],
        level="low",
    )
    yaml_text = sigma.to_yaml()
    assert "title: Suspicious /etc/passwd Read via Shell" in yaml_text
    assert "id: a1b2c3d4-1111-2222-3333-444455556666" in yaml_text
    assert "attack.t1087.001" in yaml_text
    assert "CommandLine|contains: '/etc/passwd'" in yaml_text
    assert "level: low" in yaml_text


def test_sigma_rule_variants_and_default_id() -> None:
    """Verify default UUID generation and varied detection field structures."""
    sigma = SigmaRule(
        title="Generic Process Launch",
        description="Detects process execution via list and primitive values",
        date="2026-10-14",
        logsource={"category": "process_creation", "product": "linux"},
        detection={
            "selection_list": ["cmd1", "cmd2"],
            "selection_string": "sudo",
        },
    )
    assert sigma.id is not None
    yaml_text = sigma.to_yaml()
    assert "- 'cmd1'" in yaml_text
    assert "selection_string: 'sudo'" in yaml_text
