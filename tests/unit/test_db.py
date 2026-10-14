"""Unit tests for Phase 7: SQLite WAL persistence engine and repository."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from purple_range.db import DatabaseManager, PurpleRangeRepository
from purple_range.models import (
    CampaignPlaybook,
    DetectionAlert,
    DetectionEvidence,
    DetectionVerdict,
    EmulationStatus,
    EmulationStep,
    MitreTactic,
    PurpleCampaign,
    PurpleMatrixHeatmap,
    SigmaRule,
    TacticSummary,
    TechniqueCoverageCell,
    TechniqueSeverity,
)


@pytest.fixture
def repo(temp_db_path: Path) -> PurpleRangeRepository:
    """Fixture providing initialized SQLite repository on temporary database."""
    manager = DatabaseManager(temp_db_path)
    repository = PurpleRangeRepository(manager)
    repository.initialize_schema()
    return repository


def test_db_manager_pragmas(temp_db_path: Path) -> None:
    """Verify SQLite connection configures WAL mode, foreign keys, and busy timeout."""
    manager = DatabaseManager(temp_db_path, timeout_seconds=15.0)
    with manager.connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        # WAL mode is reported as 'wal'
        assert str(journal_mode).lower() == "wal"

        fk_mode = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        assert fk_mode == 1

        timeout = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        assert timeout == 15000


def test_db_manager_transaction_rollback(temp_db_path: Path) -> None:
    """Verify rollback on exception within transaction block."""
    manager = DatabaseManager(temp_db_path)
    with manager.connection() as conn:
        conn.execute("CREATE TABLE test_tbl (id INTEGER PRIMARY KEY);")

    with pytest.raises(RuntimeError), manager.connection() as conn:
        conn.execute("INSERT INTO test_tbl VALUES (1);")
        raise RuntimeError("Forced abort")

    with manager.connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM test_tbl;").fetchone()[0]
        assert count == 0


def test_playbook_crud(repo: PurpleRangeRepository) -> None:
    """Verify saving, retrieving, and listing playbooks."""
    playbook = CampaignPlaybook(
        playbook_id="ransomware-chain",
        name="Ransomware Scenario",
        description="Emulates complete ransomware lifecycle",
        technique_ids=["T1087", "T1548", "T1070"],
        author="Purple Engineer",
    )
    repo.save_playbook(playbook)

    fetched = repo.get_playbook("ransomware-chain")
    assert fetched is not None
    assert fetched.name == "Ransomware Scenario"
    assert fetched.technique_ids == ["T1087", "T1548", "T1070"]

    # Update playbook
    updated_playbook = CampaignPlaybook(
        playbook_id="ransomware-chain",
        name="Ransomware Scenario Updated",
        description="Updated description",
        technique_ids=["T1087", "T1046"],
        author="Lead Architect",
    )
    repo.save_playbook(updated_playbook)
    fetched_updated = repo.get_playbook("ransomware-chain")
    assert fetched_updated is not None
    assert fetched_updated.name == "Ransomware Scenario Updated"

    all_playbooks = repo.list_playbooks()
    assert len(all_playbooks) >= 3
    assert repo.get_playbook("nonexistent") is None


def test_campaign_and_steps_crud(repo: PurpleRangeRepository) -> None:
    """Verify campaign persistence, emulation steps, and cascade retrieval."""
    now = datetime.now(UTC)
    campaign = PurpleCampaign(
        campaign_id="camp-sql-1",
        name="SQL Persistence Test Campaign",
        status=EmulationStatus.RUNNING,
        operator="test_operator",
        started_at=now,
    )
    repo.save_campaign(campaign)

    step = EmulationStep(
        execution_id="step-sql-1",
        campaign_id="camp-sql-1",
        technique_id="T1087.001",
        technique_name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_executed="cat /etc/passwd",
        stdout="root:x:0:0",
        exit_code=0,
        status=EmulationStatus.COMPLETED,
        started_at=now,
    )
    repo.save_emulation_step(step)

    # Fetch steps
    steps = repo.get_steps_for_campaign("camp-sql-1")
    assert len(steps) == 1
    assert steps[0].execution_id == "step-sql-1"
    assert steps[0].tactic == MitreTactic.DISCOVERY

    # Fetch full campaign
    fetched_campaign = repo.get_campaign("camp-sql-1")
    assert fetched_campaign is not None
    assert fetched_campaign.name == "SQL Persistence Test Campaign"
    assert len(fetched_campaign.emulation_steps) == 1

    # List campaigns
    all_camps = repo.list_campaigns()
    assert len(all_camps) == 1
    assert repo.get_campaign("nonexistent") is None


def test_detection_alerts_and_evidences(repo: PurpleRangeRepository) -> None:
    """Verify saving alerts and detection evidences."""
    now = datetime.now(UTC)

    # 1. Alert
    alert = DetectionAlert(
        alert_id="alert-sql-1",
        sensor_name="sysmon",
        technique_id="T1046",
        timestamp=now,
        host="localhost",
        alert_signature="Port Scan",
        severity=TechniqueSeverity.HIGH,
        raw_log={"port": 22},
    )
    repo.save_alert(alert)
    alerts = repo.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].sensor_name == "sysmon"

    # 2. Campaign & Step for Evidence Foreign Key
    campaign = PurpleCampaign(
        campaign_id="camp-ev",
        name="Evidence Test Campaign",
        started_at=now,
    )
    repo.save_campaign(campaign)
    step = EmulationStep(
        execution_id="step-ev-1",
        campaign_id="camp-ev",
        technique_id="T1046",
        technique_name="Port Scan",
        tactic=MitreTactic.DISCOVERY,
        command_executed="ss -tuln",
        started_at=now,
    )
    repo.save_emulation_step(step)

    # 3. Evidence
    evidence = DetectionEvidence(
        evidence_id="ev-sql-1",
        execution_id="step-ev-1",
        technique_id="T1046",
        verdict=DetectionVerdict.DETECTED,
        matched_alerts=[alert],
        detection_latency_seconds=1.8,
        matched_at=now,
        notes="Correlated successfully",
    )
    repo.save_evidence(evidence)

    evidences = repo.get_evidences_for_campaign("camp-ev")
    assert len(evidences) == 1
    assert evidences[0].verdict == DetectionVerdict.DETECTED
    assert len(evidences[0].matched_alerts) == 1


def test_heatmap_persistence(repo: PurpleRangeRepository) -> None:
    """Verify persisting and querying latest matrix heatmap."""
    now = datetime.now(UTC)
    cell = TechniqueCoverageCell(
        technique_id="T1087.001",
        technique_name="Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        verdict=DetectionVerdict.DETECTED,
        execution_count=1,
    )
    summary = TacticSummary(
        tactic=MitreTactic.DISCOVERY,
        total_tested=1,
        detected=1,
        coverage_rate=100.0,
    )
    heatmap = PurpleMatrixHeatmap(
        campaign_id="camp-heat-1",
        generated_at=now,
        total_techniques=1,
        detected_count=1,
        detection_coverage_rate=100.0,
        tactic_summaries={MitreTactic.DISCOVERY.value: summary},
        cells=[cell],
        blind_spots=[],
    )

    repo.save_heatmap(heatmap)

    fetched = repo.get_latest_heatmap("camp-heat-1")
    assert fetched is not None
    assert fetched.detection_coverage_rate == 100.0
    assert len(fetched.cells) == 1
    assert fetched.tactic_summaries[MitreTactic.DISCOVERY.value].coverage_rate == 100.0

    global_fetched = repo.get_latest_heatmap()
    assert global_fetched is not None
    assert repo.get_latest_heatmap("nonexistent-campaign") is None


def test_sigma_rule_persistence(repo: PurpleRangeRepository) -> None:
    """Verify saving and listing Sigma rules in repository."""
    rule = SigmaRule(
        id="sigma-sql-1",
        title="Test Sigma DB Rule",
        description="Testing DB persistence of synthesized Sigma rule",
        date="2026-10-14",
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"CommandLine|contains": "whoami"}},
        falsepositives=["Admin activity"],
        tags=["attack.discovery"],
    )
    repo.save_sigma_rule(rule, technique_id="T1087.001")

    rules = repo.list_sigma_rules()
    assert len(rules) == 1
    assert rules[0].title == "Test Sigma DB Rule"
    assert rules[0].id == "sigma-sql-1"
