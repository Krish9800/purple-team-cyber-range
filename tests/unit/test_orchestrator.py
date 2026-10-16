"""Unit tests for PurpleTeamOrchestrator and campaign execution workflows."""

from pathlib import Path

import pytest

from purple_range.db import DatabaseManager, PurpleRangeRepository
from purple_range.emulation.catalog import BUILTIN_TECHNIQUES
from purple_range.emulation.runner import AdversaryEmulationEngine
from purple_range.models import (
    DetectionAlert,
    EmulationStatus,
    MitreTactic,
    MitreTechnique,
)
from purple_range.orchestrator.service import CampaignOrchestrator


def get_test_repo(temp_db_path: Path) -> PurpleRangeRepository:
    manager = DatabaseManager(temp_db_path)
    repository = PurpleRangeRepository(manager)
    repository.initialize_schema()
    return repository


def test_orchestrator_initialization_and_seeding(temp_db_path: Path) -> None:
    """Verify default playbooks are seeded on initialization."""
    repo = get_test_repo(temp_db_path)
    orchestrator = CampaignOrchestrator(repository=repo)
    playbooks = orchestrator.repo.list_playbooks()
    assert len(playbooks) >= 2


@pytest.mark.asyncio
async def test_run_campaign_with_playbook(temp_db_path: Path) -> None:
    """Verify running a campaign using a valid playbook ID."""
    repo = get_test_repo(temp_db_path)
    orchestrator = CampaignOrchestrator(repository=repo)

    playbooks = orchestrator.repo.list_playbooks()
    target_pb = playbooks[0]

    campaign, heatmap, sigma_rules = await orchestrator.async_run_campaign(
        name="Test Playbook Campaign",
        playbook_id=target_pb.playbook_id,
        operator="test_operator",
    )

    assert campaign.status == EmulationStatus.COMPLETED
    assert campaign.campaign_id is not None
    assert heatmap.total_techniques >= 1
    assert isinstance(sigma_rules, list)


@pytest.mark.asyncio
async def test_run_campaign_with_technique_ids(temp_db_path: Path) -> None:
    """Verify running a campaign with explicit technique IDs."""
    repo = get_test_repo(temp_db_path)
    orchestrator = CampaignOrchestrator(repository=repo)

    campaign, heatmap, sigma_rules = await orchestrator.async_run_campaign(
        name="Test Technique Campaign",
        technique_ids=["T1087.001", "T1046"],
        operator="test_operator",
    )

    assert campaign.status == EmulationStatus.COMPLETED
    assert heatmap.total_techniques == 2


@pytest.mark.asyncio
async def test_run_campaign_missing_playbook_raises(temp_db_path: Path) -> None:
    """Verify ValueError is raised if playbook_id does not exist."""
    repo = get_test_repo(temp_db_path)
    orchestrator = CampaignOrchestrator(repository=repo)

    with pytest.raises(ValueError, match="Playbook 'nonexistent-pb' not found"):
        await orchestrator.async_run_campaign(
            name="Invalid PB Campaign",
            playbook_id="nonexistent-pb",
        )


@pytest.mark.asyncio
async def test_run_campaign_missing_both_args_raises(temp_db_path: Path) -> None:
    """Verify ValueError is raised if neither playbook nor technique_ids is given."""
    repo = get_test_repo(temp_db_path)
    orchestrator = CampaignOrchestrator(repository=repo)

    with pytest.raises(ValueError, match="Either playbook_id or technique_ids must be provided"):
        await orchestrator.async_run_campaign(name="No Params Campaign")


@pytest.mark.asyncio
async def test_run_campaign_skips_unknown_technique_ids(temp_db_path: Path) -> None:
    """Verify unknown technique IDs are skipped gracefully without failing."""
    repo = get_test_repo(temp_db_path)
    orchestrator = CampaignOrchestrator(repository=repo)

    campaign, heatmap, _ = await orchestrator.async_run_campaign(
        name="Unknown Technique Skip Test",
        technique_ids=["T9998", "T1046"],
    )

    assert campaign.status == EmulationStatus.COMPLETED
    assert heatmap.total_techniques == 1


@pytest.mark.asyncio
async def test_run_campaign_with_pre_existing_alerts(temp_db_path: Path) -> None:
    """Verify pre-existing stored alerts are correlated during campaign execution."""
    repo = get_test_repo(temp_db_path)
    alert = DetectionAlert(
        alert_id="alert-test-discovery",
        sensor_name="sysmon",
        technique_id="T1046",
        alert_signature="Network Service Scanning Detected",
        raw_log={"port": 22},
    )
    repo.save_alert(alert)

    orchestrator = CampaignOrchestrator(repository=repo)
    campaign, heatmap, _ = await orchestrator.async_run_campaign(
        name="Alert Correlation Campaign",
        technique_ids=["T1046"],
    )

    assert campaign.status == EmulationStatus.COMPLETED
    assert heatmap.total_techniques == 1
    assert heatmap.detected_count >= 1


@pytest.mark.asyncio
async def test_emulation_engine_timeout_handling() -> None:
    """Verify AdversaryEmulationEngine correctly enforces process timeout and kills process."""
    engine = AdversaryEmulationEngine(default_timeout_seconds=1)

    timeout_tech = MitreTechnique(
        technique_id="T9999.001",
        name="Timeout Simulation Test",
        tactic=MitreTactic.EXECUTION,
        command_template="sleep 5",
        description="Technique designed to exceed timeout.",
    )

    step = await engine.async_execute_technique(
        technique=timeout_tech,
        campaign_id="test-timeout-campaign",
        timeout_seconds=1,
    )

    assert step.status == EmulationStatus.TIMED_OUT
    assert step.exit_code == 124
    assert "timed out after 1s" in (step.error_message or "")


@pytest.mark.asyncio
async def test_emulation_engine_cleanup_execution() -> None:
    """Verify cleanup_command executes after technique runs."""
    engine = AdversaryEmulationEngine(default_timeout_seconds=5)

    tech_with_cleanup = MitreTechnique(
        technique_id="T9999.002",
        name="Cleanup Test Technique",
        tactic=MitreTactic.EXECUTION,
        command_template="echo 'running step'",
        cleanup_command="echo 'running cleanup'",
        description="Technique with cleanup command.",
    )

    step = await engine.async_execute_technique(
        technique=tech_with_cleanup,
        campaign_id="test-cleanup-campaign",
    )

    assert step.status == EmulationStatus.COMPLETED
    assert step.cleanup_executed is True


def test_synchronous_execute_technique() -> None:
    """Verify execute_technique synchronous wrapper."""
    engine = AdversaryEmulationEngine(default_timeout_seconds=5)
    tech = BUILTIN_TECHNIQUES[0]
    step = engine.execute_technique(tech, campaign_id="sync-test")
    assert step.status in (EmulationStatus.COMPLETED, EmulationStatus.FAILED)
