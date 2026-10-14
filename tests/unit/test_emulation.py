"""Unit tests for Phase 3: Adversary Emulation Engine and technique catalog."""

import pytest

from purple_range.emulation import (
    BUILTIN_TECHNIQUES,
    AdversaryEmulationEngine,
    EmulationSafetyError,
    PreFlightValidator,
    TechniqueRegistry,
)
from purple_range.models import (
    EmulationStatus,
    MitreTactic,
    MitreTechnique,
)


def test_builtin_catalog_contains_core_tactics() -> None:
    """Verify built-in catalog covers Discovery, Credential Access, Persistence, etc."""
    registry = TechniqueRegistry()
    assert registry.count() >= 6
    tactics = {tech.tactic for tech in registry.list_all()}
    assert MitreTactic.DISCOVERY in tactics
    assert MitreTactic.CREDENTIAL_ACCESS in tactics
    assert MitreTactic.PERSISTENCE in tactics
    assert MitreTactic.PRIVILEGE_ESCALATION in tactics
    assert MitreTactic.DEFENSE_EVASION in tactics


def test_technique_registry_operations() -> None:
    """Verify registration, lookup, and filtering."""
    registry = TechniqueRegistry(BUILTIN_TECHNIQUES)
    tech = registry.get("T1087.001")
    assert tech is not None
    assert tech.name == "Local Account Discovery"

    discovery_list = registry.filter_by_tactic(MitreTactic.DISCOVERY)
    assert len(discovery_list) >= 2
    for item in discovery_list:
        assert item.tactic == MitreTactic.DISCOVERY

    # Register custom technique
    custom_tech = MitreTechnique(
        technique_id="T1059.004",
        name="Unix Shell Execution",
        tactic=MitreTactic.EXECUTION,
        command_template="echo 'test execution'",
        description="Testing shell execution.",
    )
    registry.register(custom_tech)
    assert registry.get("T1059.004") is not None
    assert registry.get("NONEXISTENT") is None


def test_preflight_validator_safe_and_unsafe() -> None:
    """Verify preflight rejects dangerous payloads."""
    PreFlightValidator.validate_command("whoami && id")

    with pytest.raises(EmulationSafetyError, match="empty"):
        PreFlightValidator.validate_command("   ")

    with pytest.raises(EmulationSafetyError, match="unsafe pattern"):
        PreFlightValidator.validate_command("rm -rf /")

    with pytest.raises(EmulationSafetyError, match="unsafe pattern"):
        PreFlightValidator.validate_command(":(){ :|:& };:")

    with pytest.raises(EmulationSafetyError, match="unsafe pattern"):
        PreFlightValidator.validate_command("mkfs /dev/sda1")

    with pytest.raises(EmulationSafetyError, match="unsafe pattern"):
        PreFlightValidator.validate_command("dd if=/dev/zero of=/dev/null")

    with pytest.raises(EmulationSafetyError, match="unsafe pattern"):
        PreFlightValidator.validate_command("shutdown -h now")


@pytest.mark.asyncio
async def test_emulation_engine_safe_execution() -> None:
    """Verify execution of a benign technique in cyber range sandbox."""
    engine = AdversaryEmulationEngine(default_timeout_seconds=5)
    tech = MitreTechnique(
        technique_id="T1087.001",
        name="Local Account Discovery Test",
        tactic=MitreTactic.DISCOVERY,
        command_template="echo 'user: krish' && id -u",
        description="Test account discovery execution",
    )
    step = await engine.async_execute_technique(technique=tech, campaign_id="camp-test-1")

    assert step.status == EmulationStatus.COMPLETED
    assert step.exit_code == 0
    assert "user: krish" in step.stdout
    assert step.process_pid is not None
    assert step.duration_ms > 0
    assert step.completed_at is not None
    assert step.error_message is None


@pytest.mark.asyncio
async def test_emulation_engine_with_parameters_and_cleanup() -> None:
    """Verify command template parameter substitution and cleanup execution."""
    engine = AdversaryEmulationEngine()
    tech = MitreTechnique(
        technique_id="T1547.001",
        name="Persistence Test",
        tactic=MitreTactic.PERSISTENCE,
        command_template="echo '{content}' > {target_file}",
        cleanup_command="rm -f {target_file}",
        parameters={"content": "malicious_line", "target_file": "/tmp/test_purple_persist.txt"},
        description="Emulates startup persistence",
    )
    step = await engine.async_execute_technique(
        technique=tech,
        campaign_id="camp-param-1",
        custom_params={"content": "range_custom_marker"},
    )

    assert step.status == EmulationStatus.COMPLETED
    assert "range_custom_marker" in step.command_executed
    assert step.cleanup_executed is True


@pytest.mark.asyncio
async def test_emulation_engine_preflight_rejection() -> None:
    """Verify engine returns FAILED step when command violates safety policy."""
    engine = AdversaryEmulationEngine()
    unsafe_tech = MitreTechnique(
        technique_id="T1070.004",
        name="Dangerous Removal",
        tactic=MitreTactic.DEFENSE_EVASION,
        command_template="rm -rf /",
        description="Dangerous command",
    )
    step = await engine.async_execute_technique(
        technique=unsafe_tech,
        campaign_id="camp-unsafe",
    )
    assert step.status == EmulationStatus.FAILED
    assert step.exit_code == 126
    assert "Preflight validation failed" in str(step.error_message)


@pytest.mark.asyncio
async def test_emulation_engine_timeout() -> None:
    """Verify timeout triggers TIMED_OUT status and terminates process."""
    engine = AdversaryEmulationEngine()
    sleep_tech = MitreTechnique(
        technique_id="T1087.001",
        name="Long Sleep Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_template="sleep 5",
        description="Sleep to test timeout handling",
    )
    step = await engine.async_execute_technique(
        technique=sleep_tech,
        campaign_id="camp-timeout",
        timeout_seconds=1,
    )
    assert step.status == EmulationStatus.TIMED_OUT
    assert step.exit_code == 124
    assert "timed out after 1s" in str(step.error_message)


def test_synchronous_execute_technique() -> None:
    """Verify sync wrapper execute_technique."""
    engine = AdversaryEmulationEngine(default_timeout_seconds=5)
    tech = MitreTechnique(
        technique_id="T1046",
        name="Port Scan Discovery",
        tactic=MitreTactic.DISCOVERY,
        command_template="echo 'open 80/tcp'",
        description="Network scan check",
    )
    step = engine.execute_technique(technique=tech, campaign_id="camp-sync")
    assert step.status == EmulationStatus.COMPLETED
    assert "open 80/tcp" in step.stdout


@pytest.mark.asyncio
async def test_cleanup_failure_resilience() -> None:
    """Verify failed cleanup command does not crash engine."""
    engine = AdversaryEmulationEngine()
    # Provide an invalid unsafe cleanup command
    result = await engine._async_cleanup("rm -rf /")
    assert result is False


@pytest.mark.asyncio
async def test_emulation_engine_subprocess_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify handling when subprocess launch raises an OS error."""
    engine = AdversaryEmulationEngine()
    tech = MitreTechnique(
        technique_id="T1046",
        name="Network Scan",
        tactic=MitreTactic.DISCOVERY,
        command_template="ss -tuln",
        description="Network scan check",
    )

    async def mock_subprocess_error(*args: object, **kwargs: object) -> None:
        raise OSError("Simulated system process spawn failure")

    monkeypatch.setattr("asyncio.create_subprocess_shell", mock_subprocess_error)
    step = await engine.async_execute_technique(technique=tech, campaign_id="camp-err")
    assert step.status == EmulationStatus.FAILED
    assert step.exit_code == 1
    assert "Simulated system process spawn failure" in str(step.error_message)
