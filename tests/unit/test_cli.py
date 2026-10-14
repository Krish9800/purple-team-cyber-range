"""Unit tests for Phase 9: Typer CLI tool."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from purple_range.cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def setup_cli_env(temp_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Set temporary database path for CLI commands."""
    monkeypatch.setenv("PURPLE_DB_PATH", str(temp_db_path))
    monkeypatch.setenv("PURPLE_ENVIRONMENT", "testing")


def test_cli_version() -> None:
    """Verify version command output."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Purple-Team Cyber Range" in result.stdout


def test_cli_techniques() -> None:
    """Verify listing and showing techniques."""
    res_list = runner.invoke(app, ["techniques", "list"])
    assert res_list.exit_code == 0
    assert "T1087.001" in res_list.stdout

    res_filter = runner.invoke(app, ["techniques", "list", "--tactic", "discovery"])
    assert res_filter.exit_code == 0
    assert "discovery" in res_filter.stdout

    res_show = runner.invoke(app, ["techniques", "show", "T1087.001"])
    assert res_show.exit_code == 0
    assert "Local Account Discovery" in res_show.stdout

    res_nf = runner.invoke(app, ["techniques", "show", "T9999"])
    assert res_nf.exit_code == 1
    assert "not found" in res_nf.stdout


def test_cli_playbooks() -> None:
    """Verify playbooks listing and details."""
    res_list = runner.invoke(app, ["playbooks", "list"])
    assert res_list.exit_code == 0
    assert "ransomware-killchain" in res_list.stdout

    res_show = runner.invoke(app, ["playbooks", "show", "ransomware-killchain"])
    assert res_show.exit_code == 0
    assert "Ransomware Kill Chain" in res_show.stdout

    res_nf = runner.invoke(app, ["playbooks", "show", "nonexistent"])
    assert res_nf.exit_code == 1


def test_cli_telemetry_commands() -> None:
    """Verify telemetry alert ingestion and list commands."""
    res_ingest = runner.invoke(
        app,
        [
            "telemetry",
            "ingest",
            "--sensor",
            "sysmon",
            "--signature",
            "CLI Detection Event",
            "--technique",
            "T1087.001",
        ],
    )
    assert res_ingest.exit_code == 0
    assert "Alert ingested successfully" in res_ingest.stdout

    res_list = runner.invoke(app, ["telemetry", "list"])
    assert res_list.exit_code == 0
    assert "sysmon" in res_list.stdout


def test_cli_run_matrix_and_advisor(tmp_path: Path) -> None:
    """Verify drill execution, matrix display, and Sigma advisor output."""
    # Matrix before any drill
    res_pre_matrix = runner.invoke(app, ["matrix"])
    assert res_pre_matrix.exit_code == 1

    # Advisor before any drill
    res_pre_advisor = runner.invoke(app, ["advisor"])
    assert res_pre_advisor.exit_code == 0
    assert "No Sigma remediation rules currently stored" in res_pre_advisor.stdout

    # Run drill
    res_run = runner.invoke(
        app,
        [
            "run",
            "--name",
            "CLI Purple Drill",
            "--playbook",
            "ransomware-killchain",
            "--operator",
            "cli_tester",
        ],
    )
    assert res_run.exit_code == 0
    assert "Drill Complete!" in res_run.stdout
    assert "Overall Detection Coverage Rate" in res_run.stdout

    # Matrix after drill
    res_matrix = runner.invoke(app, ["matrix"])
    assert res_matrix.exit_code == 0
    assert "Total Evaluated" in res_matrix.stdout

    # Advisor after drill with export
    export_file = tmp_path / "exported_sigma.yaml"
    res_advisor = runner.invoke(app, ["advisor", "--export", str(export_file)])
    assert res_advisor.exit_code == 0
    assert export_file.exists()
    content = export_file.read_text(encoding="utf-8")
    assert "title:" in content
