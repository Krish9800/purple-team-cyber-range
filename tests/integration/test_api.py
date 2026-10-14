"""Integration tests for Phase 8: FastAPI REST Control Plane."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from purple_range.api import create_app
from purple_range.config.settings import Settings, get_settings


@pytest.fixture
def api_client(temp_db_path: Path) -> TestClient:
    """Provide TestClient with isolated temporary database."""
    test_settings = Settings(
        environment="testing",
        debug=True,
        db_path=temp_db_path,
        db_timeout_seconds=10.0,
    )
    app = create_app(test_settings)
    app.dependency_overrides[get_settings] = lambda: test_settings
    return TestClient(app)


def test_health_endpoints(api_client: TestClient) -> None:
    """Verify health endpoints return ok status."""
    res_root = api_client.get("/health")
    assert res_root.status_code == 200
    data_root = res_root.json()
    assert data_root["status"] == "ok"
    assert data_root["database"] == "connected"

    res_v1 = api_client.get("/api/v1/health")
    assert res_v1.status_code == 200
    assert res_v1.json()["environment"] == "testing"


def test_techniques_endpoints(api_client: TestClient) -> None:
    """Verify technique listing and lookup."""
    res = api_client.get("/api/v1/techniques")
    assert res.status_code == 200
    techniques = res.json()
    assert len(techniques) >= 6

    # Filter by tactic
    res_disc = api_client.get("/api/v1/techniques?tactic=discovery")
    assert res_disc.status_code == 200
    disc_techs = res_disc.json()
    assert len(disc_techs) >= 2
    for t in disc_techs:
        assert t["tactic"] == "discovery"

    # Get single
    res_single = api_client.get("/api/v1/techniques/T1087.001")
    assert res_single.status_code == 200
    assert res_single.json()["name"] == "Local Account Discovery"

    # Not found
    res_nf = api_client.get("/api/v1/techniques/T9999")
    assert res_nf.status_code == 404


def test_playbooks_endpoints(api_client: TestClient) -> None:
    """Verify listing and creating playbooks."""
    res = api_client.get("/api/v1/playbooks")
    assert res.status_code == 200
    playbooks = res.json()
    assert len(playbooks) >= 2  # seeded defaults

    # Create new playbook
    new_pb = {
        "playbook_id": "test-privesc-evasion",
        "name": "PrivEsc & Evasion Test",
        "description": "Integration test playbook scenario",
        "technique_ids": ["T1548.003", "T1070.004"],
        "author": "CI Integration Runner",
    }
    res_post = api_client.post("/api/v1/playbooks", json=new_pb)
    assert res_post.status_code == 201
    assert res_post.json()["playbook_id"] == "test-privesc-evasion"

    # Get created playbook
    res_get = api_client.get("/api/v1/playbooks/test-privesc-evasion")
    assert res_get.status_code == 200
    assert res_get.json()["technique_ids"] == ["T1548.003", "T1070.004"]

    # Not found
    assert api_client.get("/api/v1/playbooks/nonexistent").status_code == 404


def test_telemetry_alert_ingestion(api_client: TestClient) -> None:
    """Verify alert ingestion and query."""
    alert_payload = {
        "sensor_name": "suricata",
        "host": "localhost",
        "alert_signature": "ET SCAN Suspicious Port Scan",
        "technique_id": "T1046",
        "severity": "HIGH",
        "raw_log": {"proto": "TCP"},
    }
    res_post = api_client.post("/api/v1/telemetry/alerts", json=alert_payload)
    assert res_post.status_code == 201
    data = res_post.json()
    assert data["sensor_name"] == "suricata"
    assert data["technique_id"] == "T1046"

    # List alerts
    res_list = api_client.get("/api/v1/telemetry/alerts")
    assert res_list.status_code == 200
    alerts = res_list.json()
    assert len(alerts) >= 1


def test_campaign_run_and_reports(api_client: TestClient) -> None:
    """Verify end-to-end campaign execution, heatmap reporting, and Sigma advisor."""
    # Pre-check reports before run
    assert api_client.get("/api/v1/reports/heatmap").status_code == 404
    assert api_client.get("/api/v1/reports/summary").status_code == 404

    # Run campaign using seeded playbook
    run_req = {
        "name": "Automated Range Drill",
        "playbook_id": "ransomware-killchain",
        "operator": "test_runner",
    }
    res_run = api_client.post("/api/v1/campaigns/run", json=run_req)
    assert res_run.status_code == 200
    run_data = res_run.json()

    campaign = run_data["campaign"]
    assert campaign["name"] == "Automated Range Drill"
    assert campaign["status"] == "COMPLETED"
    assert len(campaign["emulation_steps"]) == 3
    assert len(campaign["evidences"]) == 3

    heatmap = run_data["heatmap"]
    assert heatmap["total_techniques"] == 3
    assert len(heatmap["cells"]) == 3

    # Check campaigns list and get by ID
    c_id = campaign["campaign_id"]
    res_camps = api_client.get("/api/v1/campaigns")
    assert res_camps.status_code == 200
    assert len(res_camps.json()) >= 1

    res_single_camp = api_client.get(f"/api/v1/campaigns/{c_id}")
    assert res_single_camp.status_code == 200
    assert res_single_camp.json()["campaign_id"] == c_id

    # Check heatmap endpoint
    res_heatmap = api_client.get("/api/v1/reports/heatmap")
    assert res_heatmap.status_code == 200
    assert res_heatmap.json()["total_techniques"] == 3

    # Check markdown summary
    res_summary = api_client.get("/api/v1/reports/summary")
    assert res_summary.status_code == 200
    assert "# Purple-Team Detection Verification Summary" in res_summary.text

    # Check Sigma Advisor
    res_sigma = api_client.get("/api/v1/advisor/sigma")
    assert res_sigma.status_code == 200
    sigma_rules = res_sigma.json()
    assert isinstance(sigma_rules, list)

    res_sigma_export = api_client.get("/api/v1/advisor/sigma/export")
    assert res_sigma_export.status_code == 200

    # Bad request (neither playbook nor technique_ids)
    res_bad = api_client.post("/api/v1/campaigns/run", json={"name": "Bad Run"})
    assert res_bad.status_code == 400
