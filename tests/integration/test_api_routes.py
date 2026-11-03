"""Integration tests for FastAPI REST API endpoints."""

import pytest
from fastapi.testclient import TestClient
from src.api.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_check_endpoint(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "hybrid_topology" in data


def test_dashboard_html_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "SENTINEL DATA EXFILTRATION DEFENSE" in response.text
    assert "OpenStack Edge Telemetry Bus" in response.text


def test_telemetry_routes(client, benign_event):
    # Ingest
    res_ingest = client.post("/api/v1/telemetry/ingest", json=benign_event.model_dump())
    assert res_ingest.status_code == 200
    data = res_ingest.json()
    assert data["status"] == "INGESTED"

    # Recent
    res_recent = client.get("/api/v1/telemetry/recent?limit=10")
    assert res_recent.status_code == 200
    assert isinstance(res_recent.json(), list)


def test_evaluate_endpoint(client, dns_tunnel_event):
    res_eval = client.post("/api/v1/evaluate/process", json=dns_tunnel_event.model_dump())
    assert res_eval.status_code == 200
    data = res_eval.json()
    assert "layer1_evaluation" in data
    assert "layer2_evaluation" in data
    assert data["layer3_dispatched"] is True
    assert data["incident_dossier"]["verdict"] == "MALICIOUS_EXFILTRATION"


def test_incidents_and_worm_routes(client):
    res_inc = client.get("/api/v1/incidents")
    assert res_inc.status_code == 200
    assert isinstance(res_inc.json(), list)

    res_worm = client.get("/api/v1/incidents/worm/verify")
    assert res_worm.status_code == 200
    data = res_worm.json()
    assert data["chain_valid"] is True


def test_metrics_observatory_endpoint(client):
    res_metrics = client.get("/api/v1/metrics")
    assert res_metrics.status_code == 200
    report = res_metrics.json()
    assert "business_metrics" in report
    assert "system_metrics" in report
    assert "ml_metrics" in report
    assert "rag_metrics" in report
    assert "agentic_metrics" in report


def test_drift_and_governance_endpoint(client):
    res_drift = client.get("/api/v1/drift/report")
    assert res_drift.status_code == 200
    data = res_drift.json()
    assert "drift_metrics" in data
    assert "production_models" in data
    assert "prompt_templates" in data


def test_simulator_injection_endpoint(client):
    res_sim = client.post("/api/v1/simulator/inject/t1048_dns_tunnel")
    assert res_sim.status_code == 200
    data = res_sim.json()
    assert data["scenario_injected"] == "t1048_dns_tunnel"
    assert data["incident_dossier"]["verdict"] == "MALICIOUS_EXFILTRATION"
