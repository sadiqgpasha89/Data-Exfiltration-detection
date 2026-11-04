"""Access control, input handling and operational endpoints, exercised through the real application."""

import json

import pytest
from fastapi.testclient import TestClient
from src.api.main import app
from src.core.config import settings
from src.core.security import rate_limiter
from tests.conftest import headers_for

EVENT = {
    "event_id": "api-sec-1", "timestamp": "2026-09-14T10:00:00Z", "event_type": "batch_export", "source_ip": "10.240.35.12",
    "destination_ip": "10.240.10.50", "destination_port": 443, "user_id": "usr_retail_5512", "bytes_in": 100, "bytes_out": 20_000_000,
    "payload_entropy": 3.0, "record_count": 500,
}


@pytest.fixture
def client(auth_keys):
    rate_limiter._buckets.clear()
    with TestClient(app) as c:
        yield c


def test_every_api_route_requires_a_key(client):
    calls = [
        ("get", "/api/v1/incidents"), ("get", "/api/v1/incidents/worm/verify"), ("get", "/api/v1/incidents/CASE-X"),
        ("post", "/api/v1/incidents/CASE-X/adjudicate"), ("post", "/api/v1/remediation/execute-playbook"),
        ("post", "/api/v1/evaluate/process"), ("post", "/api/v1/telemetry/ingest"), ("get", "/api/v1/telemetry/recent"),
        ("post", "/api/v1/telemetry/inject-seed"), ("get", "/api/v1/metrics"), ("get", "/api/v1/drift/report"),
        ("post", "/api/v1/drift/trigger-retrain"), ("post", "/api/v1/simulator/inject/t1048_dns_tunnel"),
    ]
    for method, path in calls:
        res = getattr(client, method)(path)
        assert res.status_code == 401, (method, path, res.status_code)
        assert res.headers["www-authenticate"] == "Bearer"
    assert client.get("/api/v1/incidents", headers={"X-API-Key": "wrong-key-0123456789abcdef"}).status_code == 401


def test_bearer_header_works_and_public_endpoints_stay_public(client):
    assert client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {headers_for('viewer')['X-API-Key']}"}).status_code == 200
    assert client.get("/healthz").status_code == 200 and client.get("/").status_code == 200


@pytest.mark.parametrize("role,method,path,allowed", [
    ("viewer", "get", "/api/v1/incidents", True), ("viewer", "get", "/api/v1/metrics", True),
    ("viewer", "post", "/api/v1/evaluate/process", False), ("viewer", "post", "/api/v1/remediation/execute-playbook", False),
    ("ingest", "get", "/api/v1/incidents", False), ("ingest", "post", "/api/v1/drift/trigger-retrain", False),
    ("analyst", "post", "/api/v1/drift/trigger-retrain", False), ("analyst", "get", "/api/v1/incidents/overrides/flagged", False),
    ("analyst", "post", "/api/v1/simulator/inject/t1048_dns_tunnel", False),
    ("admin", "get", "/api/v1/incidents/overrides/flagged", True),
])
def test_role_matrix(client, role, method, path, allowed):
    res = getattr(client, method)(path, headers=headers_for(role), **({"json": {}} if method == "post" else {}))
    assert (res.status_code != 403) is allowed, (role, path, res.status_code)


def test_ingest_role_can_evaluate_and_bad_bodies_are_422(client):
    ok = client.post("/api/v1/evaluate/process", json=EVENT, headers=headers_for("ingest"))
    assert ok.status_code == 200 and ok.json()["event_id"] == "api-sec-1"
    for bad in ({**EVENT, "event_id": "bad-port", "destination_port": 99999}, {**EVENT, "event_id": "neg", "bytes_out": -5}, {**EVENT, "event_id": "ip", "source_ip": "nope"}):
        assert client.post("/api/v1/evaluate/process", json=bad, headers=headers_for("ingest")).status_code == 422
    assert client.post("/api/v1/telemetry/ingest", json={}, headers=headers_for("ingest")).status_code == 422


def test_oversized_body_is_rejected(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_BODY_BYTES", 2_000)
    big = {**EVENT, "event_id": "big", "query": "x" * 5_000}
    assert client.post("/api/v1/evaluate/process", json=big, headers=headers_for("ingest")).status_code == 413
    assert client.post("/api/v1/evaluate/process", content=b"{" + b" " * 3_000, headers={**headers_for("ingest"), "content-type": "application/json"}).status_code == 413


def test_rate_limit_returns_429_with_retry_after(client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 3)
    codes = [client.get("/api/v1/incidents", headers=headers_for("viewer")) for _ in range(5)]
    assert [r.status_code for r in codes] == [200, 200, 200, 429, 429]
    assert int(codes[3].headers["retry-after"]) >= 1
    assert client.get("/api/v1/incidents", headers=headers_for("analyst")).status_code == 200  # limits are per principal


def test_saturation_sheds_load_with_503(client):
    from src.data_engineering.ingestion import ingestion_service
    taken = []
    while ingestion_service.acquire_slot():
        taken.append(1)
    try:
        res = client.post("/api/v1/evaluate/process", json={**EVENT, "event_id": "shed"}, headers=headers_for("ingest"))
        assert res.status_code == 503 and res.headers["retry-after"] == "2"
        assert ingestion_service.get_backpressure_ratio() == 1.0
    finally:
        for _ in taken:
            ingestion_service.release_slot()
    assert ingestion_service.get_backpressure_ratio() == 0.0


def _malicious(client, event_id):
    event = {**EVENT, "event_id": event_id, "user_id": "usr_dba_1022", "source_ip": "10.240.5.10", "destination_ip": "185.220.101.5", "process_name": "7z.exe",
             "event_type": "network_flow", "bytes_out": 4_000_000_000, "payload_entropy": 7.95, "record_count": 1_000_000}
    res = client.post("/api/v1/evaluate/process", json=event, headers=headers_for("ingest"))
    assert res.status_code == 200
    return res.json()["incident_dossier"]


def test_adjudication_records_the_authenticated_analyst_not_the_body(client):
    dossier = _malicious(client, "adj-1")
    res = client.post(f"/api/v1/incidents/{dossier['case_id']}/adjudicate", headers=headers_for("analyst"),
                      json={"action": "DISMISSED_BENIGN", "notes": "n", "analyst_id": "usr_someone_else"})
    assert res.status_code == 200
    audit = res.json()["audit_check"]
    assert audit["analyst_id"] == "analyst_user" and audit["is_suspicious_override"] is True  # the key's identity, not the claimed one
    assert res.json()["analyst_id"] == "analyst_user"
    flagged = client.get("/api/v1/incidents/overrides/flagged", headers=headers_for("admin")).json()
    assert any(f["case_id"] == dossier["case_id"] for f in flagged)

    again = client.post(f"/api/v1/incidents/{dossier['case_id']}/adjudicate", headers=headers_for("analyst"), json={"action": "ISOLATE"})
    assert again.status_code == 409
    assert client.post(f"/api/v1/incidents/{dossier['case_id']}/adjudicate", headers=headers_for("analyst"), json={"action": "SHRUG"}).status_code == 422
    assert client.post("/api/v1/incidents/NO-SUCH-CASE/adjudicate", headers=headers_for("analyst"), json={"action": "ISOLATE"}).status_code == 404


def test_containment_targets_come_from_the_case(client):
    dossier = _malicious(client, "contain-1")
    res = client.post("/api/v1/remediation/execute-playbook", headers=headers_for("analyst"),
                      json={"case_id": dossier["case_id"], "ip_address": "10.99.99.99", "user_id": "usr_ceo"})  # extra fields are ignored
    assert res.status_code == 200
    body = res.json()
    assert body["target"] == {"ip": "10.240.5.10", "user_id": "usr_dba_1022"}
    assert body["effective"] is False and {a["status"] for a in body["executed_actions"]} == {"SIMULATED"}  # honest: no real backend
    assert client.post("/api/v1/remediation/execute-playbook", headers=headers_for("analyst"), json={"case_id": dossier["case_id"]}).status_code == 409
    assert client.post("/api/v1/remediation/execute-playbook", headers=headers_for("analyst"), json={"case_id": "NOPE"}).status_code == 404
    assert client.post("/api/v1/remediation/execute-playbook", headers=headers_for("analyst"), json={}).status_code == 422


def test_protected_targets_need_an_administrator(client, monkeypatch):
    monkeypatch.setattr(settings, "PROTECTED_USER_IDS", "usr_dba_1022")
    first = _malicious(client, "prot-1")
    second = _malicious(client, "prot-2")
    assert client.post("/api/v1/remediation/execute-playbook", headers=headers_for("analyst"), json={"case_id": first["case_id"]}).status_code == 403
    assert client.post("/api/v1/remediation/execute-playbook", headers=headers_for("admin"), json={"case_id": second["case_id"]}).status_code == 200


def test_worm_verify_reports_tampering_as_data(client):
    from src.core.crypto_audit import worm_ledger
    _malicious(client, "worm-1")
    clean = client.get("/api/v1/incidents/worm/verify", headers=headers_for("viewer")).json()
    assert clean["chain_valid"] is True and clean["first_bad_index"] is None and clean["total_blocks"] >= 2
    block = worm_ledger.chain[-1]
    original = block.metadata["verdict"]
    block.metadata["verdict"] = "edited"
    try:
        res = client.get("/api/v1/incidents/worm/verify", headers=headers_for("viewer"))
        assert res.status_code == 200 and res.json()["chain_valid"] is False  # not a 500
        assert res.json()["first_bad_index"] == len(worm_ledger.chain) - 1
        assert client.get("/readyz").status_code == 503  # a broken audit chain takes the instance out of rotation
    finally:
        block.metadata["verdict"] = original
    assert client.get("/readyz").status_code == 200


def test_readyz_lists_its_checks(client):
    body = client.get("/readyz").json()
    assert body["status"] == "ready" and body["checks"]["audit_ledger_intact"] and body["checks"]["iam_directory_loaded"]
    assert any("LEDGER_PATH" in n for n in body["notes"])  # in-memory ledger is called out


def test_responses_carry_request_id_and_security_headers(client):
    res = client.get("/healthz", headers={"X-Request-ID": "trace-abc"})
    assert res.headers["x-request-id"] == "trace-abc" and res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in res.headers["content-security-policy"]
    assert client.get("/healthz").headers["x-request-id"]
    assert client.get("/api/v1/incidents", headers=headers_for("viewer")).headers["cache-control"] == "no-store"


def test_unhandled_errors_do_not_leak_details(client, monkeypatch):
    import src.api.routes.evaluate as route

    def boom(_event):
        raise RuntimeError("secret internal detail: db password hunter2")

    monkeypatch.setattr(route, "run_full_pipeline", boom)
    res = client.post("/api/v1/evaluate/process", json={**EVENT, "event_id": "boom"}, headers=headers_for("ingest"))
    assert res.status_code == 500 and "hunter2" not in res.text and "see server logs" in res.text


def test_simulator_and_seed_endpoints_are_hidden_when_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_SIMULATOR", False)
    assert client.post("/api/v1/simulator/inject/t1048_dns_tunnel", headers=headers_for("admin")).status_code == 404
    assert client.post("/api/v1/telemetry/inject-seed", headers=headers_for("admin")).status_code == 404
    monkeypatch.setattr(settings, "ENABLE_SIMULATOR", True)
    assert client.post("/api/v1/simulator/inject/t1048_dns_tunnel", headers=headers_for("admin")).status_code == 200
    assert client.post("/api/v1/simulator/inject/nope", headers=headers_for("admin")).status_code == 400


def test_misconfigured_keys_fail_closed(client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEYS", "broken-entry")
    assert client.get("/api/v1/incidents", headers=headers_for("viewer")).status_code == 503


def test_auth_disabled_is_refused_in_production(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_DISABLED", True)
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "API_KEYS", "")
    with pytest.raises(RuntimeError, match="Refusing to start in production"):
        with TestClient(app):
            pass
