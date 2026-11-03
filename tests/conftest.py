"""Pytest configuration and shared fixtures for Data Exfiltration Detection platform."""

import pytest
from src.core.models import FeatureVector, TelemetryEvent


@pytest.fixture
def benign_event() -> TelemetryEvent:
    return TelemetryEvent(
        event_id="evt-test-benign-001",
        timestamp="2026-09-14T10:30:00Z",
        event_type="database_query",
        source_ip="10.240.35.12",
        destination_ip="10.240.10.50",
        destination_port=5432,
        protocol="TCP",
        user_id="usr_retail_5512",
        process_name="teller_portal.exe",
        query="SELECT customer_name, balance FROM accounts WHERE branch_id = 'B101' LIMIT 5",
        bytes_in=100,
        bytes_out=500,
        payload_entropy=3.8,
        record_count=5,
        category="benign_routine",
    )


@pytest.fixture
def dns_tunnel_event() -> TelemetryEvent:
    return TelemetryEvent(
        event_id="evt-test-tunnel-002",
        timestamp="2026-09-14T03:15:00Z",
        event_type="network_flow",
        source_ip="10.240.12.84",
        destination_ip="194.26.29.112",
        destination_port=53,
        protocol="UDP",
        user_id="usr_dev_4091",
        process_name="powershell.exe",
        domain_queried="dGhpcyBpcyBleGZpbA==.dns-tunnel-relay.xyz",
        bytes_in=64,
        bytes_out=12000,
        payload_entropy=7.88,
        record_count=200,
        category="mitre_t1048_dns_tunnel",
    )


@pytest.fixture
def burst_cloud_event() -> TelemetryEvent:
    return TelemetryEvent(
        event_id="evt-test-burst-003",
        timestamp="2026-09-14T01:30:00Z",
        event_type="network_flow",
        source_ip="10.240.5.10",
        destination_ip="185.220.101.5",
        destination_port=443,
        protocol="TCP",
        user_id="usr_dba_1022",
        process_name="7z.exe",
        bytes_in=1024,
        bytes_out=4000000000,
        payload_entropy=7.95,
        record_count=1000000,
        file_hash_sha256="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        category="mitre_t1567_burst_exfil",
    )


@pytest.fixture
def honeytoken_event() -> TelemetryEvent:
    return TelemetryEvent(
        event_id="evt-test-honey-004",
        timestamp="2026-09-14T14:20:00Z",
        event_type="database_query",
        source_ip="10.240.5.10",
        destination_ip="10.240.10.50",
        destination_port=5432,
        protocol="TCP",
        user_id="usr_dba_1022",
        process_name="dbeaver.exe",
        query="SELECT * FROM cardholder_records WHERE card_number = '4532-0198-4421-9988'",
        bytes_in=150,
        bytes_out=450,
        payload_entropy=4.1,
        record_count=1,
        category="honeytoken_canary",
    )


@pytest.fixture
def legitimate_audit_event() -> TelemetryEvent:
    return TelemetryEvent(
        event_id="evt-test-audit-005",
        timestamp="2026-09-14T11:00:00Z",
        event_type="batch_export",
        source_ip="10.240.8.44",
        destination_ip="192.0.2.100",
        destination_port=443,
        protocol="TCP",
        user_id="usr_analyst_3030",
        process_name="fincen_gateway_client.py",
        query="SELECT * FROM quarterly_regulatory_staging WHERE report_quarter = '2026-Q3'",
        bytes_in=5000,
        bytes_out=2500000000,
        payload_entropy=5.2,
        record_count=500000,
        category="legitimate_regulatory_bulk",
    )
