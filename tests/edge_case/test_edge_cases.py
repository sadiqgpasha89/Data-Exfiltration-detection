"""Edge Case & Adversarial Evasion Tests based on Section 10 of the Architectural Blueprint."""

import pytest
from src.agents.swarm_orchestrator import swarm_orchestrator
from src.core.crypto_audit import worm_ledger
from src.core.models import TelemetryEvent
from src.data_engineering.feature_store import feature_store
from src.data_engineering.pipeline import data_pipeline
from src.datascience.tier1_rules import tier1_engine
from src.datascience.tier1_rules.stego_detector import stego_detector
from src.datascience.tier2_ml import tier2_scorer
from src.hitl.case_manager import case_manager


def test_edge_case_1_low_and_slow_drip_exfiltration():
    """10.1: Drip Exfiltration over 180 days.

    5 records extracted periodically by Marcus Vance (who tendered resignation).
    Rolling cumulative read-to-export ratio deviation is caught by Layer 2 and Layer 3.
    """
    drip_event = TelemetryEvent(
        event_id="evt-drip-180d-test",
        timestamp="2026-09-14T23:30:00Z",
        event_type="database_query",
        source_ip="10.240.12.84",
        destination_ip="10.240.10.50",
        destination_port=5432,
        protocol="TCP",
        user_id="usr_dev_4091",
        process_name="python_eval.exe",
        query="SELECT customer_id, ssn, credit_score, balance FROM hnw_clients LIMIT 5",
        bytes_in=250,
        bytes_out=1820,
        payload_entropy=4.55,
        record_count=5,
        category="low_and_slow_drip",
    )

    # Force user counters to simulate months of small exports
    feature_store.cumulative_drip_counters["usr_dev_4091"] = {
        "records_read": 120.0,
        "records_exported": 850.0,
        "access_count": 180,
    }

    event, tokenized, features = data_pipeline.process_raw_event(drip_event.model_dump())
    assert features.rolling_read_to_export_ratio_180d < 1.0

    l1_eval = tier1_engine.evaluate(event)
    l2_eval = tier2_scorer.evaluate(event, features)

    # Resigned employee with abnormal cumulative export ratio triggers swarm
    dossier = swarm_orchestrator.execute_investigation(
        event=event,
        feature_vector=features,
        layer1_eval=l1_eval,
        layer2_eval=l2_eval,
    )

    assert dossier.verdict == "MALICIOUS_EXFILTRATION"
    assert any("resignation" in c.lower() for c in dossier.citations)


def test_edge_case_2_lsb_media_steganography():
    """10.2: LSB Media Steganography.

    Cardholder records concealed in PNG image with high Chi-square randomness.
    """
    stego_event = TelemetryEvent(
        event_id="evt-stego-image-test",
        timestamp="2026-09-14T14:10:00Z",
        event_type="file_egress",
        source_ip="10.240.12.84",
        destination_ip="203.0.113.88",
        destination_port=443,
        protocol="TCP",
        user_id="usr_dev_4091",
        process_name="chrome.exe",
        file_name="quarterly_banner_logo.png",
        bytes_in=512,
        bytes_out=8450000,
        payload_entropy=7.94,
        chi_square_randomness=285.4,
        record_count=4500,
        category="media_steganography",
    )

    l1_eval = tier1_engine.evaluate(stego_event)
    assert l1_eval.is_stego_detected is True
    assert l1_eval.action in ["HARD_DROP", "FLAG_DEEP_INSPECTION"]


def test_edge_case_3_insider_collusion_dba_soc_analyst():
    """10.3: High-Privilege Insider Collusion (DBA + SOC Analyst).

    DBA dumps database. Rogue analyst attempts to mark alert as False Positive.
    WORM ledger detects contradictory suppression and flags CISO escalation.
    """
    collusion_event = TelemetryEvent(
        event_id="evt-collusion-test",
        timestamp="2026-09-14T23:45:00Z",
        event_type="database_dump",
        source_ip="10.240.5.10",
        destination_ip="10.240.10.50",
        destination_port=5432,
        protocol="TCP",
        user_id="usr_dba_1022",
        process_name="pg_dump.exe",
        query="COPY customer_accounts_master TO STDOUT WITH (FORMAT CSV, HEADER)",
        bytes_in=450,
        bytes_out=2147483648,
        payload_entropy=6.85,
        record_count=480000,
        category="insider_collusion",
    )

    event, tokenized, features = data_pipeline.process_raw_event(collusion_event.model_dump())
    l1_eval = tier1_engine.evaluate(event)
    l2_eval = tier2_scorer.evaluate(event, features)

    dossier = swarm_orchestrator.execute_investigation(
        event=event,
        feature_vector=features,
        layer1_eval=l1_eval,
        layer2_eval=l2_eval,
    )
    case_manager.add_dossier(dossier)
    assert dossier.final_risk_score >= 0.85

    # Rogue SOC Analyst attempts to dismiss this high-severity case as FALSE_POSITIVE
    adjudication = case_manager.adjudicate_case(
        case_id=dossier.case_id,
        analyst_id="usr_soc_7821_rogue",
        action="FALSE_POSITIVE",
        notes="Routine maintenance, closing alert.",
    )

    # WORM ledger MUST flag this override as suspicious and escalate to CISO
    assert adjudication["audit_check"]["is_suspicious_override"] is True
    assert "CHIEF_INFORMATION_SECURITY_OFFICER" in adjudication["audit_check"]["escalation_target"]


def test_edge_case_4_legitimate_bulk_regulatory_audit(legitimate_audit_event):
    """10.4: Legitimate Bulk Operations vs Malicious Exfiltration.

    Lead analyst performs 3.5GB FinCEN data extract under approved Jira ticket.
    Graph-RAG identifies ticket and permits transfer (True Negative).
    """
    event, tokenized, features = data_pipeline.process_raw_event(legitimate_audit_event.model_dump())
    l1_eval = tier1_engine.evaluate(event)
    l2_eval = tier2_scorer.evaluate(event, features)

    dossier = swarm_orchestrator.execute_investigation(
        event=event,
        feature_vector=features,
        layer1_eval=l1_eval,
        layer2_eval=l2_eval,
    )

    assert dossier.verdict == "LEGITIMATE_BULK_OPERATION"
    assert dossier.remediation_status.value == "DISMISSED_BENIGN"


def test_edge_case_5_canary_honeytoken_trip(honeytoken_event):
    """10.5: Canary Honeytoken Ingestion.

    Zero-tolerance trip on synthetic credit card number.
    """
    l1_eval = tier1_engine.evaluate(honeytoken_event)
    assert l1_eval.is_honeytoken_hit is True
    assert l1_eval.action == "HARD_DROP"
