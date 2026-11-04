"""The verdict is decided by evidence. Fields the sender of the telemetry controls must never decide it."""

import itertools

import pytest
from src.agents.swarm_orchestrator import swarm_orchestrator
from src.core.config import settings
from src.core.models import RemediationStatus, TelemetryEvent
from src.data_engineering.pipeline import data_pipeline
from src.datascience.tier1_rules import tier1_engine
from src.datascience.tier2_ml import tier2_scorer

_ids = itertools.count(1)


def investigate(**fields):
    base = dict(event_id=f"pol-{next(_ids)}", timestamp="2026-09-14T10:00:00Z", event_type="batch_export", source_ip="10.240.35.12",
                destination_ip="10.240.10.50", destination_port=443, user_id="usr_retail_5512", bytes_in=100, bytes_out=20_000_000,
                payload_entropy=3.0, record_count=500)
    base.update(fields)
    event, _, features = data_pipeline.process_raw_event(base)
    l1, l2 = tier1_engine.evaluate(event), tier2_scorer.evaluate(event, features)
    return swarm_orchestrator.execute_investigation(event, features, l1, l2), l1, l2


def test_category_label_cannot_choose_the_verdict():
    honest, _, _ = investigate(category="routine")
    spoofed, _, _ = investigate(category="insider_collusion")
    assert spoofed.verdict == honest.verdict  # the same evidence gives the same verdict whatever the label says
    assert spoofed.verdict != "MALICIOUS_EXFILTRATION"
    assert spoofed.remediation_status != RemediationStatus.AUTO_MITIGATED
    assert spoofed.containment == {}  # nothing was executed or even attempted


def test_malicious_with_strong_evidence_is_contained_only_when_enforced(monkeypatch):
    kwargs = dict(user_id="usr_dba_1022", source_ip="10.240.5.10", destination_ip="185.220.101.5", process_name="7z.exe",
                  event_type="network_flow", bytes_out=4_000_000_000, payload_entropy=7.95, record_count=1_000_000)
    dry, _, _ = investigate(**kwargs)
    assert dry.verdict == "MALICIOUS_EXFILTRATION" and dry.remediation_status == RemediationStatus.CONTAINMENT_RECOMMENDED
    assert dry.containment["mode"] == "dry_run" and dry.containment["executed"] and not dry.containment["effective"]
    assert dry.subject_ip == "10.240.5.10" and dry.subject_user_id == "usr_dba_1022"

    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "enforce")
    enforced, _, _ = investigate(**kwargs)
    # the default backend only simulates, so even in enforce mode the dossier does not claim a mitigation that did not happen
    assert enforced.remediation_status == RemediationStatus.CONTAINMENT_RECOMMENDED and not enforced.containment["effective"]


def test_protected_user_is_never_auto_contained(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "enforce")
    monkeypatch.setattr(settings, "PROTECTED_USER_IDS", "usr_dba_1022")
    dossier, _, _ = investigate(user_id="usr_dba_1022", source_ip="10.240.5.10", destination_ip="185.220.101.5", bytes_out=4_000_000_000,
                                payload_entropy=7.95, process_name="7z.exe", event_type="network_flow")
    assert dossier.verdict == "MALICIOUS_EXFILTRATION" and "protected" in dossier.containment["blocked_reason"]
    assert dossier.remediation_status == RemediationStatus.CONTAINMENT_RECOMMENDED


def test_valid_ticket_dismisses_only_clean_activity():
    legit, l1, _ = investigate(event_id="pol-legit", user_id="usr_analyst_3030", source_ip="10.240.8.44", destination_ip="192.0.2.100",
                               timestamp="2026-09-14T11:00:00Z", query="SELECT * FROM quarterly_regulatory_staging WHERE report_quarter = '2026-Q3'",
                               bytes_out=3_500_000_000, record_count=850_000, payload_entropy=5.4, process_name="fincen_gateway_client.py")
    assert legit.verdict == "LEGITIMATE_BULK_OPERATION" and legit.remediation_status == RemediationStatus.DISMISSED_BENIGN
    assert legit.final_risk_score <= 0.30 and "REG-2026-8910" in legit.root_cause_analysis

    # the same activity after the ticket expired is not dismissed
    late, _, _ = investigate(user_id="usr_analyst_3030", source_ip="10.240.8.44", destination_ip="192.0.2.100", timestamp="2026-11-03T11:00:00Z",
                             query="SELECT * FROM quarterly_regulatory_staging WHERE report_quarter = '2026-Q3'", bytes_out=3_500_000_000,
                             record_count=850_000, payload_entropy=5.4)
    assert late.verdict != "LEGITIMATE_BULK_OPERATION" and any("validity window" in c for c in late.citations)


def test_ticket_does_not_launder_a_hard_indicator():
    # a valid-looking ticket exists, but the destination is a known C2 address: not dismissed (and not even in the ticket's subnets)
    d, l1, _ = investigate(user_id="usr_analyst_3030", source_ip="10.240.8.44", destination_ip="185.220.101.5", timestamp="2026-09-14T11:00:00Z",
                           query="SELECT * FROM quarterly_regulatory_staging", bytes_out=3_500_000_000, record_count=850_000)
    assert l1.is_known_c2 and d.verdict == "MALICIOUS_EXFILTRATION"


def test_ticket_does_not_dismiss_sensitive_data_in_the_payload():
    d, l1, _ = investigate(user_id="usr_analyst_3030", source_ip="10.240.8.44", destination_ip="192.0.2.100", timestamp="2026-09-14T11:00:00Z",
                           query="SELECT * FROM quarterly_regulatory_staging", bytes_out=3_500_000_000, record_count=850_000,
                           raw_payload="export row: 4111 1111 1111 1111 and 123-45-6789")
    assert l1.is_regex_compliance_hit and d.verdict != "LEGITIMATE_BULK_OPERATION"
    assert d.remediation_status in (RemediationStatus.HITL_PENDING, RemediationStatus.CONTAINMENT_RECOMMENDED)


def test_honeytoken_is_critical_with_full_risk_score():
    d, l1, _ = investigate(user_id="usr_dba_1022", source_ip="10.240.5.10", event_type="database_query", bytes_out=500, record_count=1,
                           query="SELECT * FROM cardholder_records WHERE card_number = '4532-0198-4421-9988'")
    assert l1.is_honeytoken_hit and d.verdict == "MALICIOUS_EXFILTRATION" and d.severity.value == "CRITICAL" and d.final_risk_score == 1.0


def test_unauthorized_bulk_dump_off_hours_is_malicious_but_needs_a_human():
    d, _, _ = investigate(event_id="pol-dump", user_id="usr_dba_1022", source_ip="10.240.5.10", destination_ip="10.240.10.50", event_type="database_dump",
                          timestamp="2026-09-14T23:45:00Z", process_name="pg_dump.exe", bytes_out=2_147_483_648, record_count=480_000,
                          query="COPY customer_accounts_master TO STDOUT WITH (FORMAT CSV, HEADER)", payload_entropy=6.85)
    assert d.verdict == "MALICIOUS_EXFILTRATION" and d.final_risk_score >= 0.85
    assert d.remediation_status == RemediationStatus.CONTAINMENT_RECOMMENDED
    assert "analyst approval" in d.containment["blocked_reason"]  # not strong enough for automatic containment


def test_low_score_without_findings_is_a_false_positive():
    d, _, l2 = investigate(bytes_out=11_000_000, payload_entropy=3.5, record_count=5)  # L1 flags size only
    if l2.ensemble_risk_score < settings.ANOMALY_DISPATCH_THRESHOLD_TAU:
        assert d.verdict == "FALSE_POSITIVE" and d.remediation_status == RemediationStatus.DISMISSED_BENIGN
    assert d.worm_immutable_hash


def test_dossier_is_in_the_ledger_with_containment_summary():
    from src.core.crypto_audit import worm_ledger
    d, _, _ = investigate(user_id="usr_dba_1022", source_ip="10.240.5.10", destination_ip="185.220.101.5", bytes_out=4_000_000_000,
                          payload_entropy=7.95, process_name="7z.exe", event_type="network_flow")
    assert any(b.block_hash == d.worm_immutable_hash for b in worm_ledger.chain)
    assert worm_ledger.verify_chain()["valid"]
