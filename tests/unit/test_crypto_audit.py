"""Unit tests for WORM Append-Only Ledger and Anti-Collusion Audit."""

import pytest
from src.core.crypto_audit import WormAuditLedger, worm_ledger
from src.core.exceptions import AuditIntegrityError


def test_worm_ledger_block_creation_and_hash():
    test_ledger = WormAuditLedger()
    initial_len = len(test_ledger.chain)

    dossier = {
        "case_id": "TEST-CASE-001",
        "verdict": "MALICIOUS_EXFILTRATION",
        "final_risk_score": 0.95,
    }
    block_hash = test_ledger.append_incident_dossier("TEST-CASE-001", dossier)

    assert len(test_ledger.chain) == initial_len + 1
    assert len(block_hash) == 64
    assert test_ledger.verify_chain_integrity() is True


def test_worm_anti_collusion_override_detection():
    test_ledger = WormAuditLedger()

    # Suspicious scenario: Agent reports 0.95 risk, human analyst marks FALSE_POSITIVE
    audit_res = test_ledger.audit_human_decision(
        case_id="CASE-COLLUSION-001",
        agent_risk_score=0.95,
        analyst_action="FALSE_POSITIVE",
    )

    assert audit_res["is_suspicious_override"] is True
    assert "CHIEF_INFORMATION_SECURITY_OFFICER" in audit_res["escalation_target"]

    # Normal scenario: Agent reports 0.20 risk, analyst marks FALSE_POSITIVE
    audit_normal = test_ledger.audit_human_decision(
        case_id="CASE-NORMAL-002",
        agent_risk_score=0.20,
        analyst_action="FALSE_POSITIVE",
    )
    assert audit_normal["is_suspicious_override"] is False


def test_worm_tamper_detection():
    test_ledger = WormAuditLedger()
    test_ledger.append_incident_dossier("CASE-A", {"val": 1})
    test_ledger.append_incident_dossier("CASE-B", {"val": 2})

    assert test_ledger.verify_chain_integrity() is True

    # Intentionally tamper with block 1 payload hash
    test_ledger.chain[1].payload_hash = "tampered_payload_hash_value"

    with pytest.raises(AuditIntegrityError):
        test_ledger.verify_chain_integrity()
