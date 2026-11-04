"""Case closure rules: known actions only, one closure per case, every closure audited with the real analyst."""

from src.core.crypto_audit import worm_ledger
from src.core.models import IncidentDossier, RemediationStatus
from src.hitl.case_manager import CaseManager


def dossier(case_id, status=RemediationStatus.HITL_PENDING, score=0.9):
    return IncidentDossier(case_id=case_id, event_id="e", timestamp="2026-09-14T10:00:00+00:00", verdict="X", severity="HIGH", final_risk_score=score,
                           primary_hypothesis="h", root_cause_analysis="r", remediation_status=status, worm_immutable_hash="0" * 64)


def test_unknown_action_is_rejected_and_changes_nothing():
    mgr = CaseManager()
    mgr.add_dossier(dossier("C1"))
    result = mgr.adjudicate_case("C1", "usr_a", "SHRUG", "")
    assert result["success"] is False and "Unknown action" in result["error"]
    assert mgr.get_case("C1").remediation_status == RemediationStatus.HITL_PENDING


def test_a_case_closes_once():
    mgr = CaseManager()
    mgr.add_dossier(dossier("C2"))
    assert mgr.adjudicate_case("C2", "usr_a", "APPROVED_MITIGATE", "ok")["success"] is True
    again = mgr.adjudicate_case("C2", "usr_b", "DISMISSED_BENIGN", "changed my mind")
    assert again["success"] is False and "already closed" in again["error"]
    assert mgr.get_case("C2").remediation_status == RemediationStatus.APPROVED_MITIGATED


def test_auto_mitigated_cases_can_still_be_reviewed_and_missing_cases_are_reported():
    mgr = CaseManager()
    mgr.add_dossier(dossier("C3", status=RemediationStatus.AUTO_MITIGATED, score=0.95))
    assert mgr.adjudicate_case("C3", "usr_a", "FALSE_POSITIVE", "release")["success"] is True
    assert "not found" in mgr.adjudicate_case("NOPE", "usr_a", "ISOLATE", "")["error"]


def test_suspicious_dismissal_is_flagged_and_names_the_analyst():
    mgr = CaseManager()
    mgr.add_dossier(dossier("C4", score=0.92))
    result = mgr.adjudicate_case("C4", "usr_soc_7821", "DISMISSED_BENIGN", "routine")
    assert result["audit_check"]["is_suspicious_override"] is True and result["audit_check"]["analyst_id"] == "usr_soc_7821"
    assert mgr.flagged_overrides[-1]["case_id"] == "C4"
    assert any(b.metadata.get("case_id") == "AUDIT-C4" for b in worm_ledger.chain)


def test_queue_is_bounded(monkeypatch):
    import sys
    cm = sys.modules["src.hitl.case_manager"]  # `src.hitl.case_manager` the package attribute is the singleton instance, not the module
    monkeypatch.setattr(cm, "MAX_CASES", 3)
    mgr = CaseManager()
    for i in range(6):
        mgr.add_dossier(dossier(f"Q{i}"))
    assert [c.case_id for c in mgr.cases.values()] == ["Q3", "Q4", "Q5"]
