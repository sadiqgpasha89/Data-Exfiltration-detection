"""HITL Case Management and Incident Adjudication."""

from typing import Any, Dict, List, Optional
from src.core.crypto_audit import worm_ledger
from src.core.models import IncidentDossier, RemediationStatus


class CaseManager:
    """Manages SOC incident adjudication queue and collusion audits."""

    def __init__(self):
        self.cases: Dict[str, IncidentDossier] = {}

    def add_dossier(self, dossier: IncidentDossier):
        self.cases[dossier.case_id] = dossier

    def get_case(self, case_id: str) -> Optional[IncidentDossier]:
        return self.cases.get(case_id)

    def list_cases(self, status: Optional[str] = None) -> List[IncidentDossier]:
        all_cases = list(self.cases.values())
        if status:
            return [c for c in all_cases if c.remediation_status == status]
        # Return sorted by timestamp descending
        return sorted(all_cases, key=lambda x: x.timestamp, reverse=True)

    def adjudicate_case(self, case_id: str, analyst_id: str, action: str, notes: str) -> Dict[str, Any]:
        """Adjudicates a case and verifies against WORM ledger to prevent collusion."""
        dossier = self.get_case(case_id)
        if not dossier:
            return {"success": False, "error": f"Case {case_id} not found"}

        # Perform anti-collusion audit against Agent's risk score
        audit_result = worm_ledger.audit_human_decision(
            case_id=case_id,
            agent_risk_score=dossier.final_risk_score,
            analyst_action=action,
        )

        if action in ["DISMISSED_BENIGN", "FALSE_POSITIVE"]:
            dossier.remediation_status = RemediationStatus.DISMISSED_BENIGN
        elif action in ["APPROVED_MITIGATE", "ISOLATE"]:
            dossier.remediation_status = RemediationStatus.APPROVED_MITIGATED

        return {
            "success": True,
            "case_id": case_id,
            "analyst_id": analyst_id,
            "new_status": dossier.remediation_status.value,
            "audit_check": audit_result,
            "notes": notes,
        }


case_manager = CaseManager()
