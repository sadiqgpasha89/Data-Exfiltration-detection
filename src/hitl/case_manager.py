"""HITL Case Management and Incident Adjudication."""

import threading
from typing import Any, Dict, List, Optional
from src.core.crypto_audit import worm_ledger
from src.core.models import IncidentDossier, RemediationStatus

CLOSING_ACTIONS = {
    "DISMISSED_BENIGN": RemediationStatus.DISMISSED_BENIGN,
    "FALSE_POSITIVE": RemediationStatus.DISMISSED_BENIGN,
    "APPROVED_MITIGATE": RemediationStatus.APPROVED_MITIGATED,
    "ISOLATE": RemediationStatus.APPROVED_MITIGATED,
}
OPEN_STATUSES = {  # anything not yet closed by a human, including auto-mitigated cases that still need review
    RemediationStatus.HITL_PENDING,
    RemediationStatus.CONTAINMENT_RECOMMENDED,
    RemediationStatus.PENDING_EVALUATION,
    RemediationStatus.AUTO_MITIGATED,
}
MAX_CASES = 50_000


class CaseManager:
    """Manages the SOC incident queue and records every closure in the audit ledger."""

    def __init__(self):
        self.cases: Dict[str, IncidentDossier] = {}
        self._lock = threading.RLock()
        self.flagged_overrides: List[Dict[str, Any]] = []

    def add_dossier(self, dossier: IncidentDossier):
        with self._lock:
            self.cases[dossier.case_id] = dossier
            while len(self.cases) > MAX_CASES:  # oldest first; closed cases are in the ledger and the lakehouse
                self.cases.pop(next(iter(self.cases)))

    def get_case(self, case_id: str) -> Optional[IncidentDossier]:
        with self._lock:
            return self.cases.get(case_id)

    def list_cases(self, status: Optional[str] = None) -> List[IncidentDossier]:
        with self._lock:
            all_cases = list(self.cases.values())
        if status:
            return [c for c in all_cases if c.remediation_status == status]
        return sorted(all_cases, key=lambda x: x.timestamp, reverse=True)

    def adjudicate_case(self, case_id: str, analyst_id: str, action: str, notes: str) -> Dict[str, Any]:
        """Closes a case. The action must be a known one, a case can be closed once, and the closure is checked against the agent's verdict."""
        if action not in CLOSING_ACTIONS:
            return {"success": False, "error": f"Unknown action '{action}'. Use one of: {', '.join(sorted(CLOSING_ACTIONS))}"}
        with self._lock:
            dossier = self.cases.get(case_id)
            if not dossier:
                return {"success": False, "error": f"Case {case_id} not found"}
            if dossier.remediation_status not in OPEN_STATUSES:
                return {"success": False, "error": f"Case {case_id} is already closed ({dossier.remediation_status.value})"}

            audit_result = worm_ledger.audit_human_decision(
                case_id=case_id,
                agent_risk_score=dossier.final_risk_score,
                analyst_action=action,
                analyst_id=analyst_id,
            )
            dossier.remediation_status = CLOSING_ACTIONS[action]
            if audit_result["is_suspicious_override"]:
                self.flagged_overrides.append(audit_result)

        return {
            "success": True,
            "case_id": case_id,
            "analyst_id": analyst_id,
            "new_status": dossier.remediation_status.value,
            "audit_check": audit_result,
            "notes": notes,
        }


case_manager = CaseManager()
