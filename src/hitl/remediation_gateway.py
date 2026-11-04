"""Remediation Gateway for 1-Click SOC Cockpit Adjudication."""

from typing import Any, Dict
from src.agents.tools.remediation_tool import remediation_tool
from src.core.models import RemediationStatus
from src.hitl.case_manager import OPEN_STATUSES, case_manager


class RemediationGateway:
    """Interfaces between human analysts in the SOC cockpit and enforcement APIs."""

    def __init__(self):
        self.tool = remediation_tool
        self.case_mgr = case_manager

    def execute_one_click_isolation(self, case_id: str, analyst_id: str, role: str = "analyst") -> Dict[str, Any]:
        """Executes the containment playbook an analyst approved for a case.

        The target is the case's own subject (host and user recorded when the incident was raised). Protected identities
        and addresses need an admin. Containment always runs for real here: this is a person's decision, not automation,
        so the automatic-remediation mode (dry run by default) does not apply.
        """
        dossier = self.case_mgr.get_case(case_id)
        if dossier is None:
            raise LookupError(f"Case {case_id} not found")
        if dossier.remediation_status not in OPEN_STATUSES:
            raise ValueError(f"Case {case_id} is already closed ({dossier.remediation_status.value})")
        if not dossier.subject_ip or not dossier.subject_user_id:
            raise ValueError(f"Case {case_id} has no host or user to contain")

        protected = self.tool.guard.protected_reason(dossier.subject_ip, dossier.subject_user_id)
        if protected and role != "admin":
            raise PermissionError(f"Containing a protected target requires an administrator: {protected}")

        actions = self.tool.execute_containment_playbook(ip_address=dossier.subject_ip, user_id=dossier.subject_user_id, case_id=case_id)
        effective = all(a.get("status") == "APPLIED" for a in actions)
        closure = self.case_mgr.adjudicate_case(
            case_id=case_id,
            analyst_id=analyst_id,
            action="APPROVED_MITIGATE",
            notes="1-Click containment via SOC Cockpit" + ("" if effective else " (not verifiably applied: see action statuses)"),
        )
        return {
            "success": closure["success"],
            "case_id": case_id,
            "analyst_id": analyst_id,
            "target": {"ip": dossier.subject_ip, "user_id": dossier.subject_user_id},
            "effective": effective,
            "executed_actions": actions,
        }


remediation_gateway = RemediationGateway()
