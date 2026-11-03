"""Remediation Gateway for 1-Click SOC Cockpit Adjudication."""

from typing import Any, Dict, List
from src.agents.tools.remediation_tool import remediation_tool
from src.hitl.case_manager import case_manager


class RemediationGateway:
    """Interaces between human analysts in the SOC cockpit and enforcement APIs."""

    def __init__(self):
        self.tool = remediation_tool
        self.case_mgr = case_manager

    def execute_one_click_isolation(self, case_id: str, analyst_id: str, ip_address: str, user_id: str) -> Dict[str, Any]:
        """Executes full containment playbook requested by analyst in SOC cockpit."""
        actions = self.tool.execute_containment_playbook(ip_address=ip_address, user_id=user_id, case_id=case_id)
        # Update case status
        self.case_mgr.adjudicate_case(
            case_id=case_id,
            analyst_id=analyst_id,
            action="APPROVED_MITIGATE",
            notes="1-Click Emergency Network Quarantine and Token Invalidation via SOC Cockpit",
        )
        return {
            "success": True,
            "case_id": case_id,
            "analyst_id": analyst_id,
            "executed_actions": actions,
        }


remediation_gateway = RemediationGateway()
