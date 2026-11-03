"""Remediation and containment API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter, HTTPException
from src.hitl.remediation_gateway import remediation_gateway

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.post("/execute-playbook", response_model=Dict[str, Any])
def execute_containment(payload: Dict[str, Any]):
    """Executes 1-click containment action from SOC cockpit."""
    case_id = payload.get("case_id")
    analyst_id = payload.get("analyst_id", "tier2_analyst")
    ip_address = payload.get("ip_address")
    user_id = payload.get("user_id", "anonymous")

    if not ip_address:
        raise HTTPException(status_code=400, detail="ip_address is required for containment")

    result = remediation_gateway.execute_one_click_isolation(
        case_id=case_id or "ADHOC-CASE",
        analyst_id=analyst_id,
        ip_address=ip_address,
        user_id=user_id,
    )
    return result
