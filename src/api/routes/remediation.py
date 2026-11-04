"""Remediation and containment API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.core.security import Principal, require
from src.hitl.remediation_gateway import remediation_gateway

router = APIRouter(prefix="/remediation", tags=["Remediation"])


class ContainmentRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=160)


@router.post("/execute-playbook", response_model=Dict[str, Any])
def execute_containment(request: ContainmentRequest, principal: Principal = Depends(require("contain"))):
    """Analyst-approved containment of a case's subject. The host and user come from the case itself, so a caller cannot
    point this endpoint at an arbitrary address or account."""
    try:
        return remediation_gateway.execute_one_click_isolation(case_id=request.case_id, analyst_id=principal.name, role=principal.role)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
