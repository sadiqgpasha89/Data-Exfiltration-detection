"""Incident management and case adjudication API endpoints."""

from typing import Any, Dict, List, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.core.crypto_audit import worm_ledger
from src.core.security import Principal, require
from src.hitl.case_manager import case_manager

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class AdjudicationRequest(BaseModel):
    action: Literal["DISMISSED_BENIGN", "FALSE_POSITIVE", "APPROVED_MITIGATE", "ISOLATE"]
    notes: str = Field(default="", max_length=2000)


@router.get("", response_model=List[Dict[str, Any]])
def list_incidents(status: Optional[str] = None, principal: Principal = Depends(require("read"))):
    """Lists incident dossiers, newest first."""
    return [d.model_dump() for d in case_manager.list_cases(status=status)]


@router.get("/worm/verify", response_model=Dict[str, Any])
def verify_worm_audit_chain(principal: Principal = Depends(require("read"))):
    """Verifies the append-only hash chain. A broken chain is reported as data (chain_valid false), not as a server error."""
    result = worm_ledger.verify_chain()
    return {
        "chain_valid": result["valid"],
        "checked_blocks": result["checked"],
        "first_bad_index": result["first_bad_index"],
        "error": result["error"],
        "total_blocks": len(worm_ledger.chain),
        "latest_block_hash": worm_ledger.get_latest_hash(),
        "durable": bool(worm_ledger.path),
        "ledger_blocks": worm_ledger.get_ledger_blocks()[-10:],
    }


@router.get("/overrides/flagged", response_model=List[Dict[str, Any]])
def list_flagged_overrides(principal: Principal = Depends(require("admin"))):
    """Analyst closures that contradicted a high-risk verdict and were escalated by the anti-collusion audit."""
    return list(case_manager.flagged_overrides)


@router.get("/{case_id}", response_model=Dict[str, Any])
def get_incident(case_id: str, principal: Principal = Depends(require("read"))):
    """Retrieves one incident dossier with the agents' deliberation log."""
    dossier = case_manager.get_case(case_id)
    if not dossier:
        raise HTTPException(status_code=404, detail=f"Incident {case_id} not found")
    return dossier.model_dump()


@router.post("/{case_id}/adjudicate", response_model=Dict[str, Any])
def adjudicate_incident(case_id: str, request: AdjudicationRequest, principal: Principal = Depends(require("adjudicate"))):
    """Closes a case. The analyst recorded in the audit ledger is the authenticated caller, never a name taken from the request body."""
    result = case_manager.adjudicate_case(case_id=case_id, analyst_id=principal.name, action=request.action, notes=request.notes)
    if not result.get("success"):
        status = 404 if "not found" in result.get("error", "") else 409 if "already closed" in result.get("error", "") else 400
        raise HTTPException(status_code=status, detail=result.get("error"))
    return result
