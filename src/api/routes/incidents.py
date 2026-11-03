"""Incident management and case adjudication API endpoints."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from src.core.crypto_audit import worm_ledger
from src.hitl.case_manager import case_manager

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=List[Dict[str, Any]])
def list_incidents(status: Optional[str] = None):
    """Lists all active and resolved incident dossiers."""
    dossiers = case_manager.list_cases(status=status)
    return [d.model_dump() for d in dossiers]


@router.get("/{case_id}", response_model=Dict[str, Any])
def get_incident(case_id: str):
    """Retrieves specific incident dossier with multi-agent debate logs."""
    dossier = case_manager.get_case(case_id)
    if not dossier:
        raise HTTPException(status_code=404, detail=f"Incident {case_id} not found")
    return dossier.model_dump()


@router.post("/{case_id}/adjudicate", response_model=Dict[str, Any])
def adjudicate_incident(case_id: str, payload: Dict[str, Any]):
    """Adjudicates a case and performs anti-collusion audit against WORM ledger."""
    analyst_id = payload.get("analyst_id", "sec_analyst_current")
    action = payload.get("action", "DISMISSED_BENIGN")
    notes = payload.get("notes", "")

    result = case_manager.adjudicate_case(
        case_id=case_id,
        analyst_id=analyst_id,
        action=action,
        notes=notes,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/worm/verify", response_model=Dict[str, Any])
def verify_worm_audit_chain():
    """Verifies that the append-only cryptographic WORM chain is uncorrupted."""
    is_valid = worm_ledger.verify_chain_integrity()
    return {
        "chain_valid": is_valid,
        "total_blocks": len(worm_ledger.chain),
        "latest_block_hash": worm_ledger.get_latest_hash(),
        "ledger_blocks": worm_ledger.get_ledger_blocks()[-10:],
    }
