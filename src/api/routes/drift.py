"""MLOps & LLMOps Drift Governance API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter, Depends

from src.core.security import Principal, require
from src.llmops.prompt_manager import prompt_manager
from src.mlops.drift_detector import drift_detector
from src.mlops.registry import model_registry
from src.mlops.retraining_trigger import retraining_controller

router = APIRouter(prefix="/drift", tags=["Governance & Drift"])


@router.get("/report", response_model=Dict[str, Any])
def get_drift_report(principal: Principal = Depends(require("read"))):
    """Drift between the benign baseline and the live feature stream, the deployed models and their measured quality."""
    return {
        "drift_metrics": drift_detector.evaluate_feature_drift(),
        "production_models": [m.model_dump() for m in model_registry.get_production_models()],
        "prompt_templates": [p.model_dump() for p in prompt_manager.get_all_prompts()],
        "retraining_history": retraining_controller.get_history(),
    }


@router.post("/trigger-retrain", response_model=Dict[str, Any])
def trigger_retraining_job(principal: Principal = Depends(require("admin"))):
    """Requests retraining (administrators only). Dispatched when a backend is registered, otherwise recorded as requested."""
    return retraining_controller.check_and_trigger(force=True, requested_by=principal.name)
