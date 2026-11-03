"""MLOps & LLMOps Drift Governance API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter
from src.llmops.prompt_manager import prompt_manager
from src.mlops.drift_detector import drift_detector
from src.mlops.registry import model_registry
from src.mlops.retraining_trigger import retraining_controller

router = APIRouter(prefix="/drift", tags=["Governance & Drift"])


@router.get("/report", response_model=Dict[str, Any])
def get_drift_report():
    """Returns PSI score, Wasserstein distance, KS concept drift, and model statuses."""
    drift_info = drift_detector.evaluate_feature_drift()
    models = [m.model_dump() for m in model_registry.get_production_models()]
    prompts = [p.model_dump() for p in prompt_manager.get_all_prompts()]

    return {
        "drift_metrics": drift_info,
        "production_models": models,
        "prompt_templates": prompts,
        "retraining_history": retraining_controller.get_history(),
    }


@router.post("/trigger-retrain", response_model=Dict[str, Any])
def trigger_retraining_job():
    """Manually or policy-driven dispatch of Vertex AI retraining."""
    return retraining_controller.check_and_trigger(force=True)
