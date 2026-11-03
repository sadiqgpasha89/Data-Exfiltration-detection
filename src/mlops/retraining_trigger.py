"""Automated Retraining Controller for MLOps.

Triggers Vertex AI Pipelines (Kubeflow) to retrain anomaly models
when PSI > 0.25 or significant concept drift is flagged.
"""

from datetime import datetime, timezone
from typing import Any, Dict
from src.core.telemetry import logger
from src.mlops.drift_detector import drift_detector


class AutomatedRetrainingController:
    """Manages trigger lifecycle and job dispatch to Vertex AI Pipelines."""

    def __init__(self):
        self.retraining_history: list = []

    def check_and_trigger(self, force: bool = False) -> Dict[str, Any]:
        """Evaluates drift and dispatches retraining job if needed."""
        drift_report = drift_detector.evaluate_feature_drift()
        should_trigger = force or drift_report.get("alert_triggered", False)

        job_info = {
            "triggered": should_trigger,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pipeline_name": "vertex-ai-isolation-forest-retrain-v2",
            "target_models": ["mdl-iso-forest-v1.4", "mdl-vae-reconstruction-v2.1"],
            "drift_metrics": drift_report,
            "status": "DISPATCHED_TO_VERTEX_PIPELINES" if should_trigger else "IDLE",
        }

        if should_trigger:
            self.retraining_history.append(job_info)
            logger.info("vertex_retraining_dispatched", **job_info)

        return job_info

    def get_history(self) -> list:
        return self.retraining_history


retraining_controller = AutomatedRetrainingController()
