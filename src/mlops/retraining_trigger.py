"""Retraining Controller.

Drift raises a request to retrain; it does not retrain by itself. Models that learn from live traffic can be poisoned by
the traffic they are meant to catch, so refitting is a reviewed, admin-initiated job that runs on data a person has
approved as benign. This controller records the request and, when a backend (for example a Vertex AI Pipelines client)
is registered, hands the job to it. Without a backend the request is recorded and the status says so plainly.
"""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from src.core.telemetry import logger
from src.mlops.drift_detector import drift_detector

TARGET_MODELS = ["mdl-iso-forest-v1", "mdl-pca-autoencoder-v1"]


class RetrainingBackend(Protocol):
    def submit(self, job: Dict[str, Any]) -> Dict[str, Any]: ...


class AutomatedRetrainingController:
    """Records retraining requests and dispatches them to a registered backend."""

    def __init__(self, backend: Optional[RetrainingBackend] = None):
        self.backend = backend
        self.retraining_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def register_backend(self, backend: RetrainingBackend) -> None:
        self.backend = backend

    def check_and_trigger(self, force: bool = False, requested_by: str = "system") -> Dict[str, Any]:
        drift_report = drift_detector.evaluate_feature_drift()
        should_trigger = force or bool(drift_report.get("alert_triggered"))

        job_info: Dict[str, Any] = {
            "triggered": should_trigger,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requested_by": requested_by,
            "forced": force,
            "target_models": TARGET_MODELS,
            "drift_metrics": drift_report,
            "status": "IDLE",
        }
        if should_trigger:
            if self.backend is None:
                job_info["status"] = "REQUESTED_NO_BACKEND_CONFIGURED"
            else:
                try:
                    job_info["backend_result"] = self.backend.submit(job_info)
                    job_info["status"] = "DISPATCHED"
                except Exception as exc:
                    job_info["status"] = "DISPATCH_FAILED"
                    job_info["error"] = type(exc).__name__
            with self._lock:
                self.retraining_history.append(job_info)
                del self.retraining_history[:-200]
            logger.info("retraining_requested", status=job_info["status"], requested_by=requested_by, forced=force)
        return job_info

    def get_history(self) -> list:
        with self._lock:
            return list(self.retraining_history)


retraining_controller = AutomatedRetrainingController()
