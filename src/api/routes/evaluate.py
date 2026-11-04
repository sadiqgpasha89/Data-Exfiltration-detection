"""Full Tri-Layered Evaluation Endpoint."""

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException

from src.api.pipeline_service import run_full_pipeline
from src.core.models import TelemetryEvent
from src.core.security import Principal, require
from src.core.telemetry import logger
from src.data_engineering.ingestion import ingestion_service

router = APIRouter(prefix="/evaluate", tags=["Evaluation"])


@router.post("/process", response_model=Dict[str, Any])
def evaluate_event_full_pipeline(event: TelemetryEvent, principal: Principal = Depends(require("ingest"))):
    """Executes the full Tri-Layered detection pipeline: Layer 1 (rules) -> Layer 2 (ML anomaly) -> Layer 3 (agent swarm).

    The body is validated as a `TelemetryEvent` (bad ports, negative sizes, malformed addresses are rejected with 422).
    When the platform is saturated the endpoint sheds load with 503 and a Retry-After instead of queueing.
    """
    if not ingestion_service.acquire_slot():
        raise HTTPException(status_code=503, detail="Platform is saturated; retry shortly", headers={"Retry-After": "2"})
    try:
        return run_full_pipeline(event.model_dump())
    except Exception:
        logger.exception("evaluate_failed", event_id=event.event_id, actor=principal.name)
        raise HTTPException(status_code=500, detail="Evaluation failed; see server logs")
    finally:
        ingestion_service.release_slot()
