"""Telemetry streaming and ingestion API endpoints."""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query

from src.core.config import settings
from src.core.models import TelemetryEvent
from src.core.security import Principal, require
from src.core.telemetry import logger
from src.data_engineering.ingestion import ingestion_service
from src.data_engineering.pipeline import data_pipeline

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.post("/ingest", response_model=Dict[str, Any])
def ingest_event(event: TelemetryEvent, principal: Principal = Depends(require("ingest"))):
    """Ingests a single event: validation, edge tokenization and feature extraction. No detection is run (use /evaluate/process)."""
    if not ingestion_service.acquire_slot():
        raise HTTPException(status_code=503, detail="Platform is saturated; retry shortly", headers={"Retry-After": "2"})
    try:
        event_obj, tokenized, features = data_pipeline.process_raw_event(event.model_dump())
        return {
            "status": "INGESTED",
            "event_id": event_obj.event_id,
            "tokenized_event": tokenized.model_dump(),
            "extracted_features": features.model_dump(),
        }
    except Exception:
        logger.exception("ingest_failed", event_id=event.event_id, actor=principal.name)
        raise HTTPException(status_code=500, detail="Ingestion failed; see server logs")
    finally:
        ingestion_service.release_slot()


@router.post("/inject-seed", response_model=Dict[str, Any])
def inject_seed_telemetry(principal: Principal = Depends(require("simulate"))):
    """Loads the demo seed events (development and demos only)."""
    if not settings.simulator_enabled:
        raise HTTPException(status_code=404, detail="Not found")
    events = ingestion_service.load_seed_telemetry()
    return {"status": "SUCCESS", "count_loaded": len(events), "events": [e.model_dump(exclude={"raw_payload"}) for e in events]}


@router.get("/recent", response_model=List[Dict[str, Any]])
def get_recent_telemetry(limit: int = Query(25, ge=1, le=500), principal: Principal = Depends(require("read"))):
    """Fetches recent events in the ingestion ring (raw payloads are never returned)."""
    return [e.model_dump(exclude={"raw_payload"}) for e in ingestion_service.get_recent_events(limit=limit)]
