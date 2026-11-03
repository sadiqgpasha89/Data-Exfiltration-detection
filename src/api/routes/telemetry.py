"""Telemetry streaming and ingestion API endpoints."""

from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException
from src.core.models import TelemetryEvent
from src.data_engineering.ingestion import ingestion_service
from src.data_engineering.pipeline import data_pipeline

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.post("/ingest", response_model=Dict[str, Any])
def ingest_event(event_data: Dict[str, Any]):
    """Ingests a single raw event into OpenStack edge bus."""
    try:
        event, tokenized, features = data_pipeline.process_raw_event(event_data)
        return {
            "status": "INGESTED",
            "event_id": event.event_id,
            "tokenized_event": tokenized.model_dump(),
            "extracted_features": features.model_dump(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/inject-seed", response_model=Dict[str, Any])
def inject_seed_telemetry():
    """Loads and processes all seed events from data directory."""
    events = ingestion_service.load_seed_telemetry()
    return {
        "status": "SUCCESS",
        "count_loaded": len(events),
        "events": [e.model_dump() for e in events],
    }


@router.get("/recent", response_model=List[Dict[str, Any]])
def get_recent_telemetry(limit: int = 25):
    """Fetches recent events in the ingestion buffer."""
    return [e.model_dump() for e in ingestion_service.get_recent_events(limit=limit)]
