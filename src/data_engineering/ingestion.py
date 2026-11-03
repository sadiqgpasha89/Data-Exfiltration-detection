"""Telemetry Ingestion and OCSF Normalization Pipeline.

Simulates OpenStack Kafka / Fluentbit wire-speed telemetry bus with backpressure
and queue monitoring.
"""

import collections
import json
import time
from typing import Dict, List, Optional
from src.core.config import settings
from src.core.models import TelemetryEvent
from src.core.telemetry import logger


class TelemetryIngestionService:
    """Manages telemetry stream buffers, EPS tracking, and backpressure."""

    def __init__(self, max_buffer_size: int = 10000):
        self.buffer: collections.deque = collections.deque(maxlen=max_buffer_size)
        self.max_buffer_size = max_buffer_size
        self.total_events_ingested = 0
        self.start_time = time.time()
        self.event_history: collections.deque = collections.deque(maxlen=500)

    def ingest_event(self, event_data: Dict) -> TelemetryEvent:
        """Ingests a raw dictionary, normalizes into OCSF TelemetryEvent."""
        event = TelemetryEvent(**event_data)
        self.buffer.append(event)
        self.event_history.append(event)
        self.total_events_ingested += 1
        return event

    def ingest_batch(self, batch_data: List[Dict]) -> List[TelemetryEvent]:
        return [self.ingest_event(evt) for evt in batch_data]

    def get_backpressure_ratio(self) -> float:
        """Returns buffer fill ratio (0.0 to 1.0). High ratio indicates backpressure."""
        return round(len(self.buffer) / self.max_buffer_size, 4)

    def get_current_eps(self) -> float:
        """Computes sustained Events Per Second (EPS)."""
        elapsed = max(1.0, time.time() - self.start_time)
        return round(self.total_events_ingested / elapsed, 2)

    def load_seed_telemetry(self) -> List[TelemetryEvent]:
        """Loads seed events from data directory."""
        path = settings.SEED_TELEMETRY_PATH
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return self.ingest_batch(data)
        return []

    def get_recent_events(self, limit: int = 50) -> List[TelemetryEvent]:
        """Returns the most recent events."""
        return list(self.event_history)[-limit:]


# Global ingestion service
ingestion_service = TelemetryIngestionService()
