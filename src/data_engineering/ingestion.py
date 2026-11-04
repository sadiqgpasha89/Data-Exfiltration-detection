"""Telemetry Ingestion and OCSF Normalization Service.

Normalizes raw events into the validated `TelemetryEvent` model and tracks the true ingestion rate (events in the last
minute) and real backpressure: the number of pipeline runs in flight against a fixed concurrency limit. When the limit is
reached `acquire_slot()` refuses and the API sheds load with `503 Retry-After` instead of queueing without bound.
"""

import collections
import json
import threading
import time
from typing import Dict, List
from src.core.config import settings
from src.core.models import TelemetryEvent

EPS_WINDOW_SECONDS = 60.0


class TelemetryIngestionService:
    """Manages the recent-event ring, ingestion rate and backpressure."""

    def __init__(self, max_in_flight: int = None):
        self.max_in_flight = max_in_flight or settings.MAX_CONCURRENT_EVALUATIONS
        self._slots = threading.BoundedSemaphore(self.max_in_flight)
        self._lock = threading.Lock()
        self._in_flight = 0
        self._arrivals: collections.deque = collections.deque()
        self._started = time.monotonic()
        self.total_events_ingested = 0
        self.event_history: collections.deque = collections.deque(maxlen=500)

    def ingest_event(self, event_data: Dict) -> TelemetryEvent:
        """Validates and normalizes a raw dictionary into an OCSF TelemetryEvent (raises pydantic.ValidationError on bad input)."""
        event = TelemetryEvent(**event_data)
        now = time.monotonic()
        with self._lock:
            self.event_history.append(event)
            self.total_events_ingested += 1
            self._arrivals.append(now)
            while self._arrivals and now - self._arrivals[0] > EPS_WINDOW_SECONDS:
                self._arrivals.popleft()
        return event

    def ingest_batch(self, batch_data: List[Dict]) -> List[TelemetryEvent]:
        return [self.ingest_event(evt) for evt in batch_data]

    # ---- backpressure ---------------------------------------------------------------------------------------
    def acquire_slot(self) -> bool:
        """Takes a pipeline slot without waiting. False means the platform is saturated and the caller should shed load."""
        if not self._slots.acquire(blocking=False):
            return False
        with self._lock:
            self._in_flight += 1
        return True

    def release_slot(self) -> None:
        with self._lock:
            self._in_flight -= 1
        self._slots.release()

    def get_backpressure_ratio(self) -> float:
        """Share of pipeline slots in use (0.0 idle, 1.0 saturated)."""
        with self._lock:
            return round(self._in_flight / self.max_in_flight, 4)

    def get_current_eps(self) -> float:
        """Events per second over the last minute (or since start, if the process is younger than that)."""
        now = time.monotonic()
        with self._lock:
            while self._arrivals and now - self._arrivals[0] > EPS_WINDOW_SECONDS:
                self._arrivals.popleft()
            window = min(EPS_WINDOW_SECONDS, max(1.0, now - self._started))
            return round(len(self._arrivals) / window, 2)

    def load_seed_telemetry(self) -> List[TelemetryEvent]:
        """Loads seed events from the data directory (development and demos only)."""
        path = settings.SEED_TELEMETRY_PATH
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return self.ingest_batch(json.load(f))
        return []

    def get_recent_events(self, limit: int = 50) -> List[TelemetryEvent]:
        with self._lock:
            return list(self.event_history)[-max(1, min(limit, 500)):]


# Global ingestion service
ingestion_service = TelemetryIngestionService()
