"""Analytical Lakehouse Sink (BigQuery & Cloud Storage WORM).

Stores processed events and incident outcomes for auditability and model retraining. In this build it is an in-process,
bounded stand-in for the BigQuery streaming insert; the oldest records are dropped once the cap is reached so a long
running process cannot exhaust memory.
"""

import collections
import threading
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List
from src.core.config import settings
from src.core.models import IncidentDossier, TelemetryEvent

MAX_EVENT_RECORDS = 50_000
MAX_INCIDENT_RECORDS = 10_000


class LakehouseSink:
    """Manages hot BigQuery tables and cold GCS parquet archives (simulated)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.bigquery_events: Deque[Dict[str, Any]] = collections.deque(maxlen=MAX_EVENT_RECORDS)
        self.bigquery_incidents: Deque[Dict[str, Any]] = collections.deque(maxlen=MAX_INCIDENT_RECORDS)
        self.gcs_cold_archive_count = 0

    def write_event(self, event: TelemetryEvent):
        """Streaming insert. The raw payload is not stored: it is large, and it may contain the very data being protected."""
        record = event.model_dump(exclude={"raw_payload"})
        record["_bq_ingest_time"] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.bigquery_events.append(record)

    def write_incident_dossier(self, dossier: IncidentDossier):
        record = dossier.model_dump()
        record["_bq_ingest_time"] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.bigquery_incidents.append(record)
            self.gcs_cold_archive_count += 1

    def query_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.bigquery_events)[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "bigquery_total_events": len(self.bigquery_events),
                "bigquery_total_incidents": len(self.bigquery_incidents),
                "gcs_cold_archives": self.gcs_cold_archive_count,
                "lakehouse_dataset": settings.BIGQUERY_DATASET,
            }


# Global lakehouse sink
lakehouse_sink = LakehouseSink()
