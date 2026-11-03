"""Analytical Lakehouse Sink (BigQuery & Cloud Storage WORM).

Stores processed events, normalized feature vectors, and incident outcomes
for continuous auditability and model retraining pipelines.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
from src.core.config import settings
from src.core.models import IncidentDossier, TelemetryEvent


class LakehouseSink:
    """Manages hot BigQuery tables and cold GCS parquet archives."""

    def __init__(self):
        self.bigquery_events: List[Dict[str, Any]] = []
        self.bigquery_incidents: List[Dict[str, Any]] = []
        self.gcs_cold_archive_count = 0

    def write_event(self, event: TelemetryEvent):
        """Simulates streaming insert into BigQuery."""
        record = event.model_dump()
        record["_bq_ingest_time"] = datetime.now(timezone.utc).isoformat()
        self.bigquery_events.append(record)

    def write_incident_dossier(self, dossier: IncidentDossier):
        """Writes incident dossier into immutable BigQuery security table."""
        record = dossier.model_dump()
        record["_bq_ingest_time"] = datetime.now(timezone.utc).isoformat()
        self.bigquery_incidents.append(record)
        self.gcs_cold_archive_count += 1

    def query_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.bigquery_events[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "bigquery_total_events": len(self.bigquery_events),
            "bigquery_total_incidents": len(self.bigquery_incidents),
            "gcs_cold_archives": self.gcs_cold_archive_count,
            "lakehouse_dataset": settings.BIGQUERY_DATASET,
        }


# Global lakehouse sink
lakehouse_sink = LakehouseSink()
