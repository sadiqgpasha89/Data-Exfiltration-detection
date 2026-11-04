"""Master Data Engineering Pipeline Coordinator.

Orchestrates:
Raw Telemetry Ingestion -> OpenStack Edge Tokenization -> GCP Streaming Feature Extraction -> Lakehouse Sink.
"""

from typing import Dict, Tuple
from src.core.models import FeatureVector, TelemetryEvent, TokenizedTelemetryEvent
from src.core.telemetry import TelemetryTimer, logger
from src.data_engineering.feature_store import feature_store
from src.data_engineering.ingestion import ingestion_service
from src.data_engineering.lakehouse_sink import lakehouse_sink
from src.data_engineering.tokenizer import edge_tokenizer
from src.core.baseline import feature_array
from src.mlops.drift_detector import drift_detector


class DataEngineeringPipeline:
    """Coordinates edge-to-cloud data movement and feature enrichment."""

    def __init__(self):
        self.ingestion = ingestion_service
        self.tokenizer = edge_tokenizer
        self.feature_store = feature_store
        self.lakehouse = lakehouse_sink

    def process_raw_event(self, raw_event_dict: Dict) -> Tuple[TelemetryEvent, TokenizedTelemetryEvent, FeatureVector]:
        """Executes the full data engineering transformation pipeline."""
        with TelemetryTimer("data_pipeline_execution") as timer:
            # 1. Ingestion & OCSF Normalization
            event = self.ingestion.ingest_event(raw_event_dict)

            # 2. OpenStack Edge Tokenization & Anonymization
            tokenized = self.tokenizer.process_event(event)

            # 3. GCP Sliding-Window Feature Extraction
            features = self.feature_store.extract_features(event)

            # 4. Feed the live window that drift monitoring compares against the benign baseline
            drift_detector.record_feature_vector(feature_array(features))

            # 5. Asynchronous Lakehouse write
            self.lakehouse.write_event(event)

        logger.debug(
            "data_pipeline_processed_event",
            event_id=event.event_id,
            elapsed_ms=round(timer.elapsed_ms, 3),
            savings_pct=tokenized.transit_savings_pct,
        )
        return event, tokenized, features


# Global pipeline instance
data_pipeline = DataEngineeringPipeline()
