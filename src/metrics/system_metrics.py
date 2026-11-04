"""System and Operational Performance Metrics Calculator.

Computed from latencies the pipeline recorded. With no samples the figures are None.

`hybrid_transit_cost_savings_pct` is the measured size reduction of the telemetry record after tokenization. It is not
the bandwidth saved by not forwarding raw packet payloads: that depends on traffic the edge never sees in this
deployment, and has to be measured where the edge sits.
"""

import threading
from typing import Any, Dict, List, Optional

import numpy as np

from src.core.config import settings
from src.data_engineering.ingestion import ingestion_service
from src.data_engineering.tokenizer import edge_tokenizer

MAX_SAMPLES = 20_000


def _p(samples: List[float], q: float) -> Optional[float]:
    return round(float(np.percentile(np.array(samples), q)), 3) if samples else None


class SystemMetricsCalculator:
    """Measures pipeline latency, ingestion rate and tokenization efficiency."""

    def __init__(self):
        self._lock = threading.Lock()
        self.latency_samples_ms: List[float] = []
        self.l1_latency_samples_ms: List[float] = []
        self.l2_latency_samples_ms: List[float] = []

    def record_pipeline_latency(self, total_ms: float, l1_ms: float = 0.0, l2_ms: float = 0.0):
        with self._lock:
            for samples, value in ((self.latency_samples_ms, total_ms), (self.l1_latency_samples_ms, l1_ms), (self.l2_latency_samples_ms, l2_ms)):
                if value > 0:
                    samples.append(value)
                    if len(samples) > MAX_SAMPLES:
                        del samples[: MAX_SAMPLES // 2]

    def calculate_metrics(self) -> Dict[str, Any]:
        with self._lock:
            p99 = _p(self.latency_samples_ms, 99)
            report = {
                "measured": bool(self.latency_samples_ms),
                "samples": len(self.latency_samples_ms),
                "p50_latency_ms": _p(self.latency_samples_ms, 50),
                "p90_latency_ms": _p(self.latency_samples_ms, 90),
                "p99_latency_ms": p99,
                "p99_sla_target_sec": settings.LATENCY_SLA_P99_SECONDS,
                "p99_sla_met": None if p99 is None else bool(p99 / 1000.0 <= settings.LATENCY_SLA_P99_SECONDS),
                "l1_rule_evaluation_p99_ms": _p(self.l1_latency_samples_ms, 99),
                "l2_ml_inference_p99_ms": _p(self.l2_latency_samples_ms, 99),
            }
        savings = edge_tokenizer.get_aggregate_savings()
        report.update({
            "ingestion_throughput_eps": ingestion_service.get_current_eps(),
            "hybrid_transit_cost_savings_pct": savings,
            "hybrid_transit_target_met": None if savings is None else bool(savings >= settings.HYBRID_TRANSIT_SAVINGS_TARGET * 100.0),
            "ingestion_backpressure_ratio": ingestion_service.get_backpressure_ratio(),
            "active_openstack_kafka_cluster": settings.OPENSTACK_KAFKA_BROKERS,
            "active_gcp_pubsub_topic": settings.PUBSUB_TOPIC,
        })
        return report


system_metrics = SystemMetricsCalculator()
