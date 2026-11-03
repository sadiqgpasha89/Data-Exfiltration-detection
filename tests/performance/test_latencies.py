"""Performance and latency benchmark tests."""

import time
import numpy as np
import pytest
from src.core.models import FeatureVector, TelemetryEvent
from src.datascience.tier1_rules import tier1_engine
from src.datascience.tier2_ml import tier2_scorer


def test_layer1_wire_speed_microsecond_latency(benign_event):
    """Layer 1 deterministic rules must execute in under 1 millisecond on average."""
    times_ms = []
    # Warmup
    for _ in range(10):
        tier1_engine.evaluate(benign_event)

    # Benchmark 200 iterations
    for _ in range(200):
        t0 = time.perf_counter()
        tier1_engine.evaluate(benign_event)
        times_ms.append((time.perf_counter() - t0) * 1000.0)

    avg_ms = np.mean(times_ms)
    p99_ms = np.percentile(times_ms, 99)

    # Wire-speed assertion: average under 1ms
    assert avg_ms < 1.0, f"Average Layer 1 evaluation {avg_ms:.3f}ms exceeds 1.0ms SLA"
    assert p99_ms < 5.0, f"P99 Layer 1 evaluation {p99_ms:.3f}ms exceeds 5.0ms SLA"


def test_layer2_ml_inference_latency(benign_event):
    """Layer 2 ML anomaly scoring must complete in under 50 milliseconds."""
    fv = FeatureVector(
        event_id="perf-fv",
        user_id="usr_retail_5512",
        bytes_out_in_ratio=1.0,
        connection_frequency_15m=3,
        payload_entropy=3.5,
        historical_deviation_score=0.1,
        destination_cardinality_1h=1,
        rolling_read_to_export_ratio_180d=20.0,
        is_off_hours=False,
        privileged_role_hop=False,
    )

    times_ms = []
    # Warmup
    for _ in range(5):
        tier2_scorer.evaluate(benign_event, fv)

    # Benchmark 50 iterations
    for _ in range(50):
        t0 = time.perf_counter()
        tier2_scorer.evaluate(benign_event, fv)
        times_ms.append((time.perf_counter() - t0) * 1000.0)

    avg_ms = np.mean(times_ms)
    p99_ms = np.percentile(times_ms, 99)

    assert avg_ms < 50.0, f"Average Layer 2 ML inference {avg_ms:.2f}ms exceeds 50ms SLA"
    assert p99_ms < 100.0, f"P99 Layer 2 ML inference {p99_ms:.2f}ms exceeds 100ms SLA"
