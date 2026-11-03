"""Unit tests for Streaming Feature Store."""

import pytest
from src.core.models import TelemetryEvent
from src.data_engineering.feature_store import feature_store


def test_shannon_entropy_calculation():
    # Repetitive low-entropy string
    low_entropy = feature_store.calculate_shannon_entropy("AAAAAAAAAA")
    # High-entropy random hex / encrypted string
    high_entropy = feature_store.calculate_shannon_entropy("7f3a9b2c8d1e4f6a0b5c7d8e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a")

    assert low_entropy == 0.0
    assert high_entropy > 3.5


def test_off_hours_detection():
    # 02:00 UTC is off-hours
    assert feature_store.is_off_hours_access("2026-09-14T02:00:00Z") is True
    # 14:00 UTC on a Monday (2026-09-14 is Monday) is business hours
    assert feature_store.is_off_hours_access("2026-09-14T14:00:00Z") is False


def test_feature_store_extraction_and_drip_tracking(benign_event):
    fv1 = feature_store.extract_features(benign_event)
    assert fv1.user_id == "usr_retail_5512"
    assert fv1.destination_cardinality_1h >= 1
    assert fv1.bytes_out_in_ratio == 5.0

    # Simulate drip query accumulation
    drip_event = TelemetryEvent(
        event_id="evt-drip-seq-1",
        timestamp="2026-09-14T12:00:00Z",
        event_type="file_egress",
        source_ip="10.240.12.84",
        destination_ip="203.0.113.5",
        destination_port=443,
        user_id="usr_dev_4091",
        bytes_in=100,
        bytes_out=5000,
        record_count=50,
    )
    fv_drip = feature_store.extract_features(drip_event)
    assert fv_drip.user_id == "usr_dev_4091"
    assert fv_drip.rolling_read_to_export_ratio_180d < 20.0
