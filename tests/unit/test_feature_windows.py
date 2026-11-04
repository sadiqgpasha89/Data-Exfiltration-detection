"""The feature store must use real time windows and bounded memory."""

from datetime import datetime, timedelta, timezone

import pytest
from src.core.config import settings
from src.core.models import TelemetryEvent
from src.data_engineering.feature_store import StreamingFeatureStore

T0 = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)


def ev(i, minutes, dest="10.240.10.50", user="usr_retail_5512", **kw):
    base = dict(event_id=f"w{i}", timestamp=(T0 + timedelta(minutes=minutes)).isoformat(), source_ip="10.240.35.12",
                destination_ip=dest, destination_port=443, user_id=user, bytes_in=100, bytes_out=100)
    base.update(kw)
    return TelemetryEvent(**base)


def test_connection_count_uses_a_15_minute_window():
    fs = StreamingFeatureStore()
    counts = [fs.extract_features(ev(i, m)).connection_frequency_15m for i, m in enumerate([0, 5, 10, 14, 16, 40])]
    assert counts == [1, 2, 3, 4, 4, 1]  # at minute 16 the minute-0 event has left the window; at 40 only itself remains


def test_destination_cardinality_uses_a_one_hour_window():
    fs = StreamingFeatureStore()
    for i, (m, dest) in enumerate([(0, "1.1.1.1"), (10, "2.2.2.2"), (20, "3.3.3.3")]):
        fs.extract_features(ev(i, m, dest=dest))
    assert fs.extract_features(ev(9, 30, dest="1.1.1.1")).destination_cardinality_1h == 3
    assert fs.extract_features(ev(10, 200, dest="4.4.4.4")).destination_cardinality_1h == 1  # three hours later


def test_events_days_apart_do_not_count_as_one_burst():
    fs = StreamingFeatureStore()
    last = None
    for i in range(4):
        last = fs.extract_features(ev(i, i * 3 * 24 * 60, dest=f"198.51.100.{i}"))
    assert last.connection_frequency_15m == 1 and last.destination_cardinality_1h == 1


def test_history_is_trimmed_to_24_hours_and_per_user_capped(monkeypatch):
    monkeypatch.setattr(settings, "FEATURE_MAX_EVENTS_PER_USER", 5)
    fs = StreamingFeatureStore()
    for i in range(20):
        fs.extract_features(ev(i, i))
    assert len(fs.user_windows["usr_retail_5512"]) == 5
    fs2 = StreamingFeatureStore()
    fs2.extract_features(ev(0, 0))
    fs2.extract_features(ev(1, 26 * 60))
    assert len(fs2.user_windows["usr_retail_5512"]) == 1  # the 26-hour-old event was dropped


def test_user_and_cache_memory_are_bounded(monkeypatch):
    monkeypatch.setattr(settings, "FEATURE_MAX_USERS", 3)
    monkeypatch.setattr(settings, "FEATURE_CACHE_SIZE", 4)
    fs = StreamingFeatureStore()
    for i in range(10):
        fs.extract_features(ev(i, i, user=f"user{i}"))
    assert list(fs.user_windows) == ["user7", "user8", "user9"]  # least recently used users are evicted
    assert len(fs.cumulative_drip_counters) <= 3 + 1
    assert len(fs.feature_cache) == 4 and fs.get_feature_vector("w9") is not None and fs.get_feature_vector("w0") is None


def test_off_hours_handles_zones_weekends_and_garbage():
    fs = StreamingFeatureStore()
    assert fs.is_off_hours_access("2026-09-14T07:59:59Z") and not fs.is_off_hours_access("2026-09-14T08:00:00Z")
    assert not fs.is_off_hours_access("2026-09-14T18:59:59Z") and fs.is_off_hours_access("2026-09-14T19:00:00Z")
    assert fs.is_off_hours_access("2026-09-12T12:00:00Z")                  # Saturday
    assert not fs.is_off_hours_access("2026-09-14T14:00:00+00:00")
    assert fs.is_off_hours_access("2026-09-14T04:00:00-08:00") is False    # 12:00 UTC: the offset is honoured
    assert fs.is_off_hours_access("2026-09-14T14:00:00") is False          # a timestamp with no zone is read as UTC
    assert fs.is_off_hours_access("not a date") is True                    # unparseable: fail suspicious, not silent


def test_privileged_hop_comes_from_entitlements_not_from_a_user_list():
    fs = StreamingFeatureStore()
    # a quant with no grant on cardholder data, in business hours
    assert fs.extract_features(ev(1, 0, user="usr_dev_4091", query="SELECT * FROM cardholder_records LIMIT 5")).privileged_role_hop is True
    # the DBA who holds the grant
    assert fs.extract_features(ev(2, 1, user="usr_dba_1022", query="SELECT * FROM cardholder_records LIMIT 5")).privileged_role_hop is False
    # a user who is not the one the old code special-cased, with no grant: still flagged
    assert fs.extract_features(ev(3, 2, user="usr_retail_5512", query="SELECT * FROM core_ledger")).privileged_role_hop is True
    # a table that exists in no directory entry is still protected when configured as sensitive
    assert fs.extract_features(ev(4, 3, user="usr_dba_1022", query="select ssn from hnw_clients")).privileged_role_hop is True
    # a fragment of a table name is not a table
    assert fs.extract_features(ev(5, 4, user="usr_retail_5512", query="SELECT 1 FROM my_core_ledger_view")).privileged_role_hop is False
    # staging tools off hours
    assert fs.extract_features(ev(6, 14 * 60, process_name="7z.exe")).privileged_role_hop is True
    assert fs.extract_features(ev(7, 60, process_name="7z.exe")).privileged_role_hop is False


def test_drip_counters_shift_with_exports():
    fs = StreamingFeatureStore()
    first = fs.extract_features(ev(1, 0, event_type="database_query", record_count=200))
    assert first.rolling_read_to_export_ratio_180d > 10
    for i in range(2, 8):
        last = fs.extract_features(ev(i, i, event_type="batch_export", record_count=500))
    assert last.rolling_read_to_export_ratio_180d < 1.0


def test_concurrent_extraction_is_safe():
    import threading
    fs = StreamingFeatureStore()
    errors = []

    def work(n):
        try:
            for i in range(200):
                fs.extract_features(ev(n * 1000 + i, i % 50, user=f"user{n}"))
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
