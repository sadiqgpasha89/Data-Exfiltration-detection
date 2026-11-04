"""The telemetry model is the trust boundary: bad input is rejected before any detection logic sees it."""

import pytest
from pydantic import ValidationError
from src.core.models import TelemetryEvent

GOOD = dict(event_id="evt-1", source_ip="10.0.0.1", destination_ip="8.8.8.8", destination_port=443)


@pytest.mark.parametrize("override", [
    {"destination_port": 70000}, {"destination_port": -1}, {"bytes_out": -5}, {"bytes_in": -1}, {"record_count": -1},
    {"payload_entropy": 9.5}, {"payload_entropy": -0.1}, {"source_ip": "999.1.1.1"}, {"destination_ip": "hostname"},
    {"event_id": "has space"}, {"event_id": ""}, {"event_id": "x" * 200}, {"timestamp": "yesterday"},
    {"file_hash_sha256": "abc"}, {"domain_queried": "d" * 300}, {"category": "c" * 100}, {"chi_square_randomness": -3.0},
])
def test_rejects_bad_input(override):
    with pytest.raises(ValidationError):
        TelemetryEvent(**{**GOOD, **override})


def test_accepts_good_input_including_ipv6_and_naive_timestamps():
    ev = TelemetryEvent(**{**GOOD, "source_ip": "fd00::1", "timestamp": "2026-09-14T10:00:00"})
    assert ev.destination_port == 443
    assert TelemetryEvent(**GOOD).timestamp  # default is generated
