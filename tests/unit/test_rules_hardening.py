"""Layer 1 regressions: each test pins a defect found in the original rules."""

import numpy as np
import pytest
from src.core.honeytokens import CanaryRegistry
from src.core.models import TelemetryEvent
from src.datascience.tier1_rules import tier1_engine
from src.datascience.tier1_rules.regex_compliance import regex_compliance
from src.datascience.tier1_rules.reputation_filter import reputation_filter
from src.datascience.tier1_rules.stego_detector import SteganographyDetector, stego_detector


def test_domain_match_is_on_whole_labels():
    assert reputation_filter.is_malicious_domain("dns-tunnel-relay.xyz")
    assert reputation_filter.is_malicious_domain("A1b2.c3.dns-tunnel-relay.xyz.")           # subdomain, trailing dot
    assert reputation_filter.is_malicious_domain("DNS-TUNNEL-RELAY.XYZ")                    # case-insensitive
    assert not reputation_filter.is_malicious_domain("not-dns-tunnel-relay.xyz")            # different registrable domain
    assert not reputation_filter.is_malicious_domain("dns-tunnel-relay.xyz.example.org")    # listed name used as a label of someone else's domain
    assert not reputation_filter.is_malicious_domain("")
    assert not reputation_filter.is_malicious_domain(None)


def test_ip_feed_supports_cidr_ipv6_and_rejects_garbage():
    import ipaddress
    reputation_filter.malicious_networks.append(ipaddress.ip_network("198.18.0.0/15"))
    reputation_filter.malicious_networks.append(ipaddress.ip_network("2001:db8:bad::/48"))
    try:
        assert reputation_filter.is_malicious_ip("198.19.4.4") and not reputation_filter.is_malicious_ip("198.20.0.1")
        assert reputation_filter.is_malicious_ip("2001:db8:bad::1") and not reputation_filter.is_malicious_ip("2001:db8:good::1")
        assert not reputation_filter.is_malicious_ip("not an ip")
        assert reputation_filter.is_prohibited_database_egress("10.240.1.1", 22)
        assert not reputation_filter.is_prohibited_database_egress("2001:db8::1", 22)  # IPv6 source outside the monitored IPv4 subnets
    finally:
        reputation_filter.malicious_networks.clear()


def test_ssn_validity_rules():
    found = regex_compliance.scan_payload("ok 123-45-6789 bad 000-12-3456 666-12-3456 900-12-3456 123-00-4567 123-45-0000")["ssns"]
    assert found == ["123-45-6789"]


def test_card_detection_ignores_timestamps_and_glued_digits():
    assert regex_compliance.scan_payload("epoch=1700000000000 ts=20260914123000")["credit_cards"] == []
    assert regex_compliance.scan_payload("id 41111111111111111111")["credit_cards"] == []  # 20 digits: not a card, not several overlapping cards
    assert regex_compliance.scan_payload("pan 4111-1111-1111-1111.")["credit_cards"] == ["4111********1111"]


def test_scan_is_bounded_for_hostile_payloads(monkeypatch):
    import time
    from src.core.config import settings
    monkeypatch.setattr(settings, "MAX_PAYLOAD_SCAN_CHARS", 50_000)
    hostile = "1 " * 400_000 + "4111111111111111"  # the only card is beyond the scan limit
    start = time.perf_counter()
    assert regex_compliance.scan_payload(hostile)["credit_cards"] == []
    assert time.perf_counter() - start < 1.0


def test_chi_square_is_read_in_the_right_direction():
    rng = np.random.default_rng(3)
    random_bytes = rng.integers(0, 256, 200_000, dtype=np.uint8).tobytes()
    text = b"The quick brown fox jumps over the lazy dog. " * 5000
    detector = SteganographyDetector()
    chi_random = detector.compute_chi_square_randomness(random_bytes)
    chi_text = detector.compute_chi_square_randomness(text)
    assert 180 < chi_random < 330 and chi_text > 100_000
    assert detector.looks_uniformly_random(chi_random) and not detector.looks_uniformly_random(chi_text)
    assert not detector.looks_uniformly_random(0.0)

    # a structured file named like an image is NOT suspicious just because its histogram is far from uniform
    assert stego_detector.evaluate_payload(raw_bytes=text, file_name="photo.png")[0] is False
    # random-looking bytes in a large image are
    assert stego_detector.evaluate_payload(raw_bytes=random_bytes, file_name="photo.png", size_bytes=8_000_000)[0] is True
    # a tiny image is not held to the media rule (it can still trip the general entropy rule)
    suspicious, *_ = SteganographyDetector(entropy_threshold=8.5).evaluate_payload(raw_bytes=random_bytes, file_name="icon.png", size_bytes=2_000)
    assert suspicious is False


def test_chi_square_pipeline_still_flags_the_documented_attack():
    ev = TelemetryEvent(event_id="stego-doc", source_ip="10.240.12.84", destination_ip="203.0.113.88", destination_port=443, file_name="quarterly_banner_logo.png",
                        bytes_out=8_450_000, payload_entropy=7.94, chi_square_randomness=285.4)
    assert tier1_engine.evaluate(ev).is_stego_detected is True


def test_canary_registry_variants_and_secrecy():
    reg = CanaryRegistry([{"canary_id": "C1", "record_type": "credit_card", "value": "4532-0198-4421-9988"}])
    assert reg.match("SELECT '4532-0198-4421-9988'") and reg.match("x 4532 0198 4421 9988 y") and reg.match("4532019844219988")
    assert not reg.match("4532-0198-4421-9989") and not reg.match(None, "")
    reg.record_trip("C1", "usr_x")
    listing = reg.list()
    assert listing[0]["tripped"] is True and listing[0]["tripped_by"] == "usr_x"
    assert "value" not in listing[0]  # the canary value is a secret of the defender


def test_tier1_trips_once_per_canary_and_scans_payload():
    from src.core.honeytokens import canary_registry
    ev = TelemetryEvent(event_id="honey-payload", source_ip="10.240.5.10", destination_ip="10.240.10.50", destination_port=5432,
                        user_id="usr_dba_1022", raw_payload="exported: 4532-0198-4421-9988")
    res = tier1_engine.evaluate(ev)
    assert res.is_honeytoken_hit and res.action == "HARD_DROP"
    tripped = [c for c in canary_registry.list() if c["tripped"]]
    assert any(c["canary_id"] == "CANARY-CC-9988" for c in tripped)
