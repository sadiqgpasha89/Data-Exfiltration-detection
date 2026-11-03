"""Unit tests for Layer 1 Deterministic & Rule-Based Filtering Engine."""

import pytest
from src.core.models import TelemetryEvent
from src.datascience.tier1_rules.edm_matcher import edm_matcher
from src.datascience.tier1_rules.regex_compliance import regex_compliance
from src.datascience.tier1_rules.reputation_filter import reputation_filter
from src.datascience.tier1_rules.stego_detector import stego_detector
from src.datascience.tier1_rules import tier1_engine


def test_edm_matcher_known_and_unknown_hashes():
    known_hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
    unknown_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    assert edm_matcher.is_exact_match(known_hash) is True
    assert edm_matcher.is_exact_match(unknown_hash) is False
    assert edm_matcher.is_exact_match(None) is False


def test_regex_compliance_luhn_credit_card():
    # Valid Visa card passing Luhn
    valid_card = "4532 0150 1234 5671"
    invalid_card = "4532 0150 1234 5670"

    assert regex_compliance.luhn_checksum_valid(valid_card) is True
    assert regex_compliance.luhn_checksum_valid(invalid_card) is False

    # Test payload scan
    text_with_cc = f"Dump of customers: {valid_card} and SSN: 123-45-6789"
    has_viol, reasons = regex_compliance.has_compliance_violation(text_with_cc)
    assert has_viol is True
    assert any("PCI-DSS" in r for r in reasons)
    assert any("GLBA/PII" in r for r in reasons)


def test_regex_compliance_iban():
    # Standard dummy valid IBAN format test
    valid_iban = "GB82WEST12345698765432"
    invalid_iban = "GB00WEST12345698765432"

    assert regex_compliance.iban_checksum_valid(valid_iban) is True
    assert regex_compliance.iban_checksum_valid(invalid_iban) is False


def test_reputation_filter_c2_and_ports():
    # Malicious C2 IP
    assert reputation_filter.is_malicious_ip("185.220.101.5") is True
    assert reputation_filter.is_malicious_ip("8.8.8.8") is False

    # Malicious C2 domain
    assert reputation_filter.is_malicious_domain("subdomain.dns-tunnel-relay.xyz") is True
    assert reputation_filter.is_malicious_domain("bank-approved-api.internal") is False

    # Database subnet port policy (zero tolerance egress on port 22/3389)
    assert reputation_filter.is_prohibited_database_egress("10.240.10.50", 22) is True
    assert reputation_filter.is_prohibited_database_egress("10.240.10.50", 443) is False


def test_steganography_detector():
    # High entropy payload
    suspicious, entropy, chi_sq, reason = stego_detector.evaluate_payload(
        entropy_score=7.92,
        file_name="quarterly_report.png",
        chi_square_score=250.0,
    )
    assert suspicious is True
    assert "steganography" in reason.lower() or "entropy" in reason.lower()

    # Normal payload
    suspicious_normal, ent_norm, _, _ = stego_detector.evaluate_payload(
        entropy_score=3.5,
        file_name="document.pdf",
    )
    assert suspicious_normal is False


def test_tier1_engine_complete_evaluation(benign_event, burst_cloud_event, honeytoken_event):
    # Benign event should PASS_THROUGH
    res_benign = tier1_engine.evaluate(benign_event)
    assert res_benign.action == "PASS_THROUGH"
    assert res_benign.is_known_c2 is False

    # Burst cloud event with EDM hash should HARD_DROP or FLAG_DEEP_INSPECTION
    res_burst = tier1_engine.evaluate(burst_cloud_event)
    assert res_burst.action in ["HARD_DROP", "FLAG_DEEP_INSPECTION"]
    assert res_burst.is_edm_exact_match is True

    # Honeytoken event should HARD_DROP
    res_honey = tier1_engine.evaluate(honeytoken_event)
    assert res_honey.action == "HARD_DROP"
    assert res_honey.is_honeytoken_hit is True
