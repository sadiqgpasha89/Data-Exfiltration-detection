"""Layer 1 Deterministic & Rule-Based Filtering Engine Coordinator.

Executes microsecond evaluations across:
1. Exact Data Match (EDM) bloom filter
2. Syntactic DFA regex + Luhn checksum (PCI/GLBA/GDPR)
3. Threat intelligence C2 blacklists & perimeter policies
4. Steganography & Shannon entropy tests
"""

import time
from typing import Dict
from src.core.config import settings
from src.core.honeytokens import canary_registry
from src.core.models import Layer1Evaluation, TelemetryEvent
from src.core.telemetry import TelemetryTimer
from src.datascience.tier1_rules.edm_matcher import edm_matcher
from src.datascience.tier1_rules.regex_compliance import regex_compliance
from src.datascience.tier1_rules.reputation_filter import reputation_filter
from src.datascience.tier1_rules.stego_detector import stego_detector


class Tier1RuleEngine:
    """OpenStack Edge wire-speed deterministic rule engine."""

    def __init__(self):
        self.edm = edm_matcher
        self.regex = regex_compliance
        self.reputation = reputation_filter
        self.stego = stego_detector

    def evaluate(self, event: TelemetryEvent) -> Layer1Evaluation:
        with TelemetryTimer("layer1_rule_eval") as timer:
            triggered = []
            is_c2 = False
            is_edm = False
            is_compliance = False
            is_stego = False
            is_honey = False

            # 1. Honeytoken check (Zero-tolerance trip)
            canaries = canary_registry.match(event.query, event.raw_payload)
            if canaries:
                is_honey = True
                for canary in canaries:
                    canary_registry.record_trip(canary["canary_id"], event.user_id)
                    triggered.append(f"CRITICAL: Honeytoken canary {canary['canary_id']} ({canary['record_type']}) accessed")

            # 2. Exact Data Match (EDM)
            if event.file_hash_sha256 and self.edm.is_exact_match(event.file_hash_sha256):
                is_edm = True
                triggered.append(f"EDM: File hash matches proprietary banking ledger ({event.file_hash_sha256[:12]}...)")

            # 3. Reputation & Egress Policy
            has_rep_viol, rep_reasons = self.reputation.evaluate_connection(
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                destination_port=event.destination_port,
                domain_queried=event.domain_queried,
            )
            if has_rep_viol:
                is_c2 = True
                triggered.extend(rep_reasons)

            # 4. Syntactic Regex & Luhn check
            if event.query or event.raw_payload:
                text_to_scan = f"{event.query or ''} {event.raw_payload or ''}"
                has_comp_viol, comp_reasons = self.regex.has_compliance_violation(text_to_scan)
                if has_comp_viol:
                    is_compliance = True
                    triggered.extend(comp_reasons)

            # 5. Stego & Entropy check
            has_stego, entropy, chi_sq, stego_reason = self.stego.evaluate_payload(
                raw_bytes=event.raw_payload.encode()[: settings.MAX_PAYLOAD_SCAN_CHARS] if event.raw_payload else None,
                entropy_score=event.payload_entropy,
                chi_square_score=event.chi_square_randomness,
                file_name=event.file_name,
                size_bytes=event.bytes_out,
            )
            if has_stego:
                is_stego = True
                triggered.append(stego_reason)

            # Action determination
            if is_honey or is_c2:
                action = "HARD_DROP"
            elif is_edm or is_compliance or is_stego:
                action = "FLAG_DEEP_INSPECTION"
            elif event.bytes_out > 10_000_000 or event.payload_entropy > 7.0:
                action = "FLAG_DEEP_INSPECTION"
            else:
                action = "PASS_THROUGH"

        return Layer1Evaluation(
            event_id=event.event_id,
            action=action,
            triggered_rules=triggered,
            is_known_c2=is_c2,
            is_edm_exact_match=is_edm,
            is_regex_compliance_hit=is_compliance,
            is_stego_detected=is_stego,
            is_honeytoken_hit=is_honey,
            evaluation_latency_ms=round(timer.elapsed_ms, 3),
        )


# Global Tier 1 rule engine
tier1_engine = Tier1RuleEngine()

__all__ = [
    "tier1_engine",
    "Tier1RuleEngine",
    "edm_matcher",
    "regex_compliance",
    "reputation_filter",
    "stego_detector",
]
