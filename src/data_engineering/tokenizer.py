"""OpenStack Edge Anonymization and Tokenization Service.

Enforces data sovereignty and privacy mandates (PCI-DSS, GDPR, GLBA) before cross-cloud transit to Google Cloud
Platform: identifiers are replaced with keyed HMAC tokens, internal host addresses are masked, and SQL literals and
card or SSN values are removed from queries. Raw payloads never leave the edge.

The key is supplied by the operator (`TOKENIZATION_KEY_HEX`). In development an ephemeral random key is generated, so
tokens are not stable across restarts. Production refuses to start without a real key (see Settings.production_problems).
"""

import hashlib
import hmac
import ipaddress
import os
import re
import threading
from typing import Optional

from src.core.config import settings
from src.core.honeytokens import canary_registry
from src.core.models import TelemetryEvent, TokenizedTelemetryEvent
from src.core.netutil import is_internal
from src.core.telemetry import logger

_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_STRING_LITERAL = re.compile(r"'(?:[^']|'')*'")
_NUMERIC_CONSTANT = re.compile(r"(?P<op>=|<>|!=|<=|>=|<|>|\bLIKE\b|\bIN\s*\()\s*\d+(?:\.\d+)?", re.IGNORECASE)


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


class OpenStackEdgeTokenizer:
    """Anonymizes and tokenizes telemetry at OpenStack edge before GCP egress."""

    def __init__(self, key_hex: Optional[str] = None):
        key_hex = (key_hex if key_hex is not None else settings.TOKENIZATION_KEY_HEX).strip()
        if key_hex:
            self._key = bytes.fromhex(key_hex)
        else:
            self._key = os.urandom(32)
            logger.warning("tokenization_key_ephemeral", detail="TOKENIZATION_KEY_HEX is not set; tokens will change on restart")
        self._lock = threading.Lock()
        self.total_original_bytes = 0
        self.total_tokenized_bytes = 0

    def _mac(self, message: str) -> str:
        return hmac.new(self._key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def tokenize_identifier(self, value: str, prefix: str = "tok") -> str:
        """Deterministic keyed pseudonym: the same input always yields the same token, which cannot be reversed without the key."""
        if not value:
            return ""
        return f"{prefix}_{self._mac(f'{prefix}:{value}')[:16]}"

    def mask_ip(self, ip: str) -> str:
        """Pseudonymizes internal hosts but keeps the network prefix so subnet topology survives. External IPs are kept for threat-intel matching."""
        if not ip:
            return "0.0.0.0"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "0.0.0.0"
        if not is_internal(addr):
            return ip
        host = self._mac(f"ip:{ip}")[:6]
        if addr.version == 4:
            a, b, _, _ = ip.split(".")
            return f"{a}.{b}.x.{host}"
        return ":".join(addr.exploded.split(":")[:3]) + f"::x:{host}"

    def sanitize_query(self, query: str) -> str:
        """Removes literal values, card numbers, SSNs and emails from a SQL statement, keeping its structure."""
        if not query:
            return ""
        cleaned = _CARD_CANDIDATE.sub(lambda m: "[TOKEN_CREDIT_CARD]" if _luhn_valid(re.sub(r"\D", "", m.group())) else m.group(), query)
        cleaned = _SSN.sub("[TOKEN_SSN]", cleaned)
        cleaned = _EMAIL.sub("[TOKEN_EMAIL]", cleaned)
        cleaned = _STRING_LITERAL.sub("'[TOKEN_STR]'", cleaned)
        cleaned = _NUMERIC_CONSTANT.sub(lambda m: f"{m.group('op')} [TOKEN_NUM]", cleaned)
        return cleaned

    def process_event(self, event: TelemetryEvent) -> TokenizedTelemetryEvent:
        """Tokenizes an event for hybrid transit and measures the size reduction of the telemetry record itself."""
        orig_size = len(event.model_dump_json().encode("utf-8"))

        tokenized = TokenizedTelemetryEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            masked_source_ip=self.mask_ip(event.source_ip),
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            protocol=event.protocol,
            masked_user_id=self.tokenize_identifier(event.user_id or "anonymous", prefix="usr_tok"),
            tokenized_query=self.sanitize_query(event.query) if event.query else None,
            domain_queried=event.domain_queried,
            bytes_in=event.bytes_in,
            bytes_out=event.bytes_out,
            payload_entropy=event.payload_entropy,
            record_count=event.record_count,
            original_size_bytes=orig_size,
            tokenized_size_bytes=0,
            transit_savings_pct=0.0,
            is_honeytoken_hit=bool(canary_registry.match(event.query, event.raw_payload)),
        )

        tok_size = len(tokenized.model_dump_json().encode("utf-8"))
        tokenized.tokenized_size_bytes = tok_size
        tokenized.transit_savings_pct = round((orig_size - tok_size) / orig_size * 100.0, 2) if orig_size else 0.0

        with self._lock:
            self.total_original_bytes += orig_size
            self.total_tokenized_bytes += tok_size
        return tokenized

    def get_aggregate_savings(self) -> Optional[float]:
        """Measured size reduction over everything tokenized so far, or None before any event has been processed."""
        with self._lock:
            if self.total_original_bytes == 0:
                return None
            return round((self.total_original_bytes - self.total_tokenized_bytes) / self.total_original_bytes * 100.0, 2)


# Global tokenizer instance
edge_tokenizer = OpenStackEdgeTokenizer()
