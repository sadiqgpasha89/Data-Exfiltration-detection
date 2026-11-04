"""Canary records (honeytokens): the single source of truth for what counts as a trip wire.

Nothing legitimate ever reads a canary, so any query or payload that contains one is a zero-tolerance signal. The
Layer 1 engine and the edge tokenizer both ask this module, so a canary registered here is detected everywhere and the
trip is recorded exactly once.
"""

import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_SEPARATORS = re.compile(r"[\s\-]")

DEFAULT_CANARIES: List[Dict[str, str]] = [
    {"canary_id": "CANARY-CC-9988", "record_type": "credit_card", "value": "4532-0198-4421-9988", "table_location": "cardholder_records"},
    {"canary_id": "CANARY-SWIFT-1002", "record_type": "swift_bic", "value": "BNKUS33DUMMY", "table_location": "core_settlements"},
]


class CanaryRegistry:
    """Thread-safe registry of canary values with trip bookkeeping."""

    def __init__(self, canaries: Optional[List[Dict[str, str]]] = None):
        self._lock = threading.Lock()
        self._canaries: List[Dict[str, Any]] = []
        for item in canaries if canaries is not None else DEFAULT_CANARIES:
            self.register(**item)

    def register(self, canary_id: str, record_type: str, value: str, table_location: str = "") -> None:
        digits = _SEPARATORS.sub("", value)
        with self._lock:
            self._canaries.append({
                "canary_id": canary_id,
                "record_type": record_type,
                "value": value,
                "table_location": table_location,
                "_digits": digits if digits.isdigit() and len(digits) >= 12 else None,
                "tripped": False,
                "tripped_by": None,
                "tripped_at": None,
            })

    def match(self, *texts: Optional[str]) -> List[Dict[str, Any]]:
        """Canaries present in any of the texts. Card-like canaries also match with spaces or dashes removed or added."""
        joined = " ".join(t for t in texts if t)
        if not joined:
            return []
        collapsed = _SEPARATORS.sub("", joined)
        with self._lock:
            return [
                c for c in self._canaries
                if c["value"] in joined or (c["_digits"] and c["_digits"] in collapsed)
            ]

    def record_trip(self, canary_id: str, user_id: Optional[str] = None) -> None:
        with self._lock:
            for c in self._canaries:
                if c["canary_id"] == canary_id:
                    c["tripped"] = True
                    c["tripped_by"] = user_id
                    c["tripped_at"] = datetime.now(timezone.utc).isoformat()

    def list(self) -> List[Dict[str, Any]]:
        """Canary values are secrets of the defender: they are never returned by listings."""
        with self._lock:
            return [
                {k: v for k, v in c.items() if k not in ("value", "_digits")}
                for c in self._canaries
            ]


canary_registry = CanaryRegistry()
