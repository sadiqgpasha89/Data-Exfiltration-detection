"""Honeytoken Vault & Canary Record Ingestion.

A thin SOC-facing view over the shared canary registry (`src/core/honeytokens.py`).
"""

from typing import Any, Dict, List, Optional

from src.core.honeytokens import CanaryRegistry, canary_registry


class HoneytokenVault:
    """Manages active honeytokens and alerts upon any read/query touch."""

    def __init__(self, registry: CanaryRegistry = canary_registry):
        self.registry = registry

    def check_query_for_honeytoken(self, query: Optional[str], user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Checks if a SQL query or payload touches a canary record, and records the trip."""
        tripped = self.registry.match(query)
        for canary in tripped:
            self.registry.record_trip(canary["canary_id"], user_id)
        return [{k: v for k, v in c.items() if k not in ("value", "_digits")} for c in tripped]

    def list_honeytokens(self) -> List[Dict[str, Any]]:
        return self.registry.list()


honeytoken_vault = HoneytokenVault()
