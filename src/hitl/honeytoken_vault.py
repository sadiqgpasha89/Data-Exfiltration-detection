"""Honeytoken Vault & Canary Record Ingestion."""

from datetime import datetime
from typing import Any, Dict, List


class HoneytokenVault:
    """Manages active honeytokens and alerts upon any read/query touch."""

    def __init__(self):
        self.canary_records = [
            {
                "canary_id": "CANARY-CC-9988",
                "record_type": "credit_card",
                "value": "4532-0198-4421-9988",
                "table_location": "cardholder_records",
                "tripped": False,
                "tripped_by": None,
                "tripped_at": None,
            },
            {
                "canary_id": "CANARY-SWIFT-1002",
                "record_type": "swift_bic",
                "value": "BNKUS33DUMMY",
                "table_location": "core_settlements",
                "tripped": False,
                "tripped_by": None,
                "tripped_at": None,
            },
        ]

    def check_query_for_honeytoken(self, query: str, user_id: str = None) -> List[Dict[str, Any]]:
        """Checks if a SQL query or payload touches a canary record."""
        tripped = []
        if not query:
            return tripped

        for canary in self.canary_records:
            if canary["value"] in query:
                canary["tripped"] = True
                canary["tripped_by"] = user_id
                canary["tripped_at"] = datetime.utcnow().isoformat() + "Z"
                tripped.append(canary)

        return tripped

    def list_honeytokens(self) -> List[Dict[str, Any]]:
        return self.canary_records


honeytoken_vault = HoneytokenVault()
