"""Cryptographic WORM (Write Once Read Many) append-only ledger simulation.

Guarantees tamper-evident audit trails for incident dossiers and prevents
insider collusion (e.g., DBA and rogue SOC analyst suppressing alerts).
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from src.core.exceptions import AuditIntegrityError


class WormAuditBlock:
    def __init__(self, index: int, timestamp: str, payload_hash: str, previous_hash: str, metadata: Dict[str, Any]):
        self.index = index
        self.timestamp = timestamp
        self.payload_hash = payload_hash
        self.previous_hash = previous_hash
        self.metadata = metadata
        self.block_hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        content = f"{self.index}|{self.timestamp}|{self.payload_hash}|{self.previous_hash}|{json.dumps(self.metadata, sort_keys=True)}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "payload_hash": self.payload_hash,
            "previous_hash": self.previous_hash,
            "block_hash": self.block_hash,
            "metadata": self.metadata,
        }


class WormAuditLedger:
    """Simulates immutable Object-Lock WORM storage (GCS / AWS S3 Object Lock)."""

    def __init__(self):
        self.chain: List[WormAuditBlock] = []
        self._initialize_genesis_block()

    def _initialize_genesis_block(self):
        genesis = WormAuditBlock(
            index=0,
            timestamp="2026-01-01T00:00:00Z",
            payload_hash="GENESIS_PAYLOAD_HASH",
            previous_hash="0" * 64,
            metadata={"system": "Sentinel WORM Ledger Genesis"},
        )
        self.chain.append(genesis)

    def append_incident_dossier(self, case_id: str, dossier_dict: Dict[str, Any]) -> str:
        """Computes SHA-256 hash of the dossier and appends to the immutable chain."""
        serialized = json.dumps(dossier_dict, sort_keys=True)
        payload_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        previous_hash = self.chain[-1].block_hash
        timestamp = datetime.now(timezone.utc).isoformat()

        new_block = WormAuditBlock(
            index=len(self.chain),
            timestamp=timestamp,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
            metadata={"case_id": case_id, "verdict": dossier_dict.get("verdict")},
        )
        self.chain.append(new_block)
        return new_block.block_hash

    def audit_human_decision(self, case_id: str, agent_risk_score: float, analyst_action: str) -> Dict[str, Any]:
        """Audits human analyst closure against autonomous agent verdict to catch collusion."""
        is_suspicious_override = False
        escalation_target = None

        if agent_risk_score >= 0.85 and analyst_action in ["DISMISSED_BENIGN", "FALSE_POSITIVE"]:
            is_suspicious_override = True
            escalation_target = "CHIEF_INFORMATION_SECURITY_OFFICER_AND_INTERNAL_FRAUD"

        audit_entry = {
            "case_id": case_id,
            "agent_risk_score": agent_risk_score,
            "analyst_action": analyst_action,
            "is_suspicious_override": is_suspicious_override,
            "escalation_target": escalation_target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Append audit check into WORM chain
        self.append_incident_dossier(case_id=f"AUDIT-{case_id}", dossier_dict=audit_entry)
        return audit_entry

    def verify_chain_integrity(self) -> bool:
        """Verifies that the block hash chain has not been tampered with."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.previous_hash != previous.block_hash:
                raise AuditIntegrityError(f"Chain broken at block {i}: previous hash mismatch")

            if current.block_hash != current._calculate_hash():
                raise AuditIntegrityError(f"Chain broken at block {i}: hash recalculation mismatch")

        return True

    def get_latest_hash(self) -> str:
        return self.chain[-1].block_hash

    def get_ledger_blocks(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self.chain]


# Global singleton instance
worm_ledger = WormAuditLedger()
