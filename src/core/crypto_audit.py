"""Cryptographic WORM (Write Once Read Many) append-only ledger.

Each block commits to the hash of the previous one, so changing any historical record breaks every later hash and the
chain no longer verifies. With `LEDGER_PATH` set the chain is also written to an append-only JSON-lines file (flushed and
fsynced per block) and reloaded and verified at start-up, which makes the audit trail survive restarts and makes the
service refuse to start on a tampered file. A hash chain proves tampering is detectable, not that it is impossible: the
head hash should also be anchored somewhere the operator of this host cannot write (see README).
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.core.exceptions import AuditIntegrityError

GENESIS_PREVIOUS_HASH = "0" * 64
SUSPICIOUS_OVERRIDE_SCORE = 0.85
DISMISSAL_ACTIONS = {"DISMISSED_BENIGN", "FALSE_POSITIVE"}


class WormAuditBlock:
    def __init__(self, index: int, timestamp: str, payload_hash: str, previous_hash: str, metadata: Dict[str, Any],
                 block_hash: Optional[str] = None):
        self.index = index
        self.timestamp = timestamp
        self.payload_hash = payload_hash
        self.previous_hash = previous_hash
        self.metadata = metadata
        self.block_hash = block_hash or self._calculate_hash()

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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WormAuditBlock":
        return cls(data["index"], data["timestamp"], data["payload_hash"], data["previous_hash"], data["metadata"], data["block_hash"])


class WormAuditLedger:
    """Append-only, hash-chained, thread-safe ledger with optional durable storage."""

    def __init__(self, path: Optional[str] = None):
        self._lock = threading.RLock()
        self.path = path or None
        self.chain: List[WormAuditBlock] = []
        if self.path and os.path.exists(self.path) and os.path.getsize(self.path) > 0:
            self._load()
        else:
            self._initialize_genesis_block()

    # ---- persistence ----------------------------------------------------------------------------------------
    def _persist(self, block: WormAuditBlock) -> None:
        if not self.path:
            return
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(block.to_dict(), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as handle:
            self.chain = [WormAuditBlock.from_dict(json.loads(line)) for line in handle if line.strip()]
        result = self.verify_chain()
        if not result["valid"]:
            raise AuditIntegrityError(f"Ledger file {self.path} failed verification: {result['error']}")

    def _initialize_genesis_block(self):
        genesis = WormAuditBlock(
            index=0,
            timestamp="2026-01-01T00:00:00Z",
            payload_hash="GENESIS_PAYLOAD_HASH",
            previous_hash=GENESIS_PREVIOUS_HASH,
            metadata={"system": "Sentinel WORM Ledger Genesis"},
        )
        self.chain.append(genesis)
        self._persist(genesis)

    # ---- writes ---------------------------------------------------------------------------------------------
    def _append(self, payload_hash: str, metadata: Dict[str, Any]) -> WormAuditBlock:
        with self._lock:  # index and previous hash must be read and written atomically
            block = WormAuditBlock(
                index=len(self.chain),
                timestamp=datetime.now(timezone.utc).isoformat(),
                payload_hash=payload_hash,
                previous_hash=self.chain[-1].block_hash,
                metadata=metadata,
            )
            self._persist(block)  # durable first: a block that is not on disk is not in the chain
            self.chain.append(block)
            return block

    def append_incident_dossier(self, case_id: str, dossier_dict: Dict[str, Any]) -> str:
        """Computes the SHA-256 hash of the dossier and appends it to the chain."""
        serialized = json.dumps(dossier_dict, sort_keys=True, default=str)
        payload_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        block = self._append(payload_hash, {"case_id": case_id, "verdict": dossier_dict.get("verdict")})
        return block.block_hash

    def audit_human_decision(self, case_id: str, agent_risk_score: float, analyst_action: str,
                             analyst_id: Optional[str] = None) -> Dict[str, Any]:
        """Audits a human closure against the autonomous verdict to catch an analyst quietly suppressing a serious alert."""
        suspicious = agent_risk_score >= SUSPICIOUS_OVERRIDE_SCORE and analyst_action in DISMISSAL_ACTIONS
        audit_entry = {
            "case_id": case_id,
            "analyst_id": analyst_id,
            "agent_risk_score": agent_risk_score,
            "analyst_action": analyst_action,
            "is_suspicious_override": suspicious,
            "escalation_target": "CHIEF_INFORMATION_SECURITY_OFFICER_AND_INTERNAL_FRAUD" if suspicious else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.append_incident_dossier(case_id=f"AUDIT-{case_id}", dossier_dict=audit_entry)
        return audit_entry

    # ---- verification ---------------------------------------------------------------------------------------
    def verify_chain(self) -> Dict[str, Any]:
        """Verifies the whole chain and reports the first bad block instead of raising."""
        with self._lock:
            chain = list(self.chain)
        if not chain or chain[0].previous_hash != GENESIS_PREVIOUS_HASH or chain[0].block_hash != chain[0]._calculate_hash():
            return {"valid": False, "checked": 0, "first_bad_index": 0, "error": "genesis block is missing or altered"}
        for i in range(1, len(chain)):
            current, previous = chain[i], chain[i - 1]
            if current.index != i:
                return {"valid": False, "checked": i, "first_bad_index": i, "error": "block index out of sequence"}
            if current.previous_hash != previous.block_hash:
                return {"valid": False, "checked": i, "first_bad_index": i, "error": "previous hash mismatch"}
            if current.block_hash != current._calculate_hash():
                return {"valid": False, "checked": i, "first_bad_index": i, "error": "hash recalculation mismatch"}
        return {"valid": True, "checked": len(chain), "first_bad_index": None, "error": None}

    def verify_chain_integrity(self) -> bool:
        """Raises AuditIntegrityError if the chain has been tampered with, otherwise returns True."""
        result = self.verify_chain()
        if not result["valid"]:
            raise AuditIntegrityError(f"Chain broken at block {result['first_bad_index']}: {result['error']}")
        return True

    def get_latest_hash(self) -> str:
        with self._lock:
            return self.chain[-1].block_hash

    def get_ledger_blocks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [b.to_dict() for b in self.chain]


def _build_global_ledger() -> WormAuditLedger:
    from src.core.config import settings
    return WormAuditLedger(path=settings.LEDGER_PATH or None)


# Global singleton instance
worm_ledger = _build_global_ledger()
