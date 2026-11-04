"""The ledger: durable, tamper-evident, concurrency-safe."""

import json
import threading

import pytest
from src.core.crypto_audit import WormAuditLedger
from src.core.exceptions import AuditIntegrityError


def test_ledger_survives_restart(tmp_path):
    path = str(tmp_path / "audit" / "ledger.jsonl")
    ledger = WormAuditLedger(path)
    head = ledger.append_incident_dossier("CASE-1", {"verdict": "MALICIOUS_EXFILTRATION"})
    ledger.audit_human_decision("CASE-1", 0.95, "FALSE_POSITIVE", analyst_id="usr_soc_1")

    reloaded = WormAuditLedger(path)
    assert len(reloaded.chain) == 3 and reloaded.chain[1].block_hash == head
    assert reloaded.verify_chain_integrity() is True
    reloaded.append_incident_dossier("CASE-2", {"verdict": "FALSE_POSITIVE"})
    assert len(WormAuditLedger(path).chain) == 4  # appends after a reload extend the same chain


def test_start_up_refuses_a_tampered_ledger_file(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = WormAuditLedger(str(path))
    ledger.append_incident_dossier("CASE-1", {"verdict": "MALICIOUS_EXFILTRATION"})
    lines = path.read_text().splitlines()
    block = json.loads(lines[1])
    block["metadata"]["verdict"] = "FALSE_POSITIVE"  # an insider rewrites history
    lines[1] = json.dumps(block, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditIntegrityError, match="failed verification"):
        WormAuditLedger(str(path))


def test_deleting_a_block_is_detected(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = WormAuditLedger(str(path))
    for i in range(3):
        ledger.append_incident_dossier(f"C{i}", {"v": i})
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:2] + lines[3:]) + "\n")  # drop block 2
    with pytest.raises(AuditIntegrityError):
        WormAuditLedger(str(path))


def test_verify_chain_reports_the_first_bad_block_without_raising():
    ledger = WormAuditLedger()
    for i in range(4):
        ledger.append_incident_dossier(f"C{i}", {"v": i})
    assert ledger.verify_chain() == {"valid": True, "checked": 5, "first_bad_index": None, "error": None}
    ledger.chain[2].metadata["verdict"] = "edited"
    result = ledger.verify_chain()
    assert result["valid"] is False and result["first_bad_index"] == 2
    ledger.chain[2].metadata.pop("verdict")
    ledger.chain[0].metadata["system"] = "forged genesis"
    assert ledger.verify_chain()["first_bad_index"] == 0


def test_concurrent_appends_keep_the_chain_valid():
    ledger = WormAuditLedger()

    def work(n):
        for i in range(50):
            ledger.append_incident_dossier(f"T{n}-{i}", {"n": n, "i": i})

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(ledger.chain) == 1 + 8 * 50
    assert [b.index for b in ledger.chain] == list(range(len(ledger.chain)))
    assert ledger.verify_chain()["valid"] is True


def test_override_audit_records_who_did_it():
    ledger = WormAuditLedger()
    entry = ledger.audit_human_decision("CASE-9", 0.9, "DISMISSED_BENIGN", analyst_id="usr_soc_7821")
    assert entry["analyst_id"] == "usr_soc_7821" and entry["is_suspicious_override"] is True
    assert ledger.audit_human_decision("CASE-9", 0.84, "FALSE_POSITIVE")["is_suspicious_override"] is False
    assert ledger.audit_human_decision("CASE-9", 0.99, "APPROVED_MITIGATE")["is_suspicious_override"] is False
