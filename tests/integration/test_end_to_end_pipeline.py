"""End-to-End Integration Tests for Full Hybrid Tri-Layered Pipeline."""

import pytest
from src.agents.swarm_orchestrator import swarm_orchestrator
from src.core.crypto_audit import worm_ledger
from src.core.models import TelemetryEvent
from src.data_engineering.pipeline import data_pipeline
from src.datascience.tier1_rules import tier1_engine
from src.datascience.tier2_ml import tier2_scorer
from src.hitl.case_manager import case_manager


def test_full_pipeline_malicious_dns_tunnel(dns_tunnel_event):
    # 1. Data Engineering: Ingestion & Tokenization & Feature Extraction
    event, tokenized, features = data_pipeline.process_raw_event(dns_tunnel_event.model_dump())
    assert tokenized.masked_source_ip.startswith("10.240.x.")
    assert features.payload_entropy > 7.5

    # 2. Layer 1: High-Speed Rules
    l1_eval = tier1_engine.evaluate(event)
    assert l1_eval.is_known_c2 is True
    assert l1_eval.action == "HARD_DROP"

    # 3. Layer 2: Machine Learning Anomaly Ensemble
    l2_eval = tier2_scorer.evaluate(event, features)
    assert l2_eval.requires_agentic_dispatch is True
    assert l2_eval.ensemble_risk_score >= 0.70

    # 4. Layer 3: Multi-Agent Swarm Reasoning
    dossier = swarm_orchestrator.execute_investigation(
        event=event,
        feature_vector=features,
        layer1_eval=l1_eval,
        layer2_eval=l2_eval,
    )
    case_manager.add_dossier(dossier)

    # 5. Assertions
    assert dossier.verdict == "MALICIOUS_EXFILTRATION"
    assert dossier.final_risk_score >= 0.85
    assert len(dossier.citations) >= 3
    assert len(dossier.worm_immutable_hash) == 64

    # 6. Verify WORM audit ledger integrity
    assert worm_ledger.verify_chain_integrity() is True


def test_full_pipeline_legitimate_regulatory_audit(legitimate_audit_event):
    # Process legitimate regulatory audit by Samantha Liu under ticket REG-2026-8910
    event, tokenized, features = data_pipeline.process_raw_event(legitimate_audit_event.model_dump())

    # Layer 1
    l1_eval = tier1_engine.evaluate(event)
    # Layer 2
    l2_eval = tier2_scorer.evaluate(event, features)

    # Swarm
    dossier = swarm_orchestrator.execute_investigation(
        event=event,
        feature_vector=features,
        layer1_eval=l1_eval,
        layer2_eval=l2_eval,
    )

    # Should be recognized as authorized bulk transfer by Graph-RAG
    assert dossier.verdict == "LEGITIMATE_BULK_OPERATION"
    assert dossier.final_risk_score < 0.50
    assert dossier.remediation_status.value == "DISMISSED_BENIGN"
    assert any("Jira-ITSM" in c for c in dossier.citations)
