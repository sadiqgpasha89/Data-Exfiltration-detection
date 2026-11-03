"""Unit tests for Multi-Agent Swarm and Specialized Agents."""

import pytest
from src.agents.compliance_agent import compliance_agent
from src.agents.correlation_agent import correlation_agent
from src.agents.state import AgentInvestigationState
from src.agents.swarm_orchestrator import swarm_orchestrator
from src.agents.triage_agent import triage_agent
from src.core.models import FeatureVector, Layer1Evaluation, Layer2Evaluation, TelemetryEvent


@pytest.fixture
def base_state(dns_tunnel_event):
    fv = FeatureVector(
        event_id=dns_tunnel_event.event_id,
        user_id=dns_tunnel_event.user_id,
        bytes_out_in_ratio=150.0,
        connection_frequency_15m=12,
        payload_entropy=7.89,
        historical_deviation_score=0.92,
        destination_cardinality_1h=4,
        rolling_read_to_export_ratio_180d=1.2,
        is_off_hours=True,
        privileged_role_hop=True,
    )
    l1 = Layer1Evaluation(
        event_id=dns_tunnel_event.event_id,
        action="HARD_DROP",
        triggered_rules=["C2 domain matched"],
        is_known_c2=True,
    )
    l2 = Layer2Evaluation(
        event_id=dns_tunnel_event.event_id,
        isolation_forest_score=0.92,
        vae_reconstruction_loss=0.88,
        graph_entitlement_deviation=0.95,
        ensemble_risk_score=0.91,
        requires_agentic_dispatch=True,
    )
    return AgentInvestigationState(
        event=dns_tunnel_event,
        feature_vector=fv,
        layer1_eval=l1,
        layer2_eval=l2,
    )


def test_triage_agent_investigation(base_state):
    state = triage_agent.investigate(base_state)
    assert len(state.tool_executions) == 1
    assert state.tool_executions[0].tool_name == "SandboxAnalyzerTool"
    assert len(state.debate_turns) == 1
    assert state.debate_turns[0].agent_name == "TriageAgent"
    assert state.triage_findings["is_suspicious_process"] is True


def test_correlation_agent_investigation(base_state):
    state = correlation_agent.investigate(base_state)
    # dev_4091 has resignation submitted, so Correlation Agent should catch this
    turn = state.debate_turns[-1]
    assert turn.agent_name == "CorrelationAgent"
    assert "resignation" in turn.rationale.lower() or "flight risk" in turn.rationale.lower()
    assert state.graph_rag_evidence["resignation_status"]["resigned"] is True


def test_compliance_agent_investigation(base_state):
    state = compliance_agent.investigate(base_state)
    turn = state.debate_turns[-1]
    assert turn.agent_name == "ComplianceAuditorAgent"
    assert state.regulatory_assessment["estimated_capital_risk_usd"] > 0
    assert len(turn.supporting_citations) > 0


def test_swarm_orchestrator_investigation(dns_tunnel_event, base_state):
    dossier = swarm_orchestrator.execute_investigation(
        event=dns_tunnel_event,
        feature_vector=base_state.feature_vector,
        layer1_eval=base_state.layer1_eval,
        layer2_eval=base_state.layer2_eval,
    )

    assert dossier.case_id.startswith("CASE-")
    assert dossier.verdict == "MALICIOUS_EXFILTRATION"
    assert dossier.severity.value in ["HIGH", "CRITICAL"]
    assert dossier.final_risk_score >= 0.85
    assert len(dossier.debate_turns) >= 3
    assert len(dossier.citations) >= 3
    assert len(dossier.worm_immutable_hash) == 64
