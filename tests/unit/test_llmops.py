"""Unit tests for LLMOps Prompt Registry, Eval Harness, and Cost Tracker."""

import pytest
from src.core.models import (
    AgentDebateTurn,
    AgentToolExecution,
    IncidentDossier,
    RemediationStatus,
    SeverityLevel,
)
from src.llmops.cost_tracker import cost_tracker
from src.llmops.eval_harness import eval_harness
from src.llmops.prompt_manager import prompt_manager


def test_prompt_manager_integrity():
    prompts = prompt_manager.get_all_prompts()
    assert len(prompts) >= 4
    for p in prompts:
        assert len(p.sha256_checksum) == 64
        assert p.system_prompt.strip() != ""


def test_tool_trajectory_evaluation():
    perfect_executions = [
        AgentToolExecution(tool_name="SandboxAnalyzerTool", parameters={}, result={}, latency_ms=1.0),
        AgentToolExecution(tool_name="GraphRAGRetrievalTool", parameters={}, result={}, latency_ms=2.0),
        AgentToolExecution(tool_name="ComplianceKnowledgebaseTool", parameters={}, result={}, latency_ms=1.5),
    ]
    imperfect_executions = [
        AgentToolExecution(tool_name="GraphRAGRetrievalTool", parameters={}, result={}, latency_ms=2.0),
        AgentToolExecution(tool_name="SandboxAnalyzerTool", parameters={}, result={}, latency_ms=1.0),
    ]

    score_perfect = eval_harness.evaluate_tool_trajectory_accuracy(perfect_executions)
    score_imperfect = eval_harness.evaluate_tool_trajectory_accuracy(imperfect_executions)

    assert score_perfect == 1.0
    assert score_imperfect < 1.0


def test_grounding_and_hallucination_fidelity():
    dossier = IncidentDossier(
        case_id="CASE-TEST-GROUNDING",
        event_id="EVT-001",
        timestamp="2026-09-14T00:00:00Z",
        verdict="MALICIOUS_EXFILTRATION",
        severity=SeverityLevel.HIGH,
        final_risk_score=0.90,
        primary_hypothesis="H2",
        root_cause_analysis="Test exfiltration analysis",
        citations=[
            "ProcessTree: ['explorer.exe', '7z.exe']",
            "HR-System [Doc-ID: HR-RESIGN-2026]: User tendered resignation.",
            "PCI-DSS v4.0 [Req 10.2]: Cardholder records breached.",
        ],
        remediation_status=RemediationStatus.AUTO_MITIGATED,
        worm_immutable_hash="a" * 64,
    )

    eval_result = eval_harness.evaluate_grounding_fidelity(dossier)
    assert eval_result["grounding_fidelity_score"] == 1.0
    assert eval_result["hallucination_error_rate"] == 0.0
    assert eval_result["meets_sla"] is True


def test_llm_cost_tracker():
    initial_summary = cost_tracker.get_summary()
    cost_tracker.record_usage(prompt_tokens=1500, completion_tokens=350)
    new_summary = cost_tracker.get_summary()

    assert new_summary["total_tokens"] == initial_summary["total_tokens"] + 1850
    assert new_summary["estimated_cost_usd"] >= initial_summary["estimated_cost_usd"]
