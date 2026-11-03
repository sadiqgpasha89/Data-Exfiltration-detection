"""Multi-Agent Swarm State and Context Schema."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from src.core.models import (
    AgentDebateTurn,
    AgentToolExecution,
    FeatureVector,
    IncidentDossier,
    Layer1Evaluation,
    Layer2Evaluation,
    TelemetryEvent,
)


@dataclass
class AgentInvestigationState:
    """State object passed between specialized agents during plan-and-solve loops."""
    event: TelemetryEvent
    feature_vector: FeatureVector
    layer1_eval: Layer1Evaluation
    layer2_eval: Layer2Evaluation

    # Swarm working memory
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    triage_findings: Dict[str, Any] = field(default_factory=dict)
    graph_rag_evidence: Dict[str, Any] = field(default_factory=dict)
    regulatory_assessment: Dict[str, Any] = field(default_factory=dict)

    # Deliberation trail
    debate_turns: List[AgentDebateTurn] = field(default_factory=list)
    tool_executions: List[AgentToolExecution] = field(default_factory=list)

    # Consensus and outcome
    consensus_score: float = 0.0
    consensus_verdict: Optional[str] = None  # "MALICIOUS_EXFILTRATION", "LEGITIMATE_BULK_OPERATION", "FALSE_POSITIVE"
    final_dossier: Optional[IncidentDossier] = None
    consensus_cycles: int = 1
