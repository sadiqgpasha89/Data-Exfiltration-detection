"""The full tri-layer pipeline as one function, shared by the evaluate and simulator endpoints."""

from typing import Any, Dict

from src.agents.swarm_orchestrator import swarm_orchestrator
from src.core.models import RemediationStatus
from src.core.telemetry import TelemetryTimer
from src.data_engineering.lakehouse_sink import lakehouse_sink
from src.data_engineering.pipeline import data_pipeline
from src.datascience.tier1_rules import tier1_engine
from src.datascience.tier2_ml import tier2_scorer
from src.hitl.case_manager import case_manager
from src.metrics.business_metrics import business_metrics
from src.metrics.system_metrics import system_metrics

CONTAINED = {RemediationStatus.AUTO_MITIGATED, RemediationStatus.APPROVED_MITIGATED}
HUMAN_QUEUE = {RemediationStatus.HITL_PENDING, RemediationStatus.CONTAINMENT_RECOMMENDED}


def run_full_pipeline(event_data: Dict[str, Any], force_investigation: bool = False) -> Dict[str, Any]:
    """Layer 1 (rules) -> Layer 2 (ML anomaly) -> Layer 3 (agent swarm) for one raw event. Raises pydantic.ValidationError on bad input."""
    with TelemetryTimer("full_pipeline_run") as timer:
        event, _tokenized, features = data_pipeline.process_raw_event(event_data)
        l1_result = tier1_engine.evaluate(event)
        l2_result = tier2_scorer.evaluate(event, features)

        dispatch = (
            force_investigation
            or l2_result.requires_agentic_dispatch
            or l1_result.action in ("FLAG_DEEP_INSPECTION", "HARD_DROP")
            or l1_result.is_honeytoken_hit
        )
        dossier = None
        if dispatch:
            dossier = swarm_orchestrator.execute_investigation(event=event, feature_vector=features, layer1_eval=l1_result, layer2_eval=l2_result)
            case_manager.add_dossier(dossier)
            lakehouse_sink.write_incident_dossier(dossier)

    if dossier is not None:
        business_metrics.record_incident_resolution(
            verdict=dossier.verdict,
            detection_time_sec=timer.elapsed_ms / 1000.0,
            response_time_sec=dossier.total_pipeline_latency_ms / 1000.0,
            capital_risk_usd=dossier.estimated_capital_risk_usd,
            is_hitl=dossier.remediation_status in HUMAN_QUEUE,
            contained=dossier.remediation_status in CONTAINED,
        )
    system_metrics.record_pipeline_latency(total_ms=timer.elapsed_ms, l1_ms=l1_result.evaluation_latency_ms, l2_ms=l2_result.evaluation_latency_ms)

    return {
        "event_id": event.event_id,
        "layer1_evaluation": l1_result.model_dump(),
        "layer2_evaluation": l2_result.model_dump(),
        "layer3_dispatched": dispatch,
        "incident_dossier": dossier.model_dump() if dossier else None,
        "total_latency_ms": round(timer.elapsed_ms, 2),
    }
