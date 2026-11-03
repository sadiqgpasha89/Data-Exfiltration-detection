"""Full Tri-Layered Evaluation Endpoint."""

from typing import Any, Dict
from fastapi import APIRouter, HTTPException
from src.agents.swarm_orchestrator import swarm_orchestrator
from src.core.models import TelemetryEvent
from src.core.telemetry import TelemetryTimer
from src.data_engineering.pipeline import data_pipeline
from src.datascience.tier1_rules import tier1_engine
from src.datascience.tier2_ml import tier2_scorer
from src.hitl.case_manager import case_manager
from src.metrics.business_metrics import business_metrics
from src.metrics.system_metrics import system_metrics

router = APIRouter(prefix="/evaluate", tags=["Evaluation"])


@router.post("/process", response_model=Dict[str, Any])
def evaluate_event_full_pipeline(event_data: Dict[str, Any]):
    """Executes the full Tri-Layered detection pipeline:

    Layer 1 (Rules) -> Layer 2 (ML Anomaly) -> Layer 3 (Agent Swarm).
    """
    try:
        with TelemetryTimer("full_pipeline_run") as timer:
            # 1. Data Engineering Ingestion & Feature Store
            event, tokenized, features = data_pipeline.process_raw_event(event_data)

            # 2. Layer 1: High-Speed Deterministic Rules (OpenStack Edge)
            l1_result = tier1_engine.evaluate(event)

            # 3. Layer 2: Statistical & ML Anomaly Detection (GCP)
            l2_result = tier2_scorer.evaluate(event, features)

            # 4. Layer 3: Agentic Reasoning & Contextual Investigation
            dossier = None
            should_dispatch_agent = (
                l2_result.requires_agentic_dispatch
                or l1_result.action in ["FLAG_DEEP_INSPECTION", "HARD_DROP"]
                or l1_result.is_honeytoken_hit
            )

            if should_dispatch_agent:
                dossier = swarm_orchestrator.execute_investigation(
                    event=event,
                    feature_vector=features,
                    layer1_eval=l1_result,
                    layer2_eval=l2_result,
                )
                case_manager.add_dossier(dossier)

                # Record business metrics
                business_metrics.record_incident_resolution(
                    verdict=dossier.verdict,
                    detection_time_sec=timer.elapsed_ms / 1000.0,
                    response_time_sec=(timer.elapsed_ms + 150.0) / 1000.0,
                    capital_risk_usd=dossier.estimated_capital_risk_usd,
                    is_hitl=(dossier.remediation_status.value == "HITL_PENDING"),
                )

            # Record system metrics
            system_metrics.record_pipeline_latency(
                total_ms=timer.elapsed_ms,
                l1_ms=l1_result.evaluation_latency_ms,
                l2_ms=l2_result.evaluation_latency_ms,
            )

        return {
            "event_id": event.event_id,
            "layer1_evaluation": l1_result.model_dump(),
            "layer2_evaluation": l2_result.model_dump(),
            "layer3_dispatched": should_dispatch_agent,
            "incident_dossier": dossier.model_dump() if dossier else None,
            "total_latency_ms": round(timer.elapsed_ms, 2),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
