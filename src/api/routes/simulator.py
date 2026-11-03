"""MITRE ATT&CK & Evasion Attack Simulator API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter, HTTPException
from src.agents.swarm_orchestrator import swarm_orchestrator
from src.data_engineering.pipeline import data_pipeline
from src.datascience.tier1_rules import tier1_engine
from src.datascience.tier2_ml import tier2_scorer
from src.hitl.case_manager import case_manager
from src.metrics.business_metrics import business_metrics
from src.metrics.system_metrics import system_metrics
from src.mlops.shadow_validator import shadow_validator

router = APIRouter(prefix="/simulator", tags=["Simulator"])


@router.post("/inject/{scenario_name}", response_model=Dict[str, Any])
def inject_simulation_scenario(scenario_name: str):
    """Executes a pre-configured MITRE ATT&CK or edge-case scenario:

    - 't1048_dns_tunnel'
    - 't1567_burst_cloud'
    - 't1029_drip_exfil'
    - 'honeytoken_trip'
    - 'media_steganography'
    - 'insider_collusion'
    - 'legitimate_bulk_audit'
    """
    if scenario_name == "t1048_dns_tunnel":
        raw_event = shadow_validator.generate_dns_tunnel_attack()
    elif scenario_name == "t1567_burst_cloud":
        raw_event = shadow_validator.generate_burst_cloud_attack()
    elif scenario_name == "t1029_drip_exfil":
        raw_event = shadow_validator.generate_drip_exfil_attack()
    elif scenario_name == "honeytoken_trip":
        raw_event = shadow_validator.generate_honeytoken_trip()
    elif scenario_name == "media_steganography":
        raw_event = {
            "event_id": "sim-stego-lsb",
            "timestamp": "2026-09-14T14:10:20Z",
            "event_type": "file_egress",
            "source_ip": "10.240.12.84",
            "destination_ip": "203.0.113.88",
            "destination_port": 443,
            "protocol": "TCP",
            "user_id": "usr_dev_4091",
            "process_name": "chrome.exe",
            "file_name": "quarterly_banner_logo.png",
            "bytes_in": 512,
            "bytes_out": 8450000,
            "payload_entropy": 7.94,
            "chi_square_randomness": 285.4,
            "record_count": 4500,
            "category": "media_steganography",
        }
    elif scenario_name == "insider_collusion":
        raw_event = {
            "event_id": "sim-collusion-dba",
            "timestamp": "2026-09-14T23:45:00Z",
            "event_type": "database_dump",
            "source_ip": "10.240.5.10",
            "destination_ip": "10.240.10.50",
            "destination_port": 5432,
            "protocol": "TCP",
            "user_id": "usr_dba_1022",
            "process_name": "pg_dump.exe",
            "query": "COPY customer_accounts_master TO STDOUT WITH (FORMAT CSV, HEADER)",
            "bytes_in": 450,
            "bytes_out": 2147483648,
            "payload_entropy": 6.85,
            "record_count": 480000,
            "category": "insider_collusion",
        }
    elif scenario_name == "legitimate_bulk_audit":
        raw_event = {
            "event_id": "sim-legit-audit-fincen",
            "timestamp": "2026-09-14T11:00:00Z",
            "event_type": "batch_export",
            "source_ip": "10.240.8.44",
            "destination_ip": "192.0.2.100",
            "destination_port": 443,
            "protocol": "TCP",
            "user_id": "usr_analyst_3030",
            "process_name": "fincen_gateway_client.py",
            "query": "SELECT * FROM quarterly_regulatory_staging WHERE report_quarter = '2026-Q3'",
            "bytes_in": 8200,
            "bytes_out": 3500000000,
            "payload_entropy": 5.41,
            "record_count": 850000,
            "category": "legitimate_regulatory_bulk",
        }
    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{scenario_name}'")

    # Run through full Tri-Layered detection pipeline
    event, tokenized, features = data_pipeline.process_raw_event(raw_event)
    l1_result = tier1_engine.evaluate(event)
    l2_result = tier2_scorer.evaluate(event, features)

    dossier = swarm_orchestrator.execute_investigation(
        event=event,
        feature_vector=features,
        layer1_eval=l1_result,
        layer2_eval=l2_result,
    )
    case_manager.add_dossier(dossier)

    # Update business and system metrics
    business_metrics.record_incident_resolution(
        verdict=dossier.verdict,
        detection_time_sec=0.08,
        response_time_sec=0.25,
        capital_risk_usd=dossier.estimated_capital_risk_usd,
        is_hitl=(dossier.remediation_status.value == "HITL_PENDING"),
    )
    system_metrics.record_pipeline_latency(
        total_ms=dossier.total_pipeline_latency_ms,
        l1_ms=l1_result.evaluation_latency_ms,
        l2_ms=l2_result.evaluation_latency_ms,
    )

    return {
        "scenario_injected": scenario_name,
        "event_id": event.event_id,
        "layer1_evaluation": l1_result.model_dump(),
        "layer2_evaluation": l2_result.model_dump(),
        "incident_dossier": dossier.model_dump(),
    }
