"""MITRE ATT&CK & Evasion Attack Simulator API endpoints (development and demos only)."""

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException

from src.api.pipeline_service import run_full_pipeline
from src.core.config import settings
from src.core.security import Principal, require
from src.mlops.shadow_validator import shadow_validator

router = APIRouter(prefix="/simulator", tags=["Simulator"])


@router.post("/inject/{scenario_name}", response_model=Dict[str, Any])
def inject_simulation_scenario(scenario_name: str, principal: Principal = Depends(require("simulate"))):
    """Executes a pre-configured MITRE ATT&CK or edge-case scenario:

    - 't1048_dns_tunnel'
    - 't1567_burst_cloud'
    - 't1029_drip_exfil'
    - 'honeytoken_trip'
    - 'media_steganography'
    - 'insider_collusion'
    - 'legitimate_bulk_audit'
    """
    if not settings.simulator_enabled:
        raise HTTPException(status_code=404, detail="Not found")
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

    result = run_full_pipeline(raw_event, force_investigation=True)
    return {"scenario_injected": scenario_name, **result}
