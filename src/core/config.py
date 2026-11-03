"""Global configuration for Data Exfiltration Detection and Prevention Platform."""

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Base paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"

    # Environment
    APP_NAME: str = "Sentinel Data Exfiltration Detection & Prevention Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "hybrid_openstack_gcp"

    # OpenStack Edge Configuration
    OPENSTACK_REGION: str = "onprem-zone-dc1"
    OPENSTACK_KAFKA_BROKERS: str = "kafka.openstack.internal:9092"
    OPENSTACK_NEUTRON_ENDPOINT: str = "http://neutron.openstack.internal:9696/v2.0"
    SR_IOV_ENABLED: bool = True
    CEPH_BUFFER_HOURS: int = 72
    TOKENIZATION_KEY_HEX: str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    # Google Cloud Platform (GCP) Configuration
    GCP_PROJECT_ID: str = "bank-cyber-enclave-prod"
    GCP_REGION: str = "us-central1"
    PUBSUB_TOPIC: str = "projects/bank-cyber-enclave-prod/topics/telemetry-stream"
    BIGQUERY_DATASET: str = "bank_security_lakehouse"
    VERTEX_FEATURE_STORE: str = "exfiltration_feature_store"
    GKE_TRITON_ENDPOINT: str = "http://triton-ensemble.gke.internal:8000"

    # Risk & Threat Index Thresholds
    ENTROPY_THRESHOLD: float = 7.50
    ANOMALY_DISPATCH_THRESHOLD_TAU: float = 0.65
    HIGH_CONFIDENCE_MALICIOUS_THRESHOLD: float = 0.85
    PSI_DRIFT_THRESHOLD: float = 0.25
    LATENCY_SLA_P99_SECONDS: float = 1.50
    HYBRID_TRANSIT_SAVINGS_TARGET: float = 0.80

    # Data Source Paths
    CORPORATE_DIRECTORY_PATH: Path = DATA_DIR / "corporate_directory.json"
    THREAT_INTEL_IOCS_PATH: Path = DATA_DIR / "threat_intel_iocs.json"
    JIRA_TICKETS_PATH: Path = DATA_DIR / "jira_tickets.json"
    REGULATORY_FRAMEWORKS_PATH: Path = DATA_DIR / "regulatory_frameworks.json"
    SEED_TELEMETRY_PATH: Path = DATA_DIR / "seed_telemetry.json"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
