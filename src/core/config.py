"""Global configuration for the Data Exfiltration Detection and Prevention Platform.

Every operational setting comes from the environment (or a local `.env`). There are no secrets in this file: the
tokenization key and the API keys must be supplied by the operator, and `production_problems()` lists everything that
must be true before the service is allowed to start with `APP_ENV=production`.
"""

from pathlib import Path
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_TOKENIZATION_KEY_BYTES = 32
KNOWN_INSECURE_KEYS = {
    # the key that used to ship as a default in this repository: never acceptable
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
}


def _csv(value: str) -> List[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


class Settings(BaseSettings):
    # Base paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"

    # Environment
    APP_NAME: str = "Sentinel Data Exfiltration Detection & Prevention Platform"
    APP_VERSION: str = "1.1.0"
    APP_ENV: str = "development"  # development | staging | production
    DEBUG: bool = False
    ENVIRONMENT: str = "hybrid_openstack_gcp"  # topology label shown in the cockpit
    LOG_LEVEL: str = "INFO"

    # OpenStack Edge Configuration
    OPENSTACK_REGION: str = "onprem-zone-dc1"
    OPENSTACK_KAFKA_BROKERS: str = "kafka.openstack.internal:9092"
    OPENSTACK_NEUTRON_ENDPOINT: str = "http://neutron.openstack.internal:9696/v2.0"
    SR_IOV_ENABLED: bool = True
    CEPH_BUFFER_HOURS: int = 72

    # Secrets. No defaults: see production_problems().
    TOKENIZATION_KEY_HEX: str = ""
    API_KEYS: str = ""  # "name:role:key,name2:role:key"; roles: viewer, ingest, analyst, admin
    AUTH_DISABLED: bool = False  # development only; refused in production

    # HTTP surface
    CORS_ORIGINS: str = ""  # comma separated; empty means no cross-origin access
    MAX_BODY_BYTES: int = 1_000_000
    RATE_LIMIT_PER_MINUTE: int = 600
    BENCHMARK_ON_STARTUP: bool = True  # compute the labelled-benchmark metrics in the background after start-up
    MAX_CONCURRENT_EVALUATIONS: int = 32  # in-flight pipeline runs; beyond this the API answers 503 with Retry-After
    ENABLE_SIMULATOR: Optional[bool] = None  # None: on in development, off elsewhere

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
    BULK_RECORD_THRESHOLD: int = 100_000
    BULK_BYTES_THRESHOLD: int = 1_000_000_000
    MAX_PAYLOAD_SCAN_CHARS: int = 1_000_000
    SENSITIVE_TABLES: str = "hnw_clients"  # tables that exist outside the IAM directory but must never be read without entitlement

    # Streaming features
    FEATURE_MAX_USERS: int = 50_000
    FEATURE_MAX_EVENTS_PER_USER: int = 2_000
    FEATURE_CACHE_SIZE: int = 50_000
    DRIFT_MIN_SAMPLES: int = 200
    DRIFT_WINDOW_SIZE: int = 5_000

    # Containment. "dry_run" records what would be done and changes nothing.
    AUTO_REMEDIATION_MODE: str = "dry_run"  # off | dry_run | enforce
    PROTECTED_USER_IDS: str = ""  # never contained automatically (executives, break-glass, service accounts)
    PROTECTED_IPS: str = ""  # addresses or CIDRs that are never contained automatically
    MAX_AUTO_CONTAINMENTS_PER_HOUR: int = 5

    # Audit ledger. Empty means in-memory only (development).
    LEDGER_PATH: str = ""

    # Data Source Paths
    CORPORATE_DIRECTORY_PATH: Path = DATA_DIR / "corporate_directory.json"
    THREAT_INTEL_IOCS_PATH: Path = DATA_DIR / "threat_intel_iocs.json"
    JIRA_TICKETS_PATH: Path = DATA_DIR / "jira_tickets.json"
    REGULATORY_FRAMEWORKS_PATH: Path = DATA_DIR / "regulatory_frameworks.json"
    SEED_TELEMETRY_PATH: Path = DATA_DIR / "seed_telemetry.json"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ---- derived values -------------------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def simulator_enabled(self) -> bool:
        if self.ENABLE_SIMULATOR is not None:
            return self.ENABLE_SIMULATOR
        return self.APP_ENV.lower() == "development"

    @property
    def cors_origins(self) -> List[str]:
        return [o for o in _csv(self.CORS_ORIGINS) if o != "*"]

    @property
    def sensitive_tables(self) -> List[str]:
        return [t.lower() for t in _csv(self.SENSITIVE_TABLES)]

    @property
    def protected_user_ids(self) -> List[str]:
        return _csv(self.PROTECTED_USER_IDS)

    @property
    def protected_ips(self) -> List[str]:
        return _csv(self.PROTECTED_IPS)

    def production_problems(self) -> List[str]:
        """Everything that must be fixed before this process may serve production traffic."""
        problems: List[str] = []
        if not self.is_production:
            return problems
        key = self.TOKENIZATION_KEY_HEX.strip().lower()
        if not key:
            problems.append("TOKENIZATION_KEY_HEX is not set")
        elif key in KNOWN_INSECURE_KEYS:
            problems.append("TOKENIZATION_KEY_HEX is the example key that was published in the repository")
        else:
            try:
                if len(bytes.fromhex(key)) < MIN_TOKENIZATION_KEY_BYTES:
                    problems.append(f"TOKENIZATION_KEY_HEX must be at least {MIN_TOKENIZATION_KEY_BYTES} bytes of hex")
            except ValueError:
                problems.append("TOKENIZATION_KEY_HEX is not valid hex")
        if self.AUTH_DISABLED:
            problems.append("AUTH_DISABLED must not be set in production")
        if not self.API_KEYS.strip():
            problems.append("API_KEYS is empty: every endpoint would be unreachable or unauthenticated")
        if not self.LEDGER_PATH:
            problems.append("LEDGER_PATH is not set: the audit ledger would be lost on restart")
        if self.AUTO_REMEDIATION_MODE not in ("off", "dry_run", "enforce"):
            problems.append("AUTO_REMEDIATION_MODE must be off, dry_run or enforce")
        return problems


settings = Settings()
