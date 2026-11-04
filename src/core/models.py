"""Pydantic data models for OCSF schemas, pipeline envelopes, and incident dossiers."""

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator

from src.core.config import settings

_ID_PATTERN = r"^[A-Za-z0-9_.:\-]{1,128}$"


def utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventType(str, Enum):
    NETWORK_FLOW = "network_flow"
    DATABASE_QUERY = "database_query"
    DATABASE_DUMP = "database_dump"
    FILE_EGRESS = "file_egress"
    BATCH_EXPORT = "batch_export"
    IDENTITY_AUTH = "identity_auth"


class SeverityLevel(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RemediationStatus(str, Enum):
    PENDING_EVALUATION = "PENDING_EVALUATION"
    AUTO_MITIGATED = "AUTO_MITIGATED"  # containment verifiably applied
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"  # malicious verdict; containment not applied (dry run, blocked or simulated)
    HITL_PENDING = "HITL_PENDING"
    APPROVED_MITIGATED = "APPROVED_MITIGATED"
    DISMISSED_BENIGN = "DISMISSED_BENIGN"


class TelemetryEvent(BaseModel):
    """Raw or normalized OCSF telemetry event.

    This is the trust boundary: everything in it is supplied by the sender, so every field is bounded. `category` is a
    free-text label from the sender and is never used to make a security decision.
    """
    event_id: str = Field(pattern=_ID_PATTERN)
    timestamp: str = Field(default_factory=utc_now_str, max_length=40)
    event_type: str = Field(default=EventType.NETWORK_FLOW.value, max_length=64)
    source_ip: str = Field(max_length=45)
    destination_ip: str = Field(max_length=45)
    destination_port: int = Field(ge=0, le=65535)
    protocol: str = Field(default="TCP", max_length=16)
    user_id: Optional[str] = Field(default=None, max_length=128)
    process_name: Optional[str] = Field(default=None, max_length=260)
    query: Optional[str] = Field(default=None, max_length=100_000)
    domain_queried: Optional[str] = Field(default=None, max_length=253)
    file_name: Optional[str] = Field(default=None, max_length=260)
    file_hash_sha256: Optional[str] = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")
    bytes_in: int = Field(default=0, ge=0, le=2**53)
    bytes_out: int = Field(default=0, ge=0, le=2**53)
    payload_entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    chi_square_randomness: Optional[float] = Field(default=None, ge=0.0)
    record_count: int = Field(default=0, ge=0, le=2**40)
    category: str = Field(default="unclassified", max_length=64)
    raw_payload: Optional[str] = Field(default=None, max_length=settings.MAX_PAYLOAD_SCAN_CHARS)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("must be a valid IPv4 or IPv6 address")
        return value

    @field_validator("timestamp")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("must be an ISO-8601 timestamp")
        return value


class TokenizedTelemetryEvent(BaseModel):
    """Event post-tokenization at OpenStack edge, ready for GCP transit."""
    event_id: str
    timestamp: str
    event_type: str
    masked_source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    masked_user_id: str
    tokenized_query: Optional[str] = None
    domain_queried: Optional[str] = None
    bytes_in: int
    bytes_out: int
    payload_entropy: float
    record_count: int
    original_size_bytes: int
    tokenized_size_bytes: int
    transit_savings_pct: float
    is_honeytoken_hit: bool = False


class FeatureVector(BaseModel):
    """Sliding-window extracted features for ML models."""
    event_id: str
    user_id: str
    bytes_out_in_ratio: float
    connection_frequency_15m: int
    payload_entropy: float
    historical_deviation_score: float
    destination_cardinality_1h: int
    rolling_read_to_export_ratio_180d: float
    is_off_hours: bool
    privileged_role_hop: bool
    feature_timestamp: str = Field(default_factory=utc_now_str)


class Layer1Evaluation(BaseModel):
    """Outcome from OpenStack Layer 1 Rule-Based Engine."""
    event_id: str
    action: str  # "HARD_DROP", "PASS_THROUGH", "FLAG_DEEP_INSPECTION"
    triggered_rules: List[str] = Field(default_factory=list)
    is_known_c2: bool = False
    is_edm_exact_match: bool = False
    is_regex_compliance_hit: bool = False
    is_stego_detected: bool = False
    is_honeytoken_hit: bool = False
    evaluation_latency_ms: float = 0.0


class Layer2Evaluation(BaseModel):
    """Outcome from GCP Layer 2 Machine Learning Anomaly Detection."""
    event_id: str
    isolation_forest_score: float
    vae_reconstruction_loss: float
    graph_entitlement_deviation: float
    ensemble_risk_score: float  # S in [0.0, 1.0]
    requires_agentic_dispatch: bool
    evaluation_latency_ms: float = 0.0


class AgentToolExecution(BaseModel):
    """Record of a tool invoked by an agent."""
    tool_name: str
    parameters: Dict[str, Any]
    result: Dict[str, Any]
    latency_ms: float
    timestamp: str = Field(default_factory=utc_now_str)


class AgentDebateTurn(BaseModel):
    """Record of agent deliberation and reflection."""
    agent_name: str
    hypothesis: str
    confidence: float
    rationale: str
    supporting_citations: List[str]
    proposed_action: str


class IncidentDossier(BaseModel):
    """Cryptographically signed incident case generated by Layer 3 Swarm."""
    case_id: str
    event_id: str
    subject_ip: Optional[str] = None  # source host of the event: the only address a case may contain
    subject_user_id: Optional[str] = None
    timestamp: str
    verdict: str  # "MALICIOUS_EXFILTRATION", "LEGITIMATE_BULK_OPERATION", "FALSE_POSITIVE"
    severity: SeverityLevel
    final_risk_score: float
    primary_hypothesis: str
    root_cause_analysis: str
    regulatory_exposure: List[str] = Field(default_factory=list)
    estimated_capital_risk_usd: float = 0.0
    citations: List[str] = Field(default_factory=list)
    remediation_status: RemediationStatus
    remediation_playbook: List[str] = Field(default_factory=list)
    debate_turns: List[AgentDebateTurn] = Field(default_factory=list)
    tool_executions: List[AgentToolExecution] = Field(default_factory=list)
    worm_immutable_hash: str
    containment: Dict[str, Any] = Field(default_factory=dict)  # what automatic containment did, or why it did not
    consensus_cycles: int = 1
    total_pipeline_latency_ms: float = 0.0
