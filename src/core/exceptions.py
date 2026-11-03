"""Domain exceptions for Data Exfiltration Detection Platform."""


class ExfiltrationPlatformException(Exception):
    """Base exception for data exfiltration platform."""
    pass


class IngestionError(ExfiltrationPlatformException):
    """Raised when telemetry ingestion fails."""
    pass


class TokenizationError(ExfiltrationPlatformException):
    """Raised when PII/PCI tokenization fails."""
    pass


class RuleEvaluationError(ExfiltrationPlatformException):
    """Raised when Layer 1 deterministic rule evaluation fails."""
    pass


class AnomalyDetectionError(ExfiltrationPlatformException):
    """Raised when Layer 2 ML anomaly scoring encounters an error."""
    pass


class AgentOrchestrationError(ExfiltrationPlatformException):
    """Raised during Layer 3 multi-agent reasoning or debate."""
    pass


class RemediationExecutionError(ExfiltrationPlatformException):
    """Raised when automated or approved remediation fails."""
    pass


class AuditIntegrityError(ExfiltrationPlatformException):
    """Raised when cryptographic hash chain or WORM audit log is tampered with."""
    pass
