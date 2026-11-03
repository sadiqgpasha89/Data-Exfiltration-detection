"""API routes package exports."""

from src.api.routes.drift import router as drift_router
from src.api.routes.evaluate import router as evaluate_router
from src.api.routes.incidents import router as incidents_router
from src.api.routes.metrics import router as metrics_router
from src.api.routes.remediation import router as remediation_router
from src.api.routes.simulator import router as simulator_router
from src.api.routes.telemetry import router as telemetry_router

__all__ = [
    "telemetry_router",
    "evaluate_router",
    "incidents_router",
    "remediation_router",
    "metrics_router",
    "drift_router",
    "simulator_router",
]
