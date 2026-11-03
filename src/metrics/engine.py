"""Unified 5-Tier Metrics Observatory Engine."""

from typing import Any, Dict
from src.metrics.agentic_metrics import agentic_metrics
from src.metrics.business_metrics import business_metrics
from src.metrics.ml_metrics import ml_metrics
from src.metrics.rag_metrics import rag_metrics
from src.metrics.system_metrics import system_metrics


class UnifiedMetricsEngine:
    """Consolidates metrics across all 5 operational dimensions."""

    def __init__(self):
        self.business = business_metrics
        self.system = system_metrics
        self.ml = ml_metrics
        self.rag = rag_metrics
        self.agentic = agentic_metrics

    def get_full_metrics_report(self) -> Dict[str, Any]:
        return {
            "business_metrics": self.business.calculate_metrics(),
            "system_metrics": self.system.calculate_metrics(),
            "ml_metrics": self.ml.calculate_metrics(),
            "rag_metrics": self.rag.calculate_metrics(),
            "agentic_metrics": self.agentic.calculate_metrics(),
            "status": "HEALTHY",
        }


metrics_engine = UnifiedMetricsEngine()
