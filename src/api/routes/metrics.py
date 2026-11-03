"""Comprehensive 5-Tier Metrics Observatory API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter
from src.metrics.engine import metrics_engine

router = APIRouter(prefix="/metrics", tags=["Metrics"])


@router.get("", response_model=Dict[str, Any])
def get_unified_metrics():
    """Returns the consolidated 5-tier metrics report."""
    return metrics_engine.get_full_metrics_report()
