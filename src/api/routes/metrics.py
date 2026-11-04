"""Comprehensive 5-Tier Metrics Observatory API endpoints."""

from typing import Any, Dict
from fastapi import APIRouter, Depends

from src.core.security import Principal, require
from src.metrics.engine import metrics_engine

router = APIRouter(prefix="/metrics", tags=["Metrics"])


@router.get("", response_model=Dict[str, Any])
def get_unified_metrics(principal: Principal = Depends(require("read"))):
    """Returns the consolidated 5-tier metrics report. Every figure is measured; metrics with no data are null."""
    return metrics_engine.get_full_metrics_report()
