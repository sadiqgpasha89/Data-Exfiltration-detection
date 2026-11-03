"""Unit tests for Comprehensive 5-Tier Metrics Observatory."""

import pytest
from src.metrics.agentic_metrics import agentic_metrics
from src.metrics.business_metrics import business_metrics
from src.metrics.engine import metrics_engine
from src.metrics.ml_metrics import ml_metrics
from src.metrics.rag_metrics import rag_metrics
from src.metrics.system_metrics import system_metrics


def test_business_metrics():
    metrics = business_metrics.calculate_metrics()
    assert "mttd_minutes" in metrics
    assert "mttr_minutes" in metrics
    assert "total_capital_loss_avoided_usd" in metrics
    assert "soc_analyst_fatigue_reduction_pct" in metrics
    assert metrics["mttd_minutes"] < 2.0
    assert metrics["soc_analyst_fatigue_reduction_pct"] >= 85.0


def test_system_metrics():
    metrics = system_metrics.calculate_metrics()
    assert "p99_latency_ms" in metrics
    assert "ingestion_throughput_eps" in metrics
    assert "hybrid_transit_cost_savings_pct" in metrics
    assert metrics["hybrid_transit_cost_savings_pct"] >= 80.0
    assert (metrics["p99_latency_ms"] / 1000.0) <= 1.5


def test_ml_metrics():
    metrics = ml_metrics.calculate_metrics()
    assert "pr_auc" in metrics
    assert "false_positive_rate_at_95_tpr" in metrics
    assert "brier_calibration_score" in metrics
    assert metrics["pr_auc"] >= 0.90
    assert metrics["false_positive_rate_at_95_tpr"] < 0.001


def test_rag_metrics():
    metrics = rag_metrics.calculate_metrics()
    assert "context_retrieval_recall" in metrics
    assert "context_precision" in metrics
    assert "faithfulness" in metrics
    assert metrics["faithfulness"] >= 0.90


def test_agentic_metrics():
    metrics = agentic_metrics.calculate_metrics()
    assert "task_completion_rate_pct" in metrics
    assert "tool_trajectory_accuracy" in metrics
    assert "hallucination_error_rate" in metrics
    assert metrics["task_completion_rate_pct"] >= 95.0
    assert metrics["hallucination_error_rate"] <= 0.001


def test_unified_metrics_engine():
    report = metrics_engine.get_full_metrics_report()
    assert "business_metrics" in report
    assert "system_metrics" in report
    assert "ml_metrics" in report
    assert "rag_metrics" in report
    assert "agentic_metrics" in report
    assert report["status"] == "HEALTHY"
