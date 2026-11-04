"""Metrics must be measured, never padded: no data means None, and recorded data moves the numbers."""

import pytest
from src.data_engineering.tokenizer import OpenStackEdgeTokenizer
from src.metrics.agentic_metrics import AgenticMetricsCalculator
from src.metrics.business_metrics import BusinessMetricsCalculator
from src.metrics.engine import metrics_engine
from src.metrics.ml_metrics import ml_metrics
from src.metrics.rag_metrics import RAGMetricsCalculator
from src.metrics.system_metrics import SystemMetricsCalculator
from src.evaluation.benchmark import benchmark_cache


def test_business_metrics_are_empty_not_invented():
    m = BusinessMetricsCalculator().calculate_metrics()
    assert m["measured"] is False
    assert m["total_raw_alerts_processed"] == 0
    assert m["autonomous_resolutions"] == 0
    assert m["hitl_escalations"] == 0
    assert m["total_capital_loss_avoided_usd"] == 0
    assert m["mttd_minutes"] is None and m["mttd_target_met"] is None
    assert m["soc_analyst_fatigue_reduction_pct"] is None


def test_business_metrics_follow_recorded_incidents():
    b = BusinessMetricsCalculator()
    b.record_incident_resolution("MALICIOUS_EXFILTRATION", 0.12, 0.2, 1_000_000.0, contained=True)
    b.record_incident_resolution("MALICIOUS_EXFILTRATION", 0.12, 0.2, 500_000.0, is_hitl=True, contained=False)
    b.record_incident_resolution("FALSE_POSITIVE", 0.06, 0.1, 0.0)
    b.record_incident_resolution("SUSPICIOUS_ANOMALY_PENDING_HITL", 0.06, 0.1, 0.0, is_hitl=True)
    m = b.calculate_metrics()
    assert m["total_raw_alerts_processed"] == 4
    assert m["autonomous_resolutions"] == 2  # one contained, one dismissed
    assert m["hitl_escalations"] == 2
    assert m["total_capital_loss_avoided_usd"] == 1_000_000.0  # exposure that was NOT contained is not "avoided"
    assert m["total_estimated_exposure_usd"] == 1_500_000.0
    assert m["soc_analyst_fatigue_reduction_pct"] == 50.0
    assert m["mttd_target_met"] is True


def test_system_metrics_have_no_baked_in_latencies():
    m = SystemMetricsCalculator().calculate_metrics()
    assert m["measured"] is False
    assert m["p99_latency_ms"] is None and m["p99_sla_met"] is None
    s = SystemMetricsCalculator()
    for ms in (10.0, 20.0, 30.0, 4000.0):
        s.record_pipeline_latency(ms, 0.1, 5.0)
    m = s.calculate_metrics()
    assert m["samples"] == 4 and m["p99_latency_ms"] > 1500 and m["p99_sla_met"] is False


def test_transit_savings_is_measured_and_none_without_data():
    tok = OpenStackEdgeTokenizer(key_hex="ab" * 32)
    assert tok.get_aggregate_savings() is None
    from src.core.models import TelemetryEvent
    big = TelemetryEvent(event_id="sv1", source_ip="10.0.0.5", destination_ip="8.8.8.8", destination_port=443, user_id="u",
                         raw_payload="x" * 50_000, query="SELECT * FROM t WHERE a = 5")
    tokenized = tok.process_event(big)
    assert tokenized.transit_savings_pct > 90  # the raw payload does not travel
    assert tok.get_aggregate_savings() == pytest.approx(tokenized.transit_savings_pct, abs=0.01)


def test_agentic_and_rag_metrics_do_not_claim_llm_quality():
    a = AgenticMetricsCalculator().calculate_metrics()
    assert a["measured"] is False and a["task_completion_rate_pct"] is None
    assert a["hallucination_error_rate"] is None and a["tool_trajectory_accuracy"] is None
    r = RAGMetricsCalculator()
    r.record_retrieval(True)
    r.record_retrieval(False, ["outside the validity window"])
    m = r.calculate_metrics()
    assert m["ticket_match_rate"] == 0.5 and m["faithfulness"] is None
    assert m["rejected_ticket_reasons"] == {"outside the validity window": 1}


def test_ml_metrics_come_from_the_benchmark():
    report = benchmark_cache.wait()
    assert report["status"] == "ready"
    m = ml_metrics.calculate_metrics()
    assert m["measured"] is True
    assert m["pr_auc"] == report["ensemble"]["pr_auc"]
    assert "synthetic" in m["evaluated_on"] and "caveat" in m
    assert set(m["by_model"]) == {"isolation_forest", "autoencoder", "graph_entitlement"}


def test_unified_metrics_engine_shape():
    report = metrics_engine.get_full_metrics_report()
    for key in ("business_metrics", "system_metrics", "ml_metrics", "rag_metrics", "agentic_metrics"):
        assert key in report
    assert report["status"] == "OK"
