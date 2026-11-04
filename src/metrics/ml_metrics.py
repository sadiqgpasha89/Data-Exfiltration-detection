"""Machine Learning Performance Metrics.

Read from the labelled benchmark (`src/evaluation/benchmark.py`), which runs the real rules, features and models over
generated benign and malicious telemetry. Nothing here is typed in. Until the first benchmark run finishes (a few
seconds after start-up) the report says it is computing.
"""

from typing import Any, Dict

from src.evaluation.benchmark import benchmark_cache


class MLMetricsCalculator:
    """Serves benchmark-derived model quality metrics."""

    def calculate_metrics(self) -> Dict[str, Any]:
        report = benchmark_cache.get()
        if report.get("status") != "ready":
            return {"measured": False, "status": report.get("status"), "error": report.get("error")}
        ens = report["ensemble"]
        return {
            "measured": True,
            "status": "ready",
            "evaluated_on": f"synthetic labelled benchmark ({report['dataset']['events']} events, {report['dataset']['malicious']} malicious)",
            "evaluated_at": report["evaluated_at"],
            "caveat": report["dataset"]["caveat"],
            "pr_auc": ens["pr_auc"],
            "roc_auc": ens["roc_auc"],
            "f1_score": ens["f1_at_tau"],
            "precision": ens["precision_at_tau"],
            "recall": ens["recall_at_tau"],
            "false_positive_rate_at_95_tpr": ens["fpr_at_95_tpr"],
            "fpr_target_met": None if ens["fpr_at_95_tpr"] is None else bool(ens["fpr_at_95_tpr"] < 0.001),
            "brier_calibration_score": ens["brier"],
            "by_model": report["by_model"],
            "layer3_dispatch": report["dispatch_to_layer3"],
            "total_validation_records": report["dataset"]["events"],
            "positive_malicious_samples": report["dataset"]["malicious"],
            "negative_benign_samples": report["dataset"]["benign"],
        }


ml_metrics = MLMetricsCalculator()
