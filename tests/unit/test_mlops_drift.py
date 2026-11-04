"""Unit tests for MLOps Drift Detection and Retraining Lifecycle."""

import numpy as np
import pytest
from src.mlops.drift_detector import drift_detector
from src.mlops.registry import model_registry
from src.mlops.retraining_trigger import retraining_controller


def test_psi_calculation_stable_and_drifted():
    np.random.seed(42)
    baseline = np.random.normal(loc=1.5, scale=0.5, size=500)
    stable_current = np.random.normal(loc=1.51, scale=0.49, size=200)
    drifted_current = np.random.normal(loc=3.5, scale=1.2, size=200)

    psi_stable = drift_detector.calculate_psi(baseline, stable_current)
    psi_drifted = drift_detector.calculate_psi(baseline, drifted_current)

    assert psi_stable < 0.10
    assert psi_drifted > 0.25


def test_wasserstein_distance():
    baseline = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
    current_close = np.array([1.1, 2.0, 3.1, 4.0, 5.1])
    current_far = np.array([10.0, 20.0, 30.0, 40.0, 50.0])

    w_close = drift_detector.calculate_wasserstein_distance(baseline, current_close)
    w_far = drift_detector.calculate_wasserstein_distance(baseline, current_far)

    assert w_close < 0.5
    assert w_far > 10.0


def test_drift_reports_insufficient_data_instead_of_inventing_a_window():
    from src.mlops.drift_detector import DriftDetector
    fresh = DriftDetector()
    report = fresh.evaluate_feature_drift()
    assert report["status"] == "INSUFFICIENT_DATA"
    assert report["psi_score"] is None and report["alert_triggered"] is False


def test_drift_uses_the_live_feature_window():
    from src.core.baseline import benign_baseline_matrix
    from src.mlops.drift_detector import DriftDetector
    detector = DriftDetector()
    for row in benign_baseline_matrix(400, seed=99):  # same distribution, new draw
        detector.record_feature_vector(row)
    healthy = detector.evaluate_feature_drift()
    assert healthy["status"] == "OK" and healthy["alert_triggered"] is False

    drifted = DriftDetector()
    for row in benign_baseline_matrix(400, seed=5):
        row = row.copy()
        row[0] += 2.0   # outbound ratio shifts far up
        row[2] += 2.5   # entropy rises
        drifted.record_feature_vector(row)
    report = drifted.evaluate_feature_drift()
    assert report["alert_triggered"] is True and report["data_drift_detected"] is True
    assert report["worst_feature"] in ("log_bytes_out_in_ratio", "payload_entropy")


def test_model_registry_describes_what_runs_and_measures_it():
    from src.evaluation.benchmark import benchmark_cache
    benchmark_cache.wait()
    models = model_registry.get_production_models()
    assert len(models) == 3
    names = " ".join(m.algorithm for m in models)
    assert "Isolation" in names and "PCA" in names and "not a neural network" in names  # no VAE or GNN claims
    for m in models:
        assert m.status == "PRODUCTION"
        assert m.pr_auc is not None and 0.0 < m.pr_auc <= 1.0
        assert "benchmark" in m.metrics_source


def test_retraining_is_recorded_and_honest_about_dispatch():
    from src.mlops.retraining_trigger import AutomatedRetrainingController

    controller = AutomatedRetrainingController()
    job = controller.check_and_trigger(force=True, requested_by="admin_user")
    assert job["triggered"] is True and job["requested_by"] == "admin_user"
    assert job["status"] == "REQUESTED_NO_BACKEND_CONFIGURED"  # nothing was dispatched, and it says so
    assert len(controller.get_history()) == 1

    class Backend:
        def submit(self, job):
            return {"run_id": "r-1"}

    controller.register_backend(Backend())
    job = controller.check_and_trigger(force=True)
    assert job["status"] == "DISPATCHED" and job["backend_result"] == {"run_id": "r-1"}

    class Broken:
        def submit(self, job):
            raise RuntimeError("down")

    controller.register_backend(Broken())
    assert controller.check_and_trigger(force=True)["status"] == "DISPATCH_FAILED"
    assert controller.check_and_trigger()["status"] == "IDLE"  # no drift, not forced
