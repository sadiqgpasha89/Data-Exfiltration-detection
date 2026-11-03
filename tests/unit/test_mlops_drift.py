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


def test_model_registry_metadata():
    models = model_registry.get_production_models()
    assert len(models) >= 3
    for m in models:
        assert m.status == "PRODUCTION"
        assert m.pr_auc > 0.90


def test_retraining_trigger():
    initial_jobs = len(retraining_controller.get_history())
    job = retraining_controller.check_and_trigger(force=True)

    assert job["triggered"] is True
    assert job["status"] == "DISPATCHED_TO_VERTEX_PIPELINES"
    assert len(retraining_controller.get_history()) == initial_jobs + 1
