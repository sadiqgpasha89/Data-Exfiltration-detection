"""Regression gate on measured quality. A change that makes the stack worse on the labelled benchmark fails here.

The thresholds are floors under what the benchmark measured when they were set, with some headroom. They are a
regression check on synthetic data, not a claim about production performance.
"""

import pytest
from src.evaluation.benchmark import benchmark_cache, generate_dataset, run_benchmark


def test_dataset_is_deterministic_labelled_and_includes_hard_benign_cases():
    a, b = generate_dataset(seed=7), generate_dataset(seed=7)
    assert [(e.event_id, e.model_dump_json()) for e, _, _ in a] == [(e.event_id, e.model_dump_json()) for e, _, _ in b]
    assert len({e.event_id for e, _, _ in a}) == len(a)  # unique ids
    families = {f for _, _, f in a}
    assert {"benign_night_batch", "benign_compressed_download", "dns_tunnel", "burst_cloud_upload", "drip_exfiltration", "steganography",
            "insider_database_dump", "entitlement_abuse"} <= families
    assert sum(label for _, label, _ in a) == 120


@pytest.fixture(scope="module")
def report():
    result = benchmark_cache.wait()
    assert result["status"] == "ready"
    return result


def test_ensemble_quality_floor(report):
    ens = report["ensemble"]
    assert ens["pr_auc"] >= 0.80
    assert ens["roc_auc"] >= 0.95
    assert ens["recall_at_tau"] >= 0.85
    assert ens["precision_at_tau"] >= 0.70
    assert ens["fpr_at_tau"] <= 0.08
    assert ens["brier"] <= 0.15


def test_layer3_dispatch_catches_every_family(report):
    assert report["dispatch_to_layer3"]["recall"] >= 0.95
    assert report["dispatch_to_layer3"]["false_dispatch_rate"] <= 0.10
    for family, stats in report["per_family"].items():
        if not family.startswith("benign"):
            assert stats["dispatch_rate"] >= 0.9, family
    assert report["per_family"]["benign_routine"]["dispatch_rate"] <= 0.02


def test_each_model_contributes_signal(report):
    for name, scores in report["by_model"].items():
        assert scores["roc_auc"] >= 0.85, name


def test_benchmark_does_not_disturb_live_state():
    from src.data_engineering.feature_store import feature_store
    before = len(feature_store.user_windows), len(feature_store.feature_cache)
    run_benchmark(seed=11)
    assert (len(feature_store.user_windows), len(feature_store.feature_cache)) == before
