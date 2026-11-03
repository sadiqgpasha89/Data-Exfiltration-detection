"""Unit tests for Layer 2 Machine Learning Anomaly Detection Tier."""

import pytest
from src.core.models import FeatureVector, TelemetryEvent
from src.datascience.tier2_ml.ensemble_scorer import tier2_scorer
from src.datascience.tier2_ml.graph_anomaly import graph_anomaly_scorer
from src.datascience.tier2_ml.isolation_forest import isolation_forest_model
from src.datascience.tier2_ml.vae_reconstruction import vae_reconstruction_model


@pytest.fixture
def sample_feature_vectors():
    benign_fv = FeatureVector(
        event_id="evt-fv-benign",
        user_id="usr_retail_5512",
        bytes_out_in_ratio=1.2,
        connection_frequency_15m=2,
        payload_entropy=3.8,
        historical_deviation_score=0.05,
        destination_cardinality_1h=1,
        rolling_read_to_export_ratio_180d=25.0,
        is_off_hours=False,
        privileged_role_hop=False,
    )

    anomalous_fv = FeatureVector(
        event_id="evt-fv-anomaly",
        user_id="usr_dev_4091",
        bytes_out_in_ratio=5000.0,
        connection_frequency_15m=45,
        payload_entropy=7.92,
        historical_deviation_score=0.95,
        destination_cardinality_1h=12,
        rolling_read_to_export_ratio_180d=0.85,
        is_off_hours=True,
        privileged_role_hop=True,
    )
    return benign_fv, anomalous_fv


def test_isolation_forest_scoring(sample_feature_vectors):
    benign_fv, anomalous_fv = sample_feature_vectors

    score_benign = isolation_forest_model.score_feature_vector(benign_fv)
    score_anomaly = isolation_forest_model.score_feature_vector(anomalous_fv)

    assert 0.0 <= score_benign <= 1.0
    assert 0.0 <= score_anomaly <= 1.0
    assert score_anomaly > score_benign


def test_vae_reconstruction_loss(sample_feature_vectors):
    benign_fv, anomalous_fv = sample_feature_vectors

    loss_benign = vae_reconstruction_model.compute_reconstruction_loss(benign_fv)
    loss_anomaly = vae_reconstruction_model.compute_reconstruction_loss(anomalous_fv)

    assert 0.0 <= loss_benign <= 1.0
    assert 0.0 <= loss_anomaly <= 1.0
    assert loss_anomaly > loss_benign


def test_graph_anomaly_scoring(sample_feature_vectors, benign_event, dns_tunnel_event):
    benign_fv, anomalous_fv = sample_feature_vectors

    score_benign = graph_anomaly_scorer.score_event(benign_event, benign_fv)
    # dev_4091 has resigned, so should have significantly higher score
    score_anomaly = graph_anomaly_scorer.score_event(dns_tunnel_event, anomalous_fv)

    assert 0.0 <= score_benign <= 1.0
    assert 0.0 <= score_anomaly <= 1.0
    assert score_anomaly > score_benign


def test_ensemble_scorer_dispatch_decision(sample_feature_vectors, benign_event, dns_tunnel_event):
    benign_fv, anomalous_fv = sample_feature_vectors

    eval_benign = tier2_scorer.evaluate(benign_event, benign_fv)
    eval_anomaly = tier2_scorer.evaluate(dns_tunnel_event, anomalous_fv)

    assert eval_benign.requires_agentic_dispatch is False
    assert eval_anomaly.requires_agentic_dispatch is True
    assert eval_anomaly.ensemble_risk_score >= 0.65
