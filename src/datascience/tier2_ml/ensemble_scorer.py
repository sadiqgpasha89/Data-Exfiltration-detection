"""Calibrated Risk Scorer Ensemble.

Ensembles:
1. Tabular Isolation Forest score (spatial NetFlow & DB outlier)
2. Variational Autoencoder reconstruction loss (temporal sequence/behavior deviation)
3. Graph Entitlement & Resignation deviation score (privilege hop / insider risk)

Computes calibrated Risk Score S in [0.0, 1.0].
Dispatches to Layer 3 Multi-Agent Swarm when S >= tau (default 0.65).
"""

from src.core.config import settings
from src.core.models import FeatureVector, Layer2Evaluation, TelemetryEvent
from src.core.telemetry import TelemetryTimer
from src.datascience.tier2_ml.graph_anomaly import graph_anomaly_scorer
from src.datascience.tier2_ml.isolation_forest import isolation_forest_model
from src.datascience.tier2_ml.vae_reconstruction import vae_reconstruction_model


class Tier2EnsembleScorer:
    """Ensemble anomaly detection pipeline deployed on GCP (GKE Triton simulation)."""

    def __init__(
        self,
        tau_threshold: float = None,
        w_if: float = 0.35,
        w_vae: float = 0.35,
        w_graph: float = 0.30,
    ):
        self.tau_threshold = tau_threshold or settings.ANOMALY_DISPATCH_THRESHOLD_TAU
        self.w_if = w_if
        self.w_vae = w_vae
        self.w_graph = w_graph
        self.isolation_forest = isolation_forest_model
        self.vae = vae_reconstruction_model
        self.graph_scorer = graph_anomaly_scorer

    def evaluate(self, event: TelemetryEvent, fv: FeatureVector) -> Layer2Evaluation:
        with TelemetryTimer("layer2_ml_inference") as timer:
            # 1. Isolation Forest score
            if_score = self.isolation_forest.score_feature_vector(fv)

            # 2. VAE Reconstruction loss
            vae_loss = self.vae.compute_reconstruction_loss(fv)

            # 3. Graph Entitlement score
            graph_score = self.graph_scorer.score_event(event, fv)

            # 4. Weighted Ensemble
            raw_ensemble = (self.w_if * if_score) + (self.w_vae * vae_loss) + (self.w_graph * graph_score)

            # 5. Non-linear calibration: if any single model reports severe anomaly (>0.85), escalate
            if max(if_score, vae_loss, graph_score) >= 0.85:
                ensemble_score = max(raw_ensemble, 0.75)
            else:
                ensemble_score = raw_ensemble

            ensemble_score = round(float(min(1.0, max(0.0, ensemble_score))), 4)
            requires_dispatch = ensemble_score >= self.tau_threshold

        return Layer2Evaluation(
            event_id=event.event_id,
            isolation_forest_score=if_score,
            vae_reconstruction_loss=vae_loss,
            graph_entitlement_deviation=graph_score,
            ensemble_risk_score=ensemble_score,
            requires_agentic_dispatch=requires_dispatch,
            evaluation_latency_ms=round(timer.elapsed_ms, 3),
        )


# Global Tier 2 ensemble scorer
tier2_scorer = Tier2EnsembleScorer()
