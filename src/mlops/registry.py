"""MLOps Model Registry: what is deployed, and how well it measurably does.

The registry describes the models that actually run (not the ones a design document proposes) and takes their quality
figures from the labelled benchmark rather than from literals. Until the first benchmark run completes the metrics are
None.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.evaluation.benchmark import benchmark_cache


class ModelMetadata(BaseModel):
    model_id: str
    model_name: str
    version: str
    algorithm: str
    framework: str
    pr_auc: Optional[float] = None
    roc_auc: Optional[float] = None
    f1_score: Optional[float] = None
    fpr_at_95_tpr: Optional[float] = None
    metrics_source: str = "not yet evaluated"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "PRODUCTION"  # "PRODUCTION", "SHADOW", "ARCHIVED"
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)


# registry id -> key in the benchmark's by_model report
BENCHMARK_KEYS = {
    "mdl-iso-forest-v1": "isolation_forest",
    "mdl-pca-autoencoder-v1": "autoencoder",
    "mdl-iam-entitlement-v1": "graph_entitlement",
}


class ModelRegistry:
    """Manages the deployed models and their measured quality."""

    def __init__(self):
        self.models: Dict[str, ModelMetadata] = {}
        self._register_default_models()

    def _register_default_models(self):
        self.register_model(ModelMetadata(
            model_id="mdl-iso-forest-v1", model_name="Tabular Isolation Forest", version="1.0.0",
            algorithm="IsolationForest", framework="scikit-learn",
            hyperparameters={"n_estimators": 100, "contamination": 0.05, "training_data": "synthetic benign baseline"},
        ))
        self.register_model(ModelMetadata(
            model_id="mdl-pca-autoencoder-v1", model_name="PCA Bottleneck Autoencoder", version="1.0.0",
            algorithm="Linear PCA autoencoder (reconstruction error, log-calibrated)", framework="NumPy",
            hyperparameters={"latent_dim": 3, "training_data": "synthetic benign baseline"},
        ))
        self.register_model(ModelMetadata(
            model_id="mdl-iam-entitlement-v1", model_name="IAM Entitlement Graph Scorer", version="1.0.0",
            algorithm="Shortest-path entitlement deviation with HR and privilege signals (not a neural network)", framework="NetworkX",
            hyperparameters={"signals": ["entitlement path", "resignation", "privileged hop"]},
        ))

    def register_model(self, model_meta: ModelMetadata):
        self.models[model_meta.model_id] = model_meta

    def _refresh_metrics(self) -> None:
        report = benchmark_cache.get()
        if report.get("status") != "ready":
            return
        for model_id, key in BENCHMARK_KEYS.items():
            model = self.models.get(model_id)
            if model:
                model.pr_auc = report["by_model"][key]["pr_auc"]
                model.roc_auc = report["by_model"][key]["roc_auc"]
                model.metrics_source = f"synthetic labelled benchmark, {report['evaluated_at']}"

    def get_production_models(self) -> List[ModelMetadata]:
        self._refresh_metrics()
        return [m for m in self.models.values() if m.status == "PRODUCTION"]

    def get_model(self, model_id: str) -> Optional[ModelMetadata]:
        self._refresh_metrics()
        return self.models.get(model_id)


# Global model registry
model_registry = ModelRegistry()
