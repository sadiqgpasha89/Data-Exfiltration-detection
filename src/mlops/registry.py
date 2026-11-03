"""MLOps Model Registry: Versioning, Signatures, and Artifact Metadata."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ModelMetadata(BaseModel):
    model_id: str
    model_name: str
    version: str
    algorithm: str
    framework: str
    pr_auc: float
    f1_score: float
    fpr_at_95_tpr: float
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "PRODUCTION"  # "PRODUCTION", "SHADOW", "ARCHIVED"
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)


class ModelRegistry:
    """Manages active and shadow ML models across OpenStack edge and GCP."""

    def __init__(self):
        self.models: Dict[str, ModelMetadata] = {}
        self._register_default_models()

    def _register_default_models(self):
        self.register_model(
            ModelMetadata(
                model_id="mdl-iso-forest-v1.4",
                model_name="NetFlow Spatial Outlier Isolation Forest",
                version="1.4.2",
                algorithm="IsolationForest",
                framework="scikit-learn 1.4",
                pr_auc=0.962,
                f1_score=0.941,
                fpr_at_95_tpr=0.0008,
                status="PRODUCTION",
                hyperparameters={"n_estimators": 100, "contamination": 0.05},
            )
        )
        self.register_model(
            ModelMetadata(
                model_id="mdl-vae-reconstruction-v2.1",
                model_name="Banking Telemetry VAE Reconstruction Loss",
                version="2.1.0",
                algorithm="VariationalAutoencoder",
                framework="PyTorch / Vertex AI",
                pr_auc=0.974,
                f1_score=0.956,
                fpr_at_95_tpr=0.0006,
                status="PRODUCTION",
                hyperparameters={"latent_dim": 3, "bottleneck": "ReLU"},
            )
        )
        self.register_model(
            ModelMetadata(
                model_id="mdl-gnn-entitlement-v1.2",
                model_name="IAM Entitlement Graph Convolutional Scorer",
                version="1.2.0",
                algorithm="GraphConvolutionalNetwork",
                framework="NetworkX / DGL",
                pr_auc=0.951,
                f1_score=0.932,
                fpr_at_95_tpr=0.0009,
                status="PRODUCTION",
                hyperparameters={"hop_depth": 3},
            )
        )

    def register_model(self, model_meta: ModelMetadata):
        self.models[model_meta.model_id] = model_meta

    def get_production_models(self) -> List[ModelMetadata]:
        return [m for m in self.models.values() if m.status == "PRODUCTION"]

    def get_model(self, model_id: str) -> Optional[ModelMetadata]:
        return self.models.get(model_id)


# Global model registry
model_registry = ModelRegistry()
