"""Unsupervised Isolation Forest Spatial Outlier Model.

Partitions high-dimensional tabular NetFlow and database access features to
identify multi-dimensional outliers in wire-speed event streams.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from src.core.models import FeatureVector
from src.core.baseline import benign_baseline_matrix, feature_array


class TabularIsolationForestModel:
    """Unsupervised spatial outlier detector using Isolation Forest."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=1,  # per-event scoring is tiny: a process-wide thread pool only adds latency
        )
        self.random_state = random_state
        self.is_fitted = False
        self._boundary = 0.0
        self._scale = 0.1
        self._fit_initial_baseline()

    def _feature_vector_to_array(self, fv: FeatureVector) -> np.ndarray:
        """Converts FeatureVector into numeric vector."""
        return feature_array(fv).astype(np.float32).reshape(1, -1)

    def _fit_initial_baseline(self):
        """Fits model on synthetic benign banking telemetry baseline."""
        X_baseline = benign_baseline_matrix(500, self.random_state)
        self.fit(X_baseline)

    def fit(self, X: np.ndarray) -> None:
        """Fits the forest and records where the benign boundary lies so scores are calibrated against it."""
        self.model.fit(X)
        raw = self.model.decision_function(X)
        self._boundary = float(np.percentile(raw, 1))  # the 1st percentile of benign data is the edge of normal
        self._scale = float(max(raw.std() * 0.5, 0.02))
        self.is_fitted = True

    def score_feature_vector(self, fv: FeatureVector) -> float:
        """Scores a feature vector. Returns normalized anomaly score in [0.0 - 1.0].

        Higher score = more anomalous.
        """
        X = self._feature_vector_to_array(fv)
        raw_score = float(self.model.decision_function(X)[0])
        # 0.5 at the benign boundary, falling toward 0 for typical benign points and rising toward 1 for outliers
        normalized = 1.0 / (1.0 + np.exp((raw_score - self._boundary) / self._scale))
        return round(float(np.clip(normalized, 0.0, 1.0)), 4)


# Global Isolation Forest model
isolation_forest_model = TabularIsolationForestModel()
