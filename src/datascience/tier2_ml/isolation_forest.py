"""Unsupervised Isolation Forest Spatial Outlier Model.

Partitions high-dimensional tabular NetFlow and database access features to
identify multi-dimensional outliers in wire-speed event streams.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from src.core.models import FeatureVector


class TabularIsolationForestModel:
    """Unsupervised spatial outlier detector using Isolation Forest."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.is_fitted = False
        self._fit_initial_baseline()

    def _feature_vector_to_array(self, fv: FeatureVector) -> np.ndarray:
        """Converts FeatureVector into numeric vector."""
        return np.array([
            math_log_ratio := float(np.log1p(max(0.0, fv.bytes_out_in_ratio))),
            float(fv.connection_frequency_15m),
            float(fv.payload_entropy),
            float(fv.historical_deviation_score),
            float(fv.destination_cardinality_1h),
            float(fv.rolling_read_to_export_ratio_180d),
            1.0 if fv.is_off_hours else 0.0,
            1.0 if fv.privileged_role_hop else 0.0,
        ], dtype=np.float32).reshape(1, -1)

    def _fit_initial_baseline(self):
        """Fits model on synthetic benign banking telemetry baseline."""
        np.random.seed(42)
        n_samples = 500
        # Normal baseline features:
        # low log ratio, low conn freq, low entropy, low deviation, 1-2 destinations, high read/export ratio, standard hours, no priv hop
        log_ratios = np.random.normal(loc=1.5, scale=0.5, size=n_samples)
        conn_freqs = np.random.poisson(lam=3, size=n_samples)
        entropies = np.random.normal(loc=4.0, scale=0.8, size=n_samples)
        dev_scores = np.random.beta(a=1, b=5, size=n_samples)
        dest_cards = np.random.poisson(lam=2, size=n_samples)
        read_exp_ratios = np.random.normal(loc=20.0, scale=3.0, size=n_samples)
        off_hours = np.random.binomial(n=1, p=0.05, size=n_samples)
        priv_hops = np.zeros(n_samples)

        X_baseline = np.column_stack([
            np.clip(log_ratios, 0, 10),
            conn_freqs,
            np.clip(entropies, 0, 8),
            np.clip(dev_scores, 0, 1),
            dest_cards,
            np.clip(read_exp_ratios, 0, 100),
            off_hours,
            priv_hops,
        ])
        self.model.fit(X_baseline)
        self.is_fitted = True

    def score_feature_vector(self, fv: FeatureVector) -> float:
        """Scores a feature vector. Returns normalized anomaly score in [0.0 - 1.0].

        Higher score = more anomalous.
        """
        X = self._feature_vector_to_array(fv)
        # raw decision function: negative values indicate outliers, positive indicate inliers
        raw_score = self.model.decision_function(X)[0]
        # Normalize into [0.0, 1.0] using sigmoid-like scaling
        # In scikit-learn, typical decision_function range is [-0.5, 0.5]
        normalized_score = 1.0 / (1.0 + np.exp(6.0 * raw_score))
        return round(float(np.clip(normalized_score, 0.0, 1.0)), 4)


# Global Isolation Forest model
isolation_forest_model = TabularIsolationForestModel()
