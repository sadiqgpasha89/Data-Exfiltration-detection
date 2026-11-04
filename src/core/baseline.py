"""The benign-traffic distribution the anomaly models are fitted on, and that drift monitoring compares against.

One definition, used by the Isolation Forest, the autoencoder and the drift detector, so "what normal looks like" cannot
silently differ between them. It is a synthetic stand-in: fit the models on real benign telemetry with `fit()` before
relying on their scores in production.
"""

import numpy as np

from src.core.models import FeatureVector

FEATURE_NAMES = [
    "log_bytes_out_in_ratio",
    "connection_frequency_15m",
    "payload_entropy",
    "historical_deviation_score",
    "destination_cardinality_1h",
    "rolling_read_to_export_ratio_180d",
    "is_off_hours",
    "privileged_role_hop",
]


def benign_baseline_matrix(n: int = 500, seed: int = 42) -> np.ndarray:
    """An (n, 8) matrix of benign feature vectors drawn with a local generator (the process-wide RNG is never touched)."""
    rng = np.random.default_rng(seed)
    return np.column_stack([
        np.clip(rng.normal(1.2, 0.4, n), 0, 10),
        rng.poisson(3, n),
        np.clip(rng.normal(4.0, 0.6, n), 0, 8),
        np.clip(rng.beta(1, 8, n), 0, 1),
        rng.poisson(2, n),
        np.clip(rng.normal(22.0, 3.0, n), 0, 100),
        rng.binomial(1, 0.03, n),
        np.zeros(n),
    ])


def feature_array(fv: FeatureVector) -> np.ndarray:
    """The model input for one feature vector, in FEATURE_NAMES order."""
    return np.array([
        float(np.log1p(max(0.0, fv.bytes_out_in_ratio))),
        float(fv.connection_frequency_15m),
        float(fv.payload_entropy),
        float(fv.historical_deviation_score),
        float(fv.destination_cardinality_1h),
        float(fv.rolling_read_to_export_ratio_180d),
        1.0 if fv.is_off_hours else 0.0,
        1.0 if fv.privileged_role_hop else 0.0,
    ], dtype=np.float64)
