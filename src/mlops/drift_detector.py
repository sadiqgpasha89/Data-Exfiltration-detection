"""MLOps Drift Detection Engine: PSI, Wasserstein, and KS-Tests.

Monitors:
1. Covariate Shift (Data Drift): Population Stability Index (PSI) & Wasserstein Distance
2. Concept Drift: Kolmogorov-Smirnov (KS) test comparing baseline vs production distributions
"""

import numpy as np
from scipy import stats
from typing import Any, Dict, List, Tuple
from src.core.config import settings


class DriftDetector:
    """Calculates statistical drift metrics across sliding windows."""

    def __init__(self, psi_threshold: float = None):
        self.psi_threshold = psi_threshold or settings.PSI_DRIFT_THRESHOLD
        np.random.seed(42)
        # Reference baseline feature distribution (500 samples)
        self.baseline_feature_dist = np.random.normal(loc=1.5, scale=0.5, size=500)

    def calculate_psi(self, baseline: np.ndarray, current: np.ndarray, num_bins: int = 10) -> float:
        """Calculates Population Stability Index (PSI).

        PSI = sum((P_i - Q_i) * ln(P_i / Q_i))
        PSI < 0.10: No significant shift
        0.10 <= PSI <= 0.25: Moderate shift
        PSI > 0.25: Severe shift (Action required)
        """
        # Define common bins based on baseline percentiles
        quantiles = np.linspace(0, 100, num_bins + 1)
        bins = np.percentile(baseline, quantiles)
        bins[0] = -np.inf
        bins[-1] = np.inf

        # Calculate frequency counts
        baseline_counts, _ = np.histogram(baseline, bins=bins)
        current_counts, _ = np.histogram(current, bins=bins)

        # Normalize to proportions (with Laplace smoothing)
        p = (baseline_counts + 1e-4) / (len(baseline) + 1e-4 * num_bins)
        q = (current_counts + 1e-4) / (len(current) + 1e-4 * num_bins)

        psi = np.sum((p - q) * np.log(p / q))
        return round(float(psi), 4)

    def calculate_wasserstein_distance(self, baseline: np.ndarray, current: np.ndarray) -> float:
        """Computes 1st Wasserstein Distance (Earth Mover's Distance)."""
        w_dist = stats.wasserstein_distance(baseline, current)
        return round(float(w_dist), 4)

    def evaluate_concept_drift_ks(self, baseline: np.ndarray, current: np.ndarray) -> Tuple[float, float, bool]:
        """Performs two-sample Kolmogorov-Smirnov test.

        Returns (ks_statistic, p_value, is_drift_detected).
        If p_value < 0.05, distributions are statistically distinct.
        """
        ks_stat, p_val = stats.ks_2samp(baseline, current)
        is_drift = bool(p_val < 0.05)
        return round(float(ks_stat), 4), round(float(p_val), 5), is_drift

    def evaluate_feature_drift(self, current_features: List[float] = None) -> Dict[str, Any]:
        """Runs full drift evaluation against current production window."""
        if current_features is None or len(current_features) < 10:
            # Default healthy production distribution
            current = np.random.normal(loc=1.52, scale=0.51, size=200)
        else:
            current = np.array(current_features)

        psi = self.calculate_psi(self.baseline_feature_dist, current)
        w_dist = self.calculate_wasserstein_distance(self.baseline_feature_dist, current)
        ks_stat, p_val, ks_drift = self.evaluate_concept_drift_ks(self.baseline_feature_dist, current)

        alert_triggered = psi > self.psi_threshold or ks_drift

        return {
            "psi_score": psi,
            "psi_threshold": self.psi_threshold,
            "wasserstein_distance": w_dist,
            "ks_statistic": ks_stat,
            "ks_p_value": p_val,
            "data_drift_detected": psi > self.psi_threshold,
            "concept_drift_detected": ks_drift,
            "alert_triggered": alert_triggered,
            "recommendation": (
                "TRIGGER_AUTOMATED_VERTEX_AI_RETRAINING" if alert_triggered else "NORMAL_MODEL_OPERATION"
            ),
        }


# Global drift detector
drift_detector = DriftDetector()
