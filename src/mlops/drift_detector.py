"""MLOps Drift Detection Engine: PSI, Wasserstein and KS tests on the live feature stream.

The detector keeps a bounded window of the feature vectors the pipeline actually produced and compares each feature to
the benign baseline the models were fitted on. With too few samples it says so (`INSUFFICIENT_DATA`) instead of
inventing a healthy-looking window, which an earlier version did by drawing a random "production" sample.
"""

import collections
import threading
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from scipy import stats

from src.core.config import settings
from src.core.baseline import FEATURE_NAMES, benign_baseline_matrix

# Features with continuous distributions, where PSI and Wasserstein are meaningful. Binary flags are reported by rate.
CONTINUOUS = [0, 1, 2, 3, 4, 5]


class DriftDetector:
    """Calculates drift metrics between the benign baseline and the live window."""

    def __init__(self, psi_threshold: float = None, baseline: Optional[np.ndarray] = None):
        self.psi_threshold = psi_threshold or settings.PSI_DRIFT_THRESHOLD
        self.baseline_matrix = baseline if baseline is not None else benign_baseline_matrix(2000, seed=42)
        self.baseline_feature_dist = self.baseline_matrix[:, 0]  # kept for callers that compare a single distribution
        self._lock = threading.Lock()
        self._window: "collections.deque[np.ndarray]" = collections.deque(maxlen=settings.DRIFT_WINDOW_SIZE)

    def record_feature_vector(self, vector: np.ndarray) -> None:
        with self._lock:
            self._window.append(np.asarray(vector, dtype=float))

    def calculate_psi(self, baseline: np.ndarray, current: np.ndarray, num_bins: int = 10) -> float:
        """Population Stability Index: PSI = sum((P_i - Q_i) * ln(P_i / Q_i)) over baseline-quantile bins.

        PSI < 0.10 no significant shift; 0.10 to 0.25 moderate; above 0.25 severe (action required).
        """
        bins = np.unique(np.percentile(baseline, np.linspace(0, 100, num_bins + 1)))
        if len(bins) < 3:  # a (near-)constant baseline cannot be binned
            return 0.0
        bins[0], bins[-1] = -np.inf, np.inf
        baseline_counts, _ = np.histogram(baseline, bins=bins)
        current_counts, _ = np.histogram(current, bins=bins)
        eps = 1e-4
        p = (baseline_counts + eps) / (len(baseline) + eps * len(baseline_counts))
        q = (current_counts + eps) / (len(current) + eps * len(current_counts))
        return round(float(np.sum((p - q) * np.log(p / q))), 4)

    def calculate_wasserstein_distance(self, baseline: np.ndarray, current: np.ndarray) -> float:
        """First Wasserstein distance (earth mover's distance)."""
        return round(float(stats.wasserstein_distance(baseline, current)), 4)

    def evaluate_concept_drift_ks(self, baseline: np.ndarray, current: np.ndarray) -> Tuple[float, float, bool]:
        """Two-sample Kolmogorov-Smirnov test. Returns (statistic, p_value, drift_detected at p < 0.05)."""
        ks_stat, p_val = stats.ks_2samp(baseline, current)
        return round(float(ks_stat), 4), round(float(p_val), 5), bool(p_val < 0.05)

    def evaluate_feature_drift(self, current_features: List[float] = None) -> Dict[str, Any]:
        """Full drift evaluation. With `current_features` it compares that single series (first feature) to the baseline;
        otherwise it uses the live window of all features."""
        if current_features is not None:
            current = np.asarray(current_features, dtype=float)
            if len(current) < settings.DRIFT_MIN_SAMPLES:
                return self._insufficient(len(current))
            return self._single(current)

        with self._lock:
            window = np.array(self._window) if self._window else np.empty((0, len(FEATURE_NAMES)))
        if len(window) < settings.DRIFT_MIN_SAMPLES:
            return self._insufficient(len(window))

        per_feature: Dict[str, Dict[str, Any]] = {}
        for idx in CONTINUOUS:
            base, cur = self.baseline_matrix[:, idx], window[:, idx]
            psi = self.calculate_psi(base, cur)
            ks_stat, p_val, ks_drift = self.evaluate_concept_drift_ks(base, cur)
            per_feature[FEATURE_NAMES[idx]] = {
                "psi": psi, "wasserstein": self.calculate_wasserstein_distance(base, cur),
                "ks_statistic": ks_stat, "ks_p_value": p_val, "drifted": bool(psi > self.psi_threshold),
            }
        worst = max(per_feature, key=lambda k: per_feature[k]["psi"])
        w = per_feature[worst]
        data_drift = any(f["drifted"] for f in per_feature.values())
        # at this sample size the KS test flags tiny shifts, so it only raises an alert together with a material PSI
        concept_drift = any(f["ks_p_value"] < 0.001 and f["psi"] > self.psi_threshold / 2 for f in per_feature.values())
        alert = data_drift or concept_drift
        return {
            "status": "OK",
            "samples": int(len(window)),
            "psi_score": w["psi"],
            "psi_threshold": self.psi_threshold,
            "worst_feature": worst,
            "wasserstein_distance": w["wasserstein"],
            "ks_statistic": w["ks_statistic"],
            "ks_p_value": w["ks_p_value"],
            "data_drift_detected": data_drift,
            "concept_drift_detected": concept_drift,
            "alert_triggered": alert,
            "off_hours_rate": round(float(window[:, 6].mean()), 4),
            "privileged_hop_rate": round(float(window[:, 7].mean()), 4),
            "features": per_feature,
            "recommendation": "REVIEW_AND_RETRAIN_ON_APPROVED_BENIGN_DATA" if alert else "NORMAL_MODEL_OPERATION",
        }

    def _single(self, current: np.ndarray) -> Dict[str, Any]:
        base = self.baseline_feature_dist
        psi = self.calculate_psi(base, current)
        ks_stat, p_val, ks_drift = self.evaluate_concept_drift_ks(base, current)
        alert = psi > self.psi_threshold or ks_drift
        return {
            "status": "OK", "samples": int(len(current)), "psi_score": psi, "psi_threshold": self.psi_threshold,
            "wasserstein_distance": self.calculate_wasserstein_distance(base, current),
            "ks_statistic": ks_stat, "ks_p_value": p_val, "data_drift_detected": psi > self.psi_threshold,
            "concept_drift_detected": ks_drift, "alert_triggered": alert,
            "recommendation": "REVIEW_AND_RETRAIN_ON_APPROVED_BENIGN_DATA" if alert else "NORMAL_MODEL_OPERATION",
        }

    def _insufficient(self, have: int) -> Dict[str, Any]:
        return {
            "status": "INSUFFICIENT_DATA", "samples": have, "samples_needed": settings.DRIFT_MIN_SAMPLES,
            "psi_score": None, "psi_threshold": self.psi_threshold, "wasserstein_distance": None,
            "ks_statistic": None, "ks_p_value": None, "data_drift_detected": False, "concept_drift_detected": False,
            "alert_triggered": False, "recommendation": "COLLECTING_DATA",
        }


# Global drift detector
drift_detector = DriftDetector()
