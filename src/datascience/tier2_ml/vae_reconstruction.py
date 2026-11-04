"""PCA bottleneck autoencoder: reconstruction-error anomaly scorer.

Despite the historical file name this is not a variational autoencoder. It is a linear bottleneck (principal
components of benign telemetry) in NumPy: the features are standardized, projected onto `latent_dim` components and
reconstructed. Behaviour unlike the benign baseline reconstructs badly, and the reconstruction error is the signal.

Two defects of an earlier version are fixed here. The encoder applied a ReLU, which discards the sign of every latent
coordinate and inflated the error of ordinary benign traffic by about a third. And standardization divided by
(std + 1e-4): a feature that is constant in the baseline (the privileged-hop flag) turned a single 1 into a z-score of
10,000, so that one flag saturated the score at 1.0 regardless of everything else. Standard deviations are now floored
and z-scores are clipped.
"""

import numpy as np
from src.core.models import FeatureVector
from src.core.baseline import benign_baseline_matrix, feature_array

STD_FLOOR = 0.05
Z_CLIP = 8.0


class VAEReconstructionModel:
    """Linear bottleneck autoencoder (PCA) with an error score calibrated against its own training distribution."""

    def __init__(self, input_dim: int = 8, latent_dim: int = 3, random_state: int = 42):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.random_state = random_state
        self.mean = np.zeros(input_dim)
        self.std = np.ones(input_dim)
        self.W_enc = np.zeros((input_dim, latent_dim))
        self.W_dec = self.W_enc.T
        self._log_mse_mean = 0.0
        self._log_mse_std = 1.0
        self._fit_initial_baseline()

    def _standardize(self, X: np.ndarray) -> np.ndarray:
        return np.clip((X - self.mean) / self.std, -Z_CLIP, Z_CLIP)

    def fit(self, X: np.ndarray) -> None:
        """Learns the principal subspace of benign feature vectors and the error distribution used for calibration."""
        self.mean = X.mean(axis=0)
        self.std = np.maximum(X.std(axis=0), STD_FLOOR)
        Xn = self._standardize(X)
        _, _, vt = np.linalg.svd(Xn, full_matrices=False)
        self.W_enc = vt[: self.latent_dim, :].T
        self.W_dec = self.W_enc.T
        errors = np.mean((Xn - Xn @ self.W_enc @ self.W_dec) ** 2, axis=1)
        log_err = np.log(errors + 1e-9)
        self._log_mse_mean = float(log_err.mean())
        self._log_mse_std = float(max(log_err.std(), 1e-3))

    def _fit_initial_baseline(self):
        """Fits on a synthetic benign profile. Replace with real benign telemetry via fit() before relying on the scores."""
        X = benign_baseline_matrix(500, self.random_state)
        self.fit(X)

    def reconstruction_error(self, fv: FeatureVector) -> float:
        x = self._standardize(feature_array(fv))
        return float(np.mean((x - x @ self.W_enc @ self.W_dec) ** 2))

    def compute_reconstruction_loss(self, fv: FeatureVector) -> float:
        """Anomaly score in [0, 1]: the reconstruction error's distance from the benign error distribution, in log space.

        A benign vector scores near 0.07, a vector 2.5 standard deviations (log scale) above the benign mean scores 0.5.
        """
        z = (np.log(self.reconstruction_error(fv) + 1e-9) - self._log_mse_mean) / self._log_mse_std
        return round(float(1.0 / (1.0 + np.exp(-(z - 2.5)))), 4)


# Global model
vae_reconstruction_model = VAEReconstructionModel()
