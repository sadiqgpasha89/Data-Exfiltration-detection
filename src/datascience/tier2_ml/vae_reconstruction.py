"""Autoencoder / Variational Autoencoder Reconstruction Error Model.

Trained on benign network transaction and query profiles.
Calculates normalized reconstruction loss: L_reconstruction = ||x - x_hat||^2.
Elevated reconstruction error flags zero-day and uncharacteristic exfiltration profiles.
"""

import numpy as np
from src.core.models import FeatureVector


class VAEReconstructionModel:
    """Linear/bottleneck projection Autoencoder for continuous feature reconstruction."""

    def __init__(self, input_dim: int = 8, latent_dim: int = 3, random_state: int = 42):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        np.random.seed(random_state)

        # Initialize weights: Encoder (input -> latent) and Decoder (latent -> input)
        # Using orthonormal projection approximation
        self.W_enc = np.random.randn(input_dim, latent_dim) * 0.1
        self.b_enc = np.zeros(latent_dim)
        self.W_dec = self.W_enc.T
        self.b_dec = np.zeros(input_dim)

        self.mean = np.zeros(input_dim)
        self.std = np.ones(input_dim)
        self._fit_initial_baseline()

    def _feature_vector_to_array(self, fv: FeatureVector) -> np.ndarray:
        return np.array([
            float(np.log1p(max(0.0, fv.bytes_out_in_ratio))),
            float(fv.connection_frequency_15m),
            float(fv.payload_entropy),
            float(fv.historical_deviation_score),
            float(fv.destination_cardinality_1h),
            float(fv.rolling_read_to_export_ratio_180d),
            1.0 if fv.is_off_hours else 0.0,
            1.0 if fv.privileged_role_hop else 0.0,
        ], dtype=np.float32)

    def _fit_initial_baseline(self):
        """Simulates VAE baseline training on benign profiles using PCA-style reconstruction."""
        np.random.seed(42)
        n_samples = 500
        # Realistic benign distributions:
        # log_ratio: ~0.5 - 2.0
        # conn_freq: ~1 - 5
        # entropy: ~3.0 - 5.0
        # dev_score: ~0.0 - 0.2
        # dest_card: ~1 - 3
        # read_to_export: ~15.0 - 30.0
        # off_hours: ~0
        # priv_hop: ~0
        log_ratios = np.random.normal(loc=1.2, scale=0.4, size=n_samples)
        conn_freqs = np.random.poisson(lam=3, size=n_samples)
        entropies = np.random.normal(loc=4.0, scale=0.6, size=n_samples)
        dev_scores = np.random.beta(a=1, b=8, size=n_samples)
        dest_cards = np.random.poisson(lam=2, size=n_samples)
        read_exp_ratios = np.random.normal(loc=22.0, scale=3.0, size=n_samples)
        off_hours = np.random.binomial(n=1, p=0.03, size=n_samples)
        priv_hops = np.zeros(n_samples)

        X = np.column_stack([
            np.clip(log_ratios, 0, 10),
            conn_freqs,
            np.clip(entropies, 0, 8),
            np.clip(dev_scores, 0, 1),
            dest_cards,
            np.clip(read_exp_ratios, 0, 100),
            off_hours,
            priv_hops,
        ])

        self.mean = np.mean(X, axis=0)
        self.std = np.std(X, axis=0) + 1e-4

        # Standardize
        X_norm = (X - self.mean) / self.std

        # Learn encoder/decoder via SVD (Principal bottleneck)
        u, s, vt = np.linalg.svd(X_norm, full_matrices=False)
        self.W_enc = vt[:self.latent_dim, :].T  # input_dim x latent_dim
        self.W_dec = self.W_enc.T               # latent_dim x input_dim

    def compute_reconstruction_loss(self, fv: FeatureVector) -> float:
        """Computes normalized reconstruction error ||x - x_hat||^2 in [0.0 - 1.0]."""
        x_raw = self._feature_vector_to_array(fv)
        x_norm = (x_raw - self.mean) / self.std

        # Encode: z = ReLU(x * W_enc)
        z = np.maximum(0, np.dot(x_norm, self.W_enc))

        # Decode: x_hat = z * W_dec
        x_hat = np.dot(z, self.W_dec)

        # Reconstruction error: mean squared error
        mse = float(np.mean((x_norm - x_hat) ** 2))

        # Normalize via sigmoid scaling [0.0, 1.0]
        # For baseline, mse is ~0.1 - 0.5. For anomalous spikes, mse reaches 5.0 - 50.0.
        norm_loss = 1.0 - (1.0 / (1.0 + 0.5 * mse))
        return round(float(np.clip(norm_loss, 0.0, 1.0)), 4)


# Global VAE model
vae_reconstruction_model = VAEReconstructionModel()
