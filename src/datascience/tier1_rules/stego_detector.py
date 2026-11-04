"""Steganography and High-Entropy Payload Detector.

Applies:
1. Shannon entropy (> 7.5 bits per byte indicates encrypted or compressed content).
2. A chi-square goodness-of-fit test of the byte histogram against the uniform distribution.

How the chi-square statistic is read matters. For 256 byte values the statistic of a uniformly random stream sits near
its 255 degrees of freedom (about 255 +/- 23). Natural data (text, bitmaps, structured files) is far from uniform and
produces a statistic in the thousands or millions. So a LARGE statistic means "structured, not random", and a statistic
close to 255 means "indistinguishable from random". An earlier version flagged any statistic above 200, which flagged
every structured file and, by the same test, missed nothing it should have: it was checking the wrong tail.

Limits, stated plainly: this works on the bytes it is given. Compressed media (PNG, JPEG, PDF) is close to uniform by
construction, so a random-looking media file is a reason to inspect it, not proof of hidden content. Detecting LSB
steganography reliably needs the decoded pixels, which this edge layer does not have.
"""

import math
from typing import Optional, Tuple

import numpy as np
from scipy import stats

from src.core.config import settings

MEDIA_EXTENSIONS = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".pdf")
MAX_ANALYZED_BYTES = 1_000_000


class SteganographyDetector:
    """Analyzes media and byte streams for concealed steganographic payloads."""

    DEGREES_OF_FREEDOM = 255

    def __init__(self, entropy_threshold: float = None, uniform_p_low: float = 0.01, uniform_p_high: float = 0.99,
                 min_media_bytes: int = 1_000_000):
        self.entropy_threshold = entropy_threshold or settings.ENTROPY_THRESHOLD
        self.uniform_p_low = uniform_p_low
        self.uniform_p_high = uniform_p_high
        self.min_media_bytes = min_media_bytes

    @staticmethod
    def _histogram(data: bytes) -> np.ndarray:
        return np.bincount(np.frombuffer(data[:MAX_ANALYZED_BYTES], dtype=np.uint8), minlength=256)

    def calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculates Shannon entropy of raw bytes [0.0 - 8.0]."""
        if not data:
            return 0.0
        counts = self._histogram(data)
        p = counts[counts > 0] / counts.sum()
        return round(float(min(8.0, -(p * np.log2(p)).sum())), 3)

    def compute_chi_square_randomness(self, data: bytes) -> float:
        """Chi-square statistic of the byte histogram against the uniform distribution (about 255 for random data)."""
        if len(data) < 256:
            return 0.0
        observed = self._histogram(data)
        expected = observed.sum() / 256.0
        return round(float(((observed - expected) ** 2 / expected).sum()), 2)

    def looks_uniformly_random(self, chi_square: float) -> bool:
        """True when the statistic is consistent with uniformly random bytes (neither too structured nor too flat)."""
        if chi_square <= 0.0:
            return False  # not measured
        p_value = float(stats.chi2.sf(chi_square, self.DEGREES_OF_FREEDOM))
        return self.uniform_p_low < p_value < self.uniform_p_high

    def evaluate_payload(
        self,
        raw_bytes: Optional[bytes] = None,
        entropy_score: Optional[float] = None,
        chi_square_score: Optional[float] = None,
        file_name: Optional[str] = None,
        size_bytes: Optional[int] = None,
    ) -> Tuple[bool, float, float, str]:
        """Evaluates a payload for steganography or nested encryption. Returns (is_suspicious, entropy, chi_square, reason)."""
        entropy = entropy_score or 0.0
        chi_sq = chi_square_score or 0.0

        if raw_bytes:
            entropy = self.calculate_shannon_entropy(raw_bytes)
            chi_sq = self.compute_chi_square_randomness(raw_bytes)

        is_media_file = bool(file_name) and file_name.lower().endswith(MEDIA_EXTENSIONS)
        large_enough = size_bytes is None or size_bytes >= self.min_media_bytes

        # A media file that is statistically indistinguishable from random noise, and large for what it claims to be.
        if is_media_file and large_enough and entropy > 7.7 and self.looks_uniformly_random(chi_sq):
            return True, entropy, chi_sq, (
                f"Suspicious media file '{file_name}': byte distribution indistinguishable from random "
                f"(entropy {entropy}, chi-square {chi_sq}); concealed or encrypted content indicated"
            )

        if entropy > self.entropy_threshold:
            return True, entropy, chi_sq, f"High payload entropy ({entropy} > {self.entropy_threshold}): Encrypted/Compressed egress detected"

        return False, entropy, chi_sq, "Payload within normal entropy distributions"


# Global steganography detector
stego_detector = SteganographyDetector()
