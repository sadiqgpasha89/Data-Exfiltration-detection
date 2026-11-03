"""Steganography and High-Entropy Payload Detector.

Applies:
1. Shannon Entropy calculations (> 7.5 indicates encrypted or compressed payload)
2. Chi-Square statistical goodness-of-fit test for byte/pixel randomness distribution
   (identifies Least Significant Bit [LSB] image steganography).
"""

import collections
import math
from typing import Optional, Tuple
from scipy import stats
from src.core.config import settings


class SteganographyDetector:
    """Analyzes media and byte streams for concealed steganographic payloads."""

    def __init__(self, entropy_threshold: float = None, chi_square_critical: float = 200.0):
        self.entropy_threshold = entropy_threshold or settings.ENTROPY_THRESHOLD
        self.chi_square_critical = chi_square_critical

    def calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculates Shannon entropy of raw bytes [0.0 - 8.0]."""
        if not data:
            return 0.0
        length = len(data)
        counts = collections.Counter(data)
        entropy = 0.0
        for count in counts.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(min(8.0, entropy), 3)

    def compute_chi_square_randomness(self, data: bytes) -> float:
        """Computes Chi-Square statistic on byte frequency distribution.

        Benign natural images have distinct byte frequency patterns.
        LSB-embedded stego data artificially flattens or uniformly randomizes bit pairs,
        causing Chi-square statistic to deviate significantly.
        """
        if len(data) < 256:
            return 0.0

        observed = [0] * 256
        for b in data:
            observed[b] += 1

        expected = len(data) / 256.0
        chi_square, _ = stats.chisquare(f_obs=observed, f_exp=[expected] * 256)
        return round(float(chi_square), 2)

    def evaluate_payload(
        self,
        raw_bytes: Optional[bytes] = None,
        entropy_score: Optional[float] = None,
        chi_square_score: Optional[float] = None,
        file_name: Optional[str] = None,
    ) -> Tuple[bool, float, float, str]:
        """Evaluates payload for steganography or nested encryption.

        Returns (is_suspicious, entropy, chi_square, reason).
        """
        entropy = entropy_score or 0.0
        chi_sq = chi_square_score or 0.0

        if raw_bytes:
            entropy = self.calculate_shannon_entropy(raw_bytes)
            chi_sq = self.compute_chi_square_randomness(raw_bytes)

        is_media_file = False
        if file_name:
            lower = file_name.lower()
            if any(lower.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".bmp", ".pdf"]):
                is_media_file = True

        # Stego detection condition:
        # High entropy (>7.5) combined with media file or elevated chi-square
        if is_media_file and (entropy > 7.7 or chi_sq > self.chi_square_critical):
            return True, entropy, chi_sq, f"Suspicious media file '{file_name}': LSB steganography indicated (Entropy: {entropy}, Chi-Sq: {chi_sq})"

        if entropy > self.entropy_threshold:
            return True, entropy, chi_sq, f"High payload entropy ({entropy} > {self.entropy_threshold}): Encrypted/Compressed egress detected"

        return False, entropy, chi_sq, "Payload within normal entropy distributions"


# Global steganography detector
stego_detector = SteganographyDetector()
