"""Exact Data Match (EDM) Engine.

Calculates cryptographic hashes of proprietary banking tables and assets
using a distributed bloom filter index for sub-millisecond memory-mapped lookups.
"""

import hashlib
import json
from typing import Optional, Set
from src.core.config import settings


class BloomFilter:
    """Lightweight in-memory Bloom filter for sub-millisecond EDM matching."""

    def __init__(self, size: int = 100000, num_hashes: int = 5):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = [0] * size

    def _hashes(self, item: str):
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.sha1(item.encode()).hexdigest(), 16)
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.size

    def add(self, item: str):
        for pos in self._hashes(item):
            self.bit_array[pos] = 1

    def contains(self, item: str) -> bool:
        return all(self.bit_array[pos] == 1 for pos in self._hashes(item))


class ExactDataMatcher:
    """Matches file hashes and structured ledger entries against proprietary assets."""

    def __init__(self):
        self.bloom_filter = BloomFilter()
        self.exact_hashes: Set[str] = set()
        self._load_proprietary_hashes()

    def _load_proprietary_hashes(self):
        path = settings.THREAT_INTEL_IOCS_PATH
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for h in data.get("proprietary_file_hashes_sha256", []):
                    self.exact_hashes.add(h)
                    self.bloom_filter.add(h)

    def is_exact_match(self, file_hash_sha256: Optional[str]) -> bool:
        """Evaluates whether the hash matches proprietary banking assets."""
        if not file_hash_sha256:
            return False
        # Fast path: Bloom filter check
        if not self.bloom_filter.contains(file_hash_sha256):
            return False
        # Exact set verification to eliminate Bloom filter false positives
        return file_hash_sha256 in self.exact_hashes

    def register_proprietary_hash(self, file_hash: str):
        self.exact_hashes.add(file_hash)
        self.bloom_filter.add(file_hash)


# Global EDM matcher
edm_matcher = ExactDataMatcher()
