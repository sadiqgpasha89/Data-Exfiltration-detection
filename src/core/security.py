"""API authentication, role-based authorization and rate limiting.

Callers present an API key (`X-API-Key: <key>` or `Authorization: Bearer <key>`). Keys come from the `API_KEYS`
setting as `name:role:key` entries. The server only ever compares SHA-256 digests, in constant time, and it derives
the acting identity from the key. A request body can never claim to be a different analyst, which matters because the
anti-collusion audit is only as good as the identity it records.
"""

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple

from fastapi import Depends, HTTPException, Request

from src.core.config import settings

PERMISSIONS: Dict[str, FrozenSet[str]] = {
    "viewer": frozenset({"read"}),
    "ingest": frozenset({"ingest"}),
    "analyst": frozenset({"read", "ingest", "adjudicate", "contain"}),
    "admin": frozenset({"read", "ingest", "adjudicate", "contain", "admin", "simulate"}),
}


@dataclass(frozen=True)
class Principal:
    name: str
    role: str

    def can(self, permission: str) -> bool:
        return permission in PERMISSIONS.get(self.role, frozenset())


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def parse_api_keys(raw: str) -> List[Tuple[str, str, bytes]]:
    """Parses `name:role:key,name2:role:key` into (name, role, sha256(key)). Raises ValueError on bad input."""
    entries: List[Tuple[str, str, bytes]] = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":", 2)
        if len(parts) != 3 or not all(parts):
            raise ValueError("API_KEYS entries must look like name:role:key")
        name, role, key = parts
        if role not in PERMISSIONS:
            raise ValueError(f"unknown role '{role}' in API_KEYS (use {', '.join(PERMISSIONS)})")
        if len(key) < 16:
            raise ValueError(f"API key for '{name}' is shorter than 16 characters")
        entries.append((name, role, _digest(key)))
    return entries


def authenticate_key(presented: Optional[str]) -> Optional[Principal]:
    if not presented:
        return None
    presented_digest = _digest(presented)
    match: Optional[Principal] = None
    for name, role, digest in parse_api_keys(settings.API_KEYS):
        if hmac.compare_digest(digest, presented_digest):  # no early exit: comparison time does not depend on the match
            match = Principal(name=name, role=role)
    return match


def _presented_key(request: Request) -> Optional[str]:
    header = request.headers.get("x-api-key")
    if header:
        return header.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


# ---- rate limiting --------------------------------------------------------------------------------------
class TokenBucketLimiter:
    """Thread-safe token bucket per key. Bounded memory: stale buckets are pruned."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, per_minute: int) -> Tuple[bool, float]:
        if per_minute <= 0:
            return True, 0.0
        capacity, rate = float(per_minute), per_minute / 60.0
        with self._lock:
            now = self._clock()
            tokens, last = self._buckets.get(key, (capacity, now))
            tokens = min(capacity, tokens + (now - last) * rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                allowed, retry = True, 0.0
            else:
                self._buckets[key] = (tokens, now)
                allowed, retry = False, (1.0 - tokens) / rate
            if len(self._buckets) > 20_000:
                full = [k for k, (t, ts) in self._buckets.items() if t + (now - ts) * rate >= capacity]
                for k in full:
                    del self._buckets[k]
            return allowed, retry


rate_limiter = TokenBucketLimiter()


def get_principal(request: Request) -> Principal:
    """Authenticates the caller, applies the rate limit and returns who they are."""
    if settings.AUTH_DISABLED and not settings.is_production:
        principal = Principal(name="dev", role="admin")
    else:
        try:
            principal = authenticate_key(_presented_key(request))
        except ValueError:  # misconfigured API_KEYS: fail closed, and do not echo the configuration
            raise HTTPException(status_code=503, detail="Authentication is not configured")
        if principal is None:
            raise HTTPException(status_code=401, detail="Missing or invalid API key", headers={"WWW-Authenticate": "Bearer"})
    allowed, retry_after = rate_limiter.hit(principal.name, settings.RATE_LIMIT_PER_MINUTE)
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": str(int(retry_after) + 1)})
    return principal


def require(permission: str):
    """FastAPI dependency factory: `Depends(require("adjudicate"))`."""

    def checker(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.can(permission):
            raise HTTPException(status_code=403, detail=f"Role '{principal.role}' lacks the '{permission}' permission")
        return principal

    return checker
