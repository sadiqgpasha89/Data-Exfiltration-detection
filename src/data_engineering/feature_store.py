"""Real-time Sliding-Window Feature Store.

Simulates GCP Dataflow stateful processing writing to Vertex AI Feature Store. Short-term features are computed over
true time windows (15 minutes, 1 hour, 24 hours) measured on the event's own timestamp, and a long-term read-to-export
counter tracks low-and-slow ('drip') exfiltration.

Memory is bounded: per-user event history is capped and evicted by age, users are evicted least-recently-used, and the
feature cache is a fixed-size LRU. All mutation is guarded by a lock because the API serves requests from a thread pool.
"""

import collections
import math
import threading
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Optional, Tuple

from src.core.config import settings
from src.core.models import FeatureVector, TelemetryEvent
from src.data_engineering.graph_builder import iam_graph_builder

WINDOW_15M = timedelta(minutes=15)
WINDOW_1H = timedelta(hours=1)
RETENTION = timedelta(hours=24)
BUSINESS_HOURS_UTC = (8, 19)  # [start, end): outside this, or on a weekend, counts as off hours
SUSPICIOUS_TOOLS = {"powershell.exe", "7z.exe", "pg_dump.exe"}
EXPORT_EVENT_TYPES = {"database_dump", "batch_export", "file_egress"}
NO_ENTITLEMENT = 0.6  # entitlement deviation at or above this means the user has no grant on the resource


def parse_timestamp(value: str) -> datetime:
    """Parses an ISO-8601 timestamp; a timestamp without a zone is read as UTC."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class StreamingFeatureStore:
    """Sliding-window temporal aggregator maintaining user state."""

    def __init__(self):
        self._lock = threading.RLock()
        # user_id -> (event time, destination ip) for the last 24h, most recent last
        self.user_windows: "collections.OrderedDict[str, Deque[Tuple[datetime, str]]]" = collections.OrderedDict()
        # user_id -> long-term rolling cumulative counters (records_read, records_exported, access_count)
        self.cumulative_drip_counters: Dict[str, Dict[str, float]] = collections.defaultdict(
            lambda: {"records_read": 100.0, "records_exported": 5.0, "access_count": 20}
        )
        self.feature_cache: "collections.OrderedDict[str, FeatureVector]" = collections.OrderedDict()

    # ---- helpers ------------------------------------------------------------------------------------------
    def calculate_shannon_entropy(self, payload: str) -> float:
        """Shannon entropy of a string buffer in bits per character. Above 7.5 strongly indicates encryption, compression or random hex."""
        if not payload:
            return 0.0
        length = len(payload)
        entropy = -sum((c / length) * math.log2(c / length) for c in collections.Counter(payload).values())
        return round(min(8.0, entropy), 3)

    def is_off_hours_access(self, timestamp_str: str) -> bool:
        """True on weekends and outside 08:00-19:00 UTC. A timestamp that cannot be parsed is treated as off hours (fail suspicious)."""
        try:
            dt = parse_timestamp(timestamp_str).astimezone(timezone.utc)
        except ValueError:
            return True
        return dt.weekday() >= 5 or not (BUSINESS_HOURS_UTC[0] <= dt.hour < BUSINESS_HOURS_UTC[1])

    def _window(self, user_id: str) -> Deque[Tuple[datetime, str]]:
        window = self.user_windows.get(user_id)
        if window is None:
            window = collections.deque(maxlen=settings.FEATURE_MAX_EVENTS_PER_USER)
            self.user_windows[user_id] = window
            while len(self.user_windows) > settings.FEATURE_MAX_USERS:
                evicted, _ = self.user_windows.popitem(last=False)
                self.cumulative_drip_counters.pop(evicted, None)
        else:
            self.user_windows.move_to_end(user_id)
        return window

    def _privileged_hop(self, event: TelemetryEvent, off_hours: bool) -> bool:
        """True when the event touches a resource the user holds no grant on, or runs staging tools off hours.

        Entitlements come from the IAM graph, not from a list of known bad users.
        """
        resource = iam_graph_builder.extract_resource(event.query)
        if resource and iam_graph_builder.compute_entitlement_deviation(event.user_id or "anonymous", resource) >= NO_ENTITLEMENT:
            return True
        return bool(event.process_name and event.process_name.lower() in SUSPICIOUS_TOOLS and off_hours)

    # ---- extraction ---------------------------------------------------------------------------------------
    def extract_features(self, event: TelemetryEvent) -> FeatureVector:
        """Extracts multi-window temporal and spatial features from an incoming event."""
        user_id = event.user_id or "anonymous"
        event_time = parse_timestamp(event.timestamp)

        with self._lock:
            history = self._window(user_id)
            history.append((event_time, event.destination_ip))
            cutoff = max(t for t, _ in history) - RETENTION
            while history and history[0][0] < cutoff:
                history.popleft()  # history is near-sorted; out-of-order stragglers are dropped by maxlen or the next pass

            conn_freq = sum(1 for t, _ in history if event_time - WINDOW_15M < t <= event_time)
            unique_destinations = len({ip for t, ip in history if event_time - WINDOW_1H < t <= event_time})

            counters = self.cumulative_drip_counters[user_id]
            if event.record_count > 0:
                key = "records_exported" if event.event_type in EXPORT_EVENT_TYPES else "records_read"
                counters[key] += event.record_count
                counters["access_count"] += 1
            read_exp_ratio = counters["records_read"] / max(1.0, counters["records_exported"])
            if len(self.cumulative_drip_counters) > settings.FEATURE_MAX_USERS:
                oldest = next(iter(self.cumulative_drip_counters))
                if oldest != user_id:
                    del self.cumulative_drip_counters[oldest]

        ratio = round(event.bytes_out / max(1, event.bytes_in), 4)

        entropy = event.payload_entropy
        if entropy <= 0.0 and event.raw_payload:
            entropy = self.calculate_shannon_entropy(event.raw_payload)
        elif entropy <= 0.0 and event.query:
            entropy = self.calculate_shannon_entropy(event.query)

        off_hours = self.is_off_hours_access(event.timestamp)

        # Composite deviation signal in [0, 1]: a sum of independent warning signs, capped.
        deviation = 0.0
        if ratio > 1000.0:
            deviation += 0.35
        if entropy > settings.ENTROPY_THRESHOLD:
            deviation += 0.30
        if off_hours:
            deviation += 0.20
        if unique_destinations > 5:
            deviation += 0.15
        if read_exp_ratio < 2.0:  # cumulative exports are catching up with reads
            deviation += 0.30

        feature_vec = FeatureVector(
            event_id=event.event_id,
            user_id=user_id,
            bytes_out_in_ratio=ratio,
            connection_frequency_15m=conn_freq,
            payload_entropy=round(entropy, 2),
            historical_deviation_score=round(min(1.0, deviation), 3),
            destination_cardinality_1h=unique_destinations,
            rolling_read_to_export_ratio_180d=round(read_exp_ratio, 2),
            is_off_hours=off_hours,
            privileged_role_hop=self._privileged_hop(event, off_hours),
        )

        with self._lock:
            self.feature_cache[event.event_id] = feature_vec
            self.feature_cache.move_to_end(event.event_id)
            while len(self.feature_cache) > settings.FEATURE_CACHE_SIZE:
                self.feature_cache.popitem(last=False)
        return feature_vec

    def get_feature_vector(self, event_id: str) -> Optional[FeatureVector]:
        with self._lock:
            return self.feature_cache.get(event_id)


# Global feature store instance
feature_store = StreamingFeatureStore()
