"""Business and Risk Metrics Calculator.

Every figure is computed from incidents this process has actually resolved. With no data a metric is None: nothing is
estimated, floored or padded, because a dashboard that shows a healthy number for a system that has seen no traffic is
worse than no dashboard.

Note what the time figures are: how long the platform took to process an event (detection) and to produce a dossier and
containment decision (response). They are processing latencies, not the wall-clock time between a malicious act and a
human noticing it; that needs timestamps from the source systems.
"""

import threading
from typing import Any, Dict, List, Optional


class BusinessMetricsCalculator:
    """Calculates operational metrics from recorded incident resolutions."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_raw_alerts = 0
        self.autonomous_mitigations = 0
        self.autonomous_dismissals = 0
        self.escalated_to_hitl = 0
        self.total_exposure_usd = 0.0
        self.total_loss_avoided_usd = 0.0
        self.detection_times_seconds: List[float] = []
        self.response_times_seconds: List[float] = []

    def record_incident_resolution(
        self,
        verdict: str,
        detection_time_sec: float,
        response_time_sec: float,
        capital_risk_usd: float,
        is_hitl: bool = False,
        contained: bool = False,
    ):
        with self._lock:
            self.total_raw_alerts += 1
            self.detection_times_seconds.append(detection_time_sec)
            self.response_times_seconds.append(response_time_sec)
            if len(self.detection_times_seconds) > 10_000:
                del self.detection_times_seconds[:5_000], self.response_times_seconds[:5_000]

            if verdict == "MALICIOUS_EXFILTRATION":
                self.total_exposure_usd += capital_risk_usd
                if contained:  # exposure counts as avoided only when containment verifiably happened
                    self.autonomous_mitigations += 1
                    self.total_loss_avoided_usd += capital_risk_usd
                elif is_hitl:
                    self.escalated_to_hitl += 1
            elif verdict in ("LEGITIMATE_BULK_OPERATION", "FALSE_POSITIVE"):
                self.autonomous_dismissals += 1
            elif is_hitl:
                self.escalated_to_hitl += 1

    @staticmethod
    def _mean_minutes(samples: List[float]) -> Optional[float]:
        return round(sum(samples) / len(samples) / 60.0, 4) if samples else None

    def calculate_metrics(self) -> Dict[str, Any]:
        with self._lock:
            mttd, mttr = self._mean_minutes(self.detection_times_seconds), self._mean_minutes(self.response_times_seconds)
            total = self.total_raw_alerts
            resolved = self.autonomous_mitigations + self.autonomous_dismissals
            fatigue = round(resolved / total * 100.0, 1) if total else None
            return {
                "measured": total > 0,
                "mttd_minutes": mttd,
                "mttd_target_met": None if mttd is None else mttd < 2.0,
                "mttr_minutes": mttr,
                "mttr_target_met": None if mttr is None else mttr < 5.0,
                "total_capital_loss_avoided_usd": round(self.total_loss_avoided_usd, 2),
                "total_estimated_exposure_usd": round(self.total_exposure_usd, 2),
                "soc_analyst_fatigue_reduction_pct": fatigue,
                "fatigue_target_met": None if fatigue is None else fatigue >= 85.0,
                "total_raw_alerts_processed": total,
                "autonomous_resolutions": resolved,
                "hitl_escalations": self.escalated_to_hitl,
            }


business_metrics = BusinessMetricsCalculator()
