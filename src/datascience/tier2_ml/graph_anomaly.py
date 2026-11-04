"""Graph Representation Learning and Entitlement Deviation Scorer.

Evaluates user access paths and role hops across the enterprise IAM graph.
Detects lateral movement, privilege expansion, and non-standard database traversal.
"""

from src.core.models import FeatureVector, TelemetryEvent
from src.core.netutil import is_internal
from src.data_engineering.graph_builder import iam_graph_builder


class GraphAnomalyScorer:
    """Calculates graph structural deviation and privilege hop anomaly score [0.0 - 1.0]."""

    def __init__(self):
        self.graph_builder = iam_graph_builder

    def _entitlement_deviation(self, user_id: str, target) -> float:
        """Deviation of the event's target from what the user is entitled to.

        An unmanaged identity or an unknown table is as suspicious as before (0.85). A network address that is not a
        graph node is not an entitlement question: reaching an external host is weak evidence on its own (0.35, the
        threat-intelligence layer carries the strong evidence) and reaching an internal host weaker still (0.15).
        """
        if not target:
            return 0.85
        known_user = self.graph_builder.graph.has_node(user_id)
        try:
            import ipaddress
            addr = ipaddress.ip_address(target)
        except ValueError:
            addr = None
        if addr is not None and known_user and not self.graph_builder.graph.has_node(target):
            return 0.15 if is_internal(addr) else 0.35
        return self.graph_builder.compute_entitlement_deviation(user_id, target)

    def score_event(self, event: TelemetryEvent, fv: FeatureVector) -> float:
        """Computes composite graph anomaly score."""
        user_id = event.user_id or "anonymous"

        # 1. Target resource resolution: a known database/table named in the query, otherwise the destination address
        target = self.graph_builder.extract_resource(event.query)
        if not target and event.destination_ip:
            target = event.destination_ip

        # 2. Entitlement deviation
        entitlement_dev = self._entitlement_deviation(user_id, target)

        # 3. Resignation status weight
        resignation_info = self.graph_builder.check_resignation_status(user_id)
        resignation_boost = 0.35 if resignation_info.get("resigned") else 0.0

        # 4. Privileged role hop flag
        priv_hop_boost = 0.25 if fv.privileged_role_hop else 0.0

        # Composite score
        total_score = 0.40 * entitlement_dev + resignation_boost + priv_hop_boost
        return round(float(min(1.0, max(0.0, total_score))), 4)


# Global graph anomaly scorer
graph_anomaly_scorer = GraphAnomalyScorer()
