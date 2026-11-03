"""Graph Representation Learning and Entitlement Deviation Scorer.

Evaluates user access paths and role hops across the enterprise IAM graph.
Detects lateral movement, privilege expansion, and non-standard database traversal.
"""

from src.core.models import FeatureVector, TelemetryEvent
from src.data_engineering.graph_builder import iam_graph_builder


class GraphAnomalyScorer:
    """Calculates graph structural deviation and privilege hop anomaly score [0.0 - 1.0]."""

    def __init__(self):
        self.graph_builder = iam_graph_builder

    def score_event(self, event: TelemetryEvent, fv: FeatureVector) -> float:
        """Computes composite graph anomaly score."""
        user_id = event.user_id or "anonymous"

        # 1. Target resource resolution
        target = None
        if event.query:
            # Check for database table mentions
            query_lower = event.query.lower()
            for db_table in ["customer_accounts_master", "core_ledger", "cardholder_records", "core_quant_models", "treasury_analytics"]:
                if db_table in query_lower:
                    target = db_table
                    break

        if not target and event.destination_ip:
            target = event.destination_ip

        # 2. Entitlement deviation
        entitlement_dev = self.graph_builder.compute_entitlement_deviation(user_id, target or "unknown_resource")

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
