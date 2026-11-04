"""Enterprise Identity & Access Management (IAM) Graph Builder.

Constructs an entitlement and behavioral graph using NetworkX.
Provides graph traversal, entitlement hop calculation, and peer group deviation metrics
for Layer 2 GNN anomaly scoring and Layer 3 Graph-RAG contextual enrichment.
"""

import json
import re
from typing import Any, Dict, List, Optional, Set
import networkx as nx
from src.core.config import settings
from src.core.telemetry import logger


class EnterpriseIAMGraphBuilder:
    """Builds and maintains the Identity and Entitlement graph."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.users_data: Dict[str, Dict] = {}
        self._load_corporate_directory()

    def _load_corporate_directory(self):
        """Loads employee directory and populates graph nodes and edges."""
        path = settings.CORPORATE_DIRECTORY_PATH
        if not path.exists():
            return

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for emp in data.get("employees", []):
            u_id = emp["user_id"]
            self.users_data[u_id] = emp

            # Add user node
            self.graph.add_node(
                u_id,
                node_type="USER",
                name=emp["name"],
                role=emp["role"],
                department=emp["department"],
                resignation_submitted=emp.get("resignation_submitted", False),
                resignation_date=emp.get("resignation_date"),
                clearance=emp.get("clearance"),
            )

            # Department node
            dept_id = f"DEPT_{emp['department']}"
            self.graph.add_node(dept_id, node_type="DEPARTMENT")
            self.graph.add_edge(u_id, dept_id, relationship="MEMBER_OF")

            # Role node
            role_id = f"ROLE_{emp['role']}"
            self.graph.add_node(role_id, node_type="ROLE")
            self.graph.add_edge(u_id, role_id, relationship="ASSIGNED_ROLE")

            # Assigned IP
            ip = emp.get("ip_assigned")
            if ip:
                self.graph.add_node(ip, node_type="IP_ENDPOINT")
                self.graph.add_edge(u_id, ip, relationship="OWNS_ENDPOINT")

            # Allowed databases
            for db in emp.get("allowed_databases", []):
                self.graph.add_node(db, node_type="DATABASE")
                self.graph.add_edge(role_id, db, relationship="CAN_READ")
                self.graph.add_edge(u_id, db, relationship="AUTHORIZED_ACCESS")

    def known_resources(self) -> Set[str]:
        """Databases and tables the platform knows about: every DATABASE node plus the configured sensitive tables."""
        databases = {n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "DATABASE"}
        return databases | set(settings.sensitive_tables)

    def extract_resource(self, query: Optional[str]) -> Optional[str]:
        """The first known resource named (as a whole identifier) in a query, or None."""
        if not query:
            return None
        lowered = query.lower()
        for resource in sorted(self.known_resources()):
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(resource.lower())}(?![A-Za-z0-9_])", lowered):
                return resource
        return None

    def get_user_metadata(self, user_id: str) -> Optional[Dict[str, Any]]:
        return self.users_data.get(user_id)

    def check_resignation_status(self, user_id: str) -> Dict[str, Any]:
        """Checks if employee submitted resignation recently (high insider risk factor)."""
        emp = self.users_data.get(user_id)
        if not emp:
            return {"resigned": False, "resignation_date": None}
        return {
            "resigned": emp.get("resignation_submitted", False),
            "resignation_date": emp.get("resignation_date"),
            "peer_group": emp.get("peer_group"),
        }

    def compute_entitlement_deviation(self, user_id: str, target_resource: str) -> float:
        """Computes graph topological distance and entitlement deviation score [0.0 - 1.0].

        0.0 = authorized direct permission.
        1.0 = unauthorized, requires multiple unapproved privilege hops.
        """
        if not self.graph.has_node(user_id) or not self.graph.has_node(target_resource):
            # Unknown node or external target
            return 0.85

        # Check if direct edge exists
        if self.graph.has_edge(user_id, target_resource):
            return 0.05

        # Check role permission
        emp = self.users_data.get(user_id, {})
        role_id = f"ROLE_{emp.get('role')}"
        if self.graph.has_node(role_id) and self.graph.has_edge(role_id, target_resource):
            return 0.10

        # Check shortest path distance
        try:
            path_len = nx.shortest_path_length(self.graph.to_undirected(), source=user_id, target=target_resource)
            deviation = min(1.0, 0.20 * path_len)
            return round(deviation, 3)
        except nx.NetworkXNoPath:
            return 1.0

    def get_peer_group_users(self, peer_group: str) -> List[str]:
        return [u for u, data in self.users_data.items() if data.get("peer_group") == peer_group]

    def get_graph_summary(self) -> Dict[str, Any]:
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "user_count": len(self.users_data),
        }


# Global IAM graph builder instance
iam_graph_builder = EnterpriseIAMGraphBuilder()
