"""Graph-RAG Contextual Retrieval Tool for Correlation Agent.

Traverses Enterprise Knowledge Graph across:
1. Active Directory and IAM Entitlement graphs
2. Human Resources (HR) resignation and PIP records
3. IT Service Management (Jira/ServiceNow) approved change request tickets
4. Peer group baseline access comparisons
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from src.core.config import settings
from src.core.telemetry import TelemetryTimer
from src.data_engineering.graph_builder import iam_graph_builder


class GraphRAGRetrievalTool:
    """Enterprise Graph-RAG retrieval engine."""

    def __init__(self):
        self.graph = iam_graph_builder
        self.tickets: List[Dict[str, Any]] = []
        self._load_jira_tickets()

    def _load_jira_tickets(self):
        path = settings.JIRA_TICKETS_PATH
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.tickets = data.get("tickets", [])

    def query_context(
        self,
        user_id: str,
        target_resource: Optional[str] = None,
        destination_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes parallel contextual retrieval across enterprise systems."""
        with TelemetryTimer("graph_rag_query") as timer:
            user_meta = self.graph.get_user_metadata(user_id) or {}
            resignation = self.graph.check_resignation_status(user_id)

            # Search Jira/ServiceNow tickets for matching approvals
            matching_tickets = []
            for ticket in self.tickets:
                if ticket.get("requester_id") == user_id and ticket.get("status") == "APPROVED":
                    app_tables = ticket.get("approved_tables", [])
                    app_subnets = ticket.get("approved_target_subnets", [])
                    target_match = False

                    if not app_tables and not app_subnets:
                        target_match = True
                    else:
                        if target_resource:
                            for tbl in app_tables:
                                if tbl.lower() in target_resource.lower():
                                    target_match = True
                                    break
                        if destination_ip:
                            for sub in app_subnets:
                                if destination_ip in sub:
                                    target_match = True
                                    break

                    if target_match:
                        matching_tickets.append(ticket)

            has_valid_approval = len(matching_tickets) > 0

            # Peer group baseline
            peer_group = user_meta.get("peer_group", "general_staff")
            peers = self.graph.get_peer_group_users(peer_group)

            evidence = {
                "user_id": user_id,
                "name": user_meta.get("name", "Unknown"),
                "role": user_meta.get("role", "Unknown"),
                "department": user_meta.get("department", "Unknown"),
                "clearance": user_meta.get("clearance", "Standard"),
                "resignation_status": resignation,
                "has_approved_change_ticket": has_valid_approval,
                "approved_tickets": matching_tickets,
                "peer_group": peer_group,
                "peer_group_size": len(peers),
                "citations": [],
            }

            # Generate citations for explainability
            if resignation.get("resigned"):
                evidence["citations"].append(
                    f"HR-System [Doc-ID: HR-RESIGN-2026]: User tendered resignation on {resignation.get('resignation_date')}. Heightened flight/exfiltration risk."
                )

            if has_valid_approval:
                t = matching_tickets[0]
                evidence["citations"].append(
                    f"Jira-ITSM [Ticket: {t['ticket_id']}]: Authorized '{t['title']}'. Approver: {t['approver']} (Signature: {t['digital_signature_hash'][:10]}...)"
                )
            else:
                evidence["citations"].append(
                    f"Jira-ITSM: No active, approved change request found authorizing bulk data extraction for {user_id}."
                )

            evidence["citations"].append(
                f"IAM-Graph: Role '{user_meta.get('role')}' in department '{user_meta.get('department')}'. Normal peer group: {peer_group}."
            )

        evidence["tool_latency_ms"] = round(timer.elapsed_ms, 2)
        return evidence


graph_rag_tool = GraphRAGRetrievalTool()
