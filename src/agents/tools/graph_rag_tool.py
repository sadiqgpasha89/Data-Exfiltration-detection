"""Graph-RAG Contextual Retrieval Tool for Correlation Agent.

Traverses Enterprise Knowledge Graph across:
1. Active Directory and IAM Entitlement graphs
2. Human Resources (HR) resignation and PIP records
3. IT Service Management (Jira/ServiceNow) approved change request tickets
4. Peer group baseline access comparisons
"""

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from src.core.config import settings
from src.core.telemetry import TelemetryTimer
from src.data_engineering.graph_builder import iam_graph_builder


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _names_table(text: Optional[str], table: str) -> bool:
    """True when `table` appears in `text` as a whole identifier (not as a fragment of a longer name)."""
    return bool(text) and re.search(rf"(?<![A-Za-z0-9_]){re.escape(table.lower())}(?![A-Za-z0-9_])", text.lower()) is not None


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

    def check_ticket(
        self,
        ticket: Dict[str, Any],
        user_id: str,
        event_time: datetime,
        target_resource: Optional[str],
        destination_ip: Optional[str],
    ) -> Tuple[bool, str]:
        """Decides whether one change ticket authorizes this event. Returns (authorized, reason).

        A ticket is authority only if every one of these holds: it is approved and was raised by this user, the event
        falls inside its validity window, it was not approved by the requester, it limits what it covers, and the
        event is inside that limit. Substring tests are not used: `192.0.2.10` is not inside `192.0.2.100/32`.
        """
        if ticket.get("status") != "APPROVED" or ticket.get("requester_id") != user_id:
            return False, "not an approved ticket of this user"

        start, end = _parse_time(ticket.get("valid_from")), _parse_time(ticket.get("valid_until"))
        if start is None or end is None:
            return False, "ticket has no validity window"
        if not (start <= event_time <= end):
            return False, f"event time {event_time.isoformat()} is outside the validity window {start.isoformat()} to {end.isoformat()}"

        requester_name = (self.graph.get_user_metadata(user_id) or {}).get("name", "")
        approver = ticket.get("approver", "")
        if not approver or (requester_name and requester_name.lower() in approver.lower()):
            return False, "ticket was approved by its own requester or has no approver"

        tables, subnets = ticket.get("approved_tables", []), ticket.get("approved_target_subnets", [])
        if not tables and not subnets:
            return False, "ticket does not limit what it covers, so it authorizes nothing in particular"

        if tables and not any(_names_table(target_resource, t) for t in tables):
            return False, "the data touched is not among the tables the ticket approves"
        if subnets:
            try:
                destination = ipaddress.ip_address(destination_ip or "")
                in_scope = any(destination in ipaddress.ip_network(sub, strict=False) for sub in subnets)
            except ValueError:
                in_scope = False
            if not in_scope:
                return False, "the destination is not inside the subnets the ticket approves"
        return True, "ticket is valid for this user, time, data and destination"

    def query_context(
        self,
        user_id: str,
        target_resource: Optional[str] = None,
        destination_ip: Optional[str] = None,
        event_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Executes contextual retrieval across enterprise systems. `event_time` is when the activity happened (default: now)."""
        with TelemetryTimer("graph_rag_query") as timer:
            event_time = event_time or datetime.now(timezone.utc)
            user_meta = self.graph.get_user_metadata(user_id) or {}
            resignation = self.graph.check_resignation_status(user_id)

            matching_tickets: List[Dict[str, Any]] = []
            rejected_tickets: List[Dict[str, str]] = []
            for ticket in self.tickets:
                if ticket.get("requester_id") != user_id:
                    continue
                authorized, reason = self.check_ticket(ticket, user_id, event_time, target_resource, destination_ip)
                if authorized:
                    matching_tickets.append(ticket)
                else:
                    rejected_tickets.append({"ticket_id": ticket.get("ticket_id", "?"), "reason": reason})

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
                "rejected_tickets": rejected_tickets,
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
                for rejected in rejected_tickets:
                    evidence["citations"].append(f"Jira-ITSM [Ticket: {rejected['ticket_id']}]: does not authorize this activity: {rejected['reason']}.")

            evidence["citations"].append(
                f"IAM-Graph: Role '{user_meta.get('role')}' in department '{user_meta.get('department')}'. Normal peer group: {peer_group}."
            )

        evidence["tool_latency_ms"] = round(timer.elapsed_ms, 2)
        return evidence


graph_rag_tool = GraphRAGRetrievalTool()
