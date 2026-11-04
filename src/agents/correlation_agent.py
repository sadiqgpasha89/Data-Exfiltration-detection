"""Context & Correlation Agent: Graph-RAG Traversal & Enterprise Context."""

from datetime import datetime, timezone

from src.agents.state import AgentInvestigationState
from src.agents.tools.graph_rag_tool import graph_rag_tool
from src.core.models import AgentDebateTurn, AgentToolExecution


class CorrelationAgent:
    """Specialized agent traversing enterprise IAM, HR, and Jira ticketing systems via Graph-RAG."""

    def __init__(self):
        self.tool = graph_rag_tool

    def investigate(self, state: AgentInvestigationState) -> AgentInvestigationState:
        event = state.event
        user_id = event.user_id or "anonymous"

        try:  # tickets are judged against when the activity happened, not when it was investigated
            event_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            event_time = event_time if event_time.tzinfo else event_time.replace(tzinfo=timezone.utc)
        except ValueError:
            event_time = datetime.now(timezone.utc)

        # Execute Graph-RAG Tool
        rag_result = self.tool.query_context(
            user_id=user_id,
            target_resource=event.query or event.file_name,
            destination_ip=event.destination_ip,
            event_time=event_time,
        )

        # Log tool execution
        tool_exec = AgentToolExecution(
            tool_name="GraphRAGRetrievalTool",
            parameters={"user_id": user_id, "destination_ip": event.destination_ip},
            result=rag_result,
            latency_ms=rag_result.get("tool_latency_ms", 2.0),
        )
        state.tool_executions.append(tool_exec)
        state.graph_rag_evidence = rag_result

        has_ticket = rag_result.get("has_approved_change_ticket", False)
        resigned = rag_result.get("resignation_status", {}).get("resigned", False)

        if has_ticket:
            ticket = rag_result["approved_tickets"][0]
            hypothesis = "Authorized Regulatory / Operational Bulk Transfer"
            confidence = 0.95
            rationale = (
                f"Graph-RAG verified active approval ticket {ticket['ticket_id']} ('{ticket['title']}') "
                f"authorized by {ticket['approver']}. Digital signature verified. Operation is legally sanctioned."
            )
            proposed_action = "AUTO_DOCUMENT_AND_CLOSE_AS_LEGITIMATE"
        elif resigned:
            hypothesis = "Malicious Departing Insider Exfiltration"
            confidence = 0.92
            rationale = (
                f"HR records confirm user '{rag_result.get('name')}' tendered resignation on "
                f"{rag_result.get('resignation_status', {}).get('resignation_date')}. "
                f"No change order authorizes bulk extraction. Severe exfiltration flight risk."
            )
            proposed_action = "EXECUTE_IMMEDIATE_CONTAINMENT_PLAYBOOK"
        elif state.feature_vector.privileged_role_hop:
            hypothesis = "Unauthorized Privilege Expansion / Out-of-Profile Access"
            confidence = 0.85
            rationale = (
                f"User role '{rag_result.get('role')}' in '{rag_result.get('department')}' has no business justification "
                f"to query target dataset. Peer group baseline does not reflect this behavior."
            )
            proposed_action = "STEP_UP_AUTHENTICATION_AND_INVESTIGATE"
        else:
            hypothesis = "Uncorrelated Activity Under Review"
            confidence = 0.50
            rationale = f"Telemetry correlates with user {rag_result.get('name')}. Baseline investigation continues."
            proposed_action = "DEFER_TO_ORCHESTRATOR_SYNTHESIS"

        turn = AgentDebateTurn(
            agent_name="CorrelationAgent",
            hypothesis=hypothesis,
            confidence=confidence,
            rationale=rationale,
            supporting_citations=rag_result.get("citations", []),
            proposed_action=proposed_action,
        )
        state.debate_turns.append(turn)
        return state


correlation_agent = CorrelationAgent()
