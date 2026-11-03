"""Policy & Compliance Auditor Agent: Regulatory Liability & Legal Exposure."""

from src.agents.state import AgentInvestigationState
from src.agents.tools.compliance_tool import compliance_tool
from src.core.models import AgentDebateTurn, AgentToolExecution


class ComplianceAuditorAgent:
    """Specialized agent mapping observed security events to banking regulatory frameworks."""

    def __init__(self):
        self.tool = compliance_tool

    def investigate(self, state: AgentInvestigationState) -> AgentInvestigationState:
        event = state.event

        # Execute Compliance Tool
        comp_result = self.tool.evaluate_compliance_impact(
            event_category=event.category,
            record_count=event.record_count,
            query=event.query,
            triggered_rules=state.layer1_eval.triggered_rules,
        )

        # Log tool execution
        tool_exec = AgentToolExecution(
            tool_name="ComplianceKnowledgebaseTool",
            parameters={"category": event.category, "record_count": event.record_count},
            result=comp_result,
            latency_ms=comp_result.get("tool_latency_ms", 1.5),
        )
        state.tool_executions.append(tool_exec)
        state.regulatory_assessment = comp_result

        frameworks = comp_result.get("applicable_frameworks", [])
        fine_usd = comp_result.get("estimated_capital_risk_usd", 0.0)
        sla_hours = comp_result.get("statutory_reporting_window_hours", 72)

        # Check if Correlation Agent found an authorized Jira ticket
        has_approval = state.graph_rag_evidence.get("has_approved_change_ticket", False)

        if has_approval:
            hypothesis = "Compliant Regulatory Data Processing"
            confidence = 0.94
            rationale = (
                f"Data handling satisfies Article 6 GDPR / BCBS 239 regulatory mandates under active ticket. "
                f"Potential liability of ${fine_usd:,.2f} is covered by legal authorization."
            )
            proposed_action = "APPROVE_TRANSMISSION_LOG"
        else:
            hypothesis = f"Statutory Violation under {', '.join(frameworks)}"
            confidence = 0.90
            rationale = (
                f"Exposure of {event.record_count} records violates {', '.join(frameworks)}. "
                f"Estimated potential regulatory liability: ${fine_usd:,.2f}. "
                f"Mandatory supervisory reporting clock: {sla_hours} hours."
            )
            proposed_action = "MANDATORY_REGULATORY_DISCLOSURE_PREPARATION"

        turn = AgentDebateTurn(
            agent_name="ComplianceAuditorAgent",
            hypothesis=hypothesis,
            confidence=confidence,
            rationale=rationale,
            supporting_citations=comp_result.get("compliance_citations", []),
            proposed_action=proposed_action,
        )
        state.debate_turns.append(turn)
        return state


compliance_agent = ComplianceAuditorAgent()
