"""Triage Agent: Physical Transmission Mechanics & Forensic Header Analysis."""

from src.agents.state import AgentInvestigationState
from src.agents.tools.sandbox_tool import sandbox_tool
from src.core.models import AgentDebateTurn, AgentToolExecution


class TriageAgent:
    """Specialized agent analyzing file headers, process trees, and payload obfuscation."""

    def __init__(self):
        self.tool = sandbox_tool

    def investigate(self, state: AgentInvestigationState) -> AgentInvestigationState:
        event = state.event

        # Execute Sandbox Tool
        tool_result = self.tool.analyze_file_and_process(
            file_name=event.file_name,
            process_name=event.process_name,
            file_hash=event.file_hash_sha256,
            entropy=event.payload_entropy,
        )

        # Log tool execution
        tool_exec = AgentToolExecution(
            tool_name="SandboxAnalyzerTool",
            parameters={
                "file_name": event.file_name,
                "process_name": event.process_name,
                "entropy": event.payload_entropy,
            },
            result=tool_result,
            latency_ms=tool_result.get("tool_latency_ms", 1.0),
        )
        state.tool_executions.append(tool_exec)
        state.triage_findings = tool_result

        # Formulate hypothesis and debate turn
        is_suspicious = tool_result.get("is_suspicious_process") or event.payload_entropy > 7.5 or state.layer1_eval.is_known_c2
        confidence = 0.88 if is_suspicious else 0.30

        if is_suspicious:
            rationale = (
                f"Triage forensics revealed suspicious process '{event.process_name}' "
                f"(Entropy: {event.payload_entropy:.2f}). {'; '.join(tool_result.get('forensic_notes', []))}"
            )
            proposed_action = "ESCALATE_FOR_NETWORK_CONTAINMENT"
            hypothesis = "Malicious Payload Staging / Active Egress Tunneling"
        else:
            rationale = (
                f"Process '{event.process_name}' belongs to certified enterprise suite. "
                f"Entropy {event.payload_entropy:.2f} is within benign boundaries."
            )
            proposed_action = "CONTINUE_CONTEXTUAL_CORRELATION"
            hypothesis = "Benign Corporate Operational Data Flow"

        turn = AgentDebateTurn(
            agent_name="TriageAgent",
            hypothesis=hypothesis,
            confidence=confidence,
            rationale=rationale,
            supporting_citations=[
                f"ProcessTree: {tool_result.get('process_parent_tree')}",
                f"PayloadEntropy: {event.payload_entropy}",
            ],
            proposed_action=proposed_action,
        )
        state.debate_turns.append(turn)
        return state


triage_agent = TriageAgent()
