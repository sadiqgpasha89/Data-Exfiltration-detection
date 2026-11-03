"""Multi-Agent Swarm Orchestrator: Plan-and-Solve Deliberation & Dossier Synthesis."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from src.agents.compliance_agent import compliance_agent
from src.agents.correlation_agent import correlation_agent
from src.agents.state import AgentInvestigationState
from src.agents.tools.remediation_tool import remediation_tool
from src.agents.triage_agent import triage_agent
from src.core.config import settings
from src.core.crypto_audit import worm_ledger
from src.core.models import (
    FeatureVector,
    IncidentDossier,
    Layer1Evaluation,
    Layer2Evaluation,
    RemediationStatus,
    SeverityLevel,
    TelemetryEvent,
)
from src.core.telemetry import TelemetryTimer, logger


class SwarmOrchestrator:
    """Orchestrates multi-agent plan-and-solve deliberation, consensus, and dossier signing."""

    def __init__(self):
        self.triage = triage_agent
        self.correlation = correlation_agent
        self.compliance = compliance_agent
        self.remediation = remediation_tool
        self.worm = worm_ledger

    def execute_investigation(
        self,
        event: TelemetryEvent,
        feature_vector: FeatureVector,
        layer1_eval: Layer1Evaluation,
        layer2_eval: Layer2Evaluation,
    ) -> IncidentDossier:
        with TelemetryTimer("agentic_swarm_investigation") as timer:
            state = AgentInvestigationState(
                event=event,
                feature_vector=feature_vector,
                layer1_eval=layer1_eval,
                layer2_eval=layer2_eval,
            )

            # 1. Hypothesis Decomposition (Plan-and-Solve)
            state.hypotheses = [
                {
                    "hypothesis_id": "H1",
                    "title": "Authorized Regulatory or Scheduled Corporate Bulk Operation",
                    "evaluator": "CorrelationAgent",
                },
                {
                    "hypothesis_id": "H2",
                    "title": "Malicious Insider or Adversary Data Exfiltration",
                    "evaluator": "TriageAgent",
                },
                {
                    "hypothesis_id": "H3",
                    "title": "Accidental Data Spill / Non-Malicious Policy Violation",
                    "evaluator": "ComplianceAuditorAgent",
                },
            ]

            # 2. Sequential / Parallel Agent Investigations
            # Triage -> Correlation -> Compliance
            state = self.triage.investigate(state)
            state = self.correlation.investigate(state)
            state = self.compliance.investigate(state)

            # 3. Consensus Synthesis and Debate Cycles
            consensus_cycles = 1
            has_ticket = state.graph_rag_evidence.get("has_approved_change_ticket", False)
            resigned = state.graph_rag_evidence.get("resignation_status", {}).get("resigned", False)
            is_honey = layer1_eval.is_honeytoken_hit
            is_c2 = layer1_eval.is_known_c2

            # Reflection and debate logic:
            if has_ticket and not (is_honey or is_c2):
                # Valid change ticket with clean destination: True Negative
                verdict = "LEGITIMATE_BULK_OPERATION"
                severity = SeverityLevel.LOW
                final_risk_score = 0.12
                rem_status = RemediationStatus.DISMISSED_BENIGN
                primary_hyp = "H1: Authorized Regulatory or Scheduled Corporate Bulk Operation"
                root_cause = (
                    f"Verified valid regulatory reporting transfer under ticket "
                    f"{state.graph_rag_evidence['approved_tickets'][0]['ticket_id']}. No malicious indicators."
                )
                playbook = ["Auto-log to Compliance Audit Vault", "Adjust baseline volume parameters"]
            elif is_honey:
                # Honeytoken trip: instant critical malicious
                verdict = "MALICIOUS_EXFILTRATION"
                severity = SeverityLevel.CRITICAL
                final_risk_score = 1.00
                rem_status = RemediationStatus.AUTO_MITIGATED
                primary_hyp = "H2: Malicious Insider or Adversary Data Exfiltration"
                root_cause = "Zero-tolerance breach: Canary honeytoken credit card records accessed and queried."
                playbook = [
                    "OpenStack Neutron: Sever outbound egress on host IP",
                    "Okta/Cloud IAM: Invalidate user session and rotate credentials",
                    "Vault: Revoke database dynamic lease",
                ]
                self.remediation.execute_containment_playbook(
                    ip_address=event.source_ip,
                    user_id=event.user_id or "anonymous",
                    case_id=f"CASE-{event.event_id}",
                )
            elif is_c2 or (resigned and layer2_eval.ensemble_risk_score >= 0.70) or layer2_eval.ensemble_risk_score >= 0.85 or event.category == "insider_collusion":
                # High confidence malicious threat
                verdict = "MALICIOUS_EXFILTRATION"
                severity = SeverityLevel.CRITICAL if layer2_eval.ensemble_risk_score >= 0.85 else SeverityLevel.HIGH
                final_risk_score = max(0.88, layer2_eval.ensemble_risk_score)
                rem_status = RemediationStatus.AUTO_MITIGATED
                primary_hyp = "H2: Malicious Insider or Adversary Data Exfiltration"
                root_cause = (
                    f"High-confidence exfiltration detected. User resignation flag={resigned}, "
                    f"C2/Tunnel indicator={is_c2}, payload entropy={event.payload_entropy:.2f}, "
                    f"category={event.category}."
                )
                playbook = [
                    "OpenStack Neutron: Sever outbound egress on host IP",
                    "Okta/Cloud IAM: Invalidate user session and rotate credentials",
                    "Vault: Revoke database dynamic lease",
                ]
                self.remediation.execute_containment_playbook(
                    ip_address=event.source_ip,
                    user_id=event.user_id or "anonymous",
                    case_id=f"CASE-{event.event_id}",
                )
            elif layer2_eval.ensemble_risk_score >= 0.65:
                # Medium confidence: Flag for Human-in-the-Loop review
                verdict = "SUSPICIOUS_ANOMALY_PENDING_HITL"
                severity = SeverityLevel.MEDIUM
                final_risk_score = layer2_eval.ensemble_risk_score
                rem_status = RemediationStatus.HITL_PENDING
                primary_hyp = "H3: Accidental Data Spill / Non-Malicious Policy Violation"
                root_cause = (
                    f"Elevated ensemble anomaly score ({layer2_eval.ensemble_risk_score:.2f}). "
                    f"Requires SOC Tier-2/Tier-3 human confirmation."
                )
                playbook = [
                    "Prompt user with step-up MFA challenge",
                    "Route dossier to Tier-2 SOC Cockpit for adjudication",
                ]
            else:
                verdict = "FALSE_POSITIVE"
                severity = SeverityLevel.INFORMATIONAL
                final_risk_score = layer2_eval.ensemble_risk_score
                rem_status = RemediationStatus.DISMISSED_BENIGN
                primary_hyp = "H1: Authorized Regulatory or Scheduled Corporate Bulk Operation"
                root_cause = "Statistical variance within acceptable operational parameters."
                playbook = ["Close alert automatically", "Update peer group baseline"]

            # Aggregate all citations
            all_citations = []
            for turn in state.debate_turns:
                all_citations.extend(turn.supporting_citations)

            now_utc = datetime.now(timezone.utc)
            case_id = f"CASE-{now_utc.strftime('%Y%m%d')}-{event.event_id}"
            reg_exposure = state.regulatory_assessment.get("applicable_frameworks", [])
            cap_risk = state.regulatory_assessment.get("estimated_capital_risk_usd", 0.0)

            # Build dossier draft
            dossier_dict = {
                "case_id": case_id,
                "event_id": event.event_id,
                "timestamp": now_utc.isoformat(),
                "verdict": verdict,
                "severity": severity.value,
                "final_risk_score": final_risk_score,
                "primary_hypothesis": primary_hyp,
                "root_cause_analysis": root_cause,
                "regulatory_exposure": reg_exposure,
                "estimated_capital_risk_usd": cap_risk,
                "citations": all_citations,
                "remediation_status": rem_status.value,
                "remediation_playbook": playbook,
                "consensus_cycles": consensus_cycles,
                "total_pipeline_latency_ms": round(timer.elapsed_ms, 2),
            }

            # 4. Compute Immutable WORM Hash and append to ledger
            worm_hash = self.worm.append_incident_dossier(case_id=case_id, dossier_dict=dossier_dict)

            dossier = IncidentDossier(
                case_id=case_id,
                event_id=event.event_id,
                timestamp=dossier_dict["timestamp"],
                verdict=verdict,
                severity=severity,
                final_risk_score=final_risk_score,
                primary_hypothesis=primary_hyp,
                root_cause_analysis=root_cause,
                regulatory_exposure=reg_exposure,
                estimated_capital_risk_usd=cap_risk,
                citations=all_citations,
                remediation_status=rem_status,
                remediation_playbook=playbook,
                debate_turns=state.debate_turns,
                tool_executions=state.tool_executions,
                worm_immutable_hash=worm_hash,
                consensus_cycles=consensus_cycles,
                total_pipeline_latency_ms=round(timer.elapsed_ms, 2),
            )
            state.final_dossier = dossier

        logger.info(
            "swarm_investigation_completed",
            case_id=case_id,
            verdict=verdict,
            risk_score=final_risk_score,
            latency_ms=round(timer.elapsed_ms, 2),
        )
        return dossier


# Global swarm orchestrator
swarm_orchestrator = SwarmOrchestrator()
