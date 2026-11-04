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
    AgentToolExecution,
    FeatureVector,
    IncidentDossier,
    Layer1Evaluation,
    Layer2Evaluation,
    RemediationStatus,
    SeverityLevel,
    TelemetryEvent,
)
from src.core.telemetry import TelemetryTimer, logger
from src.metrics.agentic_metrics import agentic_metrics
from src.metrics.rag_metrics import rag_metrics


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

            # 3. Decision. Only evidence is used. `event.category` is a label chosen by the sender of the telemetry
            #    and is deliberately ignored: trusting it would let anyone who can post an event choose the verdict.
            consensus_cycles = 1
            evidence = state.graph_rag_evidence
            has_ticket = evidence.get("has_approved_change_ticket", False)
            resigned = evidence.get("resignation_status", {}).get("resigned", False)
            is_honey = layer1_eval.is_honeytoken_hit
            hard_indicator = is_honey or layer1_eval.is_known_c2 or layer1_eval.is_edm_exact_match
            data_violation = layer1_eval.is_regex_compliance_hit or layer1_eval.is_stego_detected
            score = layer2_eval.ensemble_risk_score
            is_bulk = event.record_count >= settings.BULK_RECORD_THRESHOLD or event.bytes_out >= settings.BULK_BYTES_THRESHOLD
            unauthorized_bulk = is_bulk and not has_ticket
            corroboration = [
                name for name, present in (
                    ("departing employee", resigned),
                    ("access without entitlement or staging tool off hours", feature_vector.privileged_role_hop),
                    ("off-hours activity", feature_vector.is_off_hours),
                    ("sensitive data or concealed payload", data_violation),
                    ("bulk transfer with no valid change ticket", unauthorized_bulk),
                ) if present
            ]
            hard_names = [n for n, p in (("honeytoken", is_honey), ("known C2", layer1_eval.is_known_c2), ("proprietary file match", layer1_eval.is_edm_exact_match)) if p]
            signals = (
                f"ensemble score {score:.2f}; hard indicators: {', '.join(hard_names) or 'none'}; "
                f"corroboration: {', '.join(corroboration) or 'none'}"
            )
            containment: Dict[str, Any] = {}

            # A valid ticket explains bulk activity, but never overrides a hard indicator, a departing employee,
            # sensitive-data or concealment findings, or an extreme score. Those go to a human, not to the bin.
            ticket_explains_it = has_ticket and not (hard_indicator or resigned or data_violation or score >= settings.HIGH_CONFIDENCE_MALICIOUS_THRESHOLD)

            if ticket_explains_it:
                ticket = evidence["approved_tickets"][0]
                verdict, severity = "LEGITIMATE_BULK_OPERATION", SeverityLevel.LOW
                final_risk_score = round(min(0.30, score * 0.5), 2)
                rem_status = RemediationStatus.DISMISSED_BENIGN
                primary_hyp = "H1: Authorized Regulatory or Scheduled Corporate Bulk Operation"
                root_cause = (
                    f"Activity falls inside change ticket {ticket['ticket_id']} (valid at the time of the event, scoped to this data and "
                    f"destination, not self-approved). No hard indicators. {signals}."
                )
                playbook = ["Auto-log to Compliance Audit Vault", "Adjust baseline volume parameters"]
            elif (
                hard_indicator
                or score >= settings.HIGH_CONFIDENCE_MALICIOUS_THRESHOLD
                or (resigned and score >= 0.70)
                or (unauthorized_bulk and score >= 0.70 and len(corroboration) >= 2)
            ):
                verdict = "MALICIOUS_EXFILTRATION"
                severity = SeverityLevel.CRITICAL if (is_honey or score >= settings.HIGH_CONFIDENCE_MALICIOUS_THRESHOLD or hard_indicator) else SeverityLevel.HIGH
                final_risk_score = 1.0 if is_honey else max(0.88 if hard_indicator else 0.85, score)
                primary_hyp = "H2: Malicious Insider or Adversary Data Exfiltration"
                root_cause = (
                    ("Zero-tolerance breach: a canary honeytoken record was accessed. " if is_honey else "High-confidence exfiltration. ")
                    + f"{signals}. Payload entropy {event.payload_entropy:.2f}."
                )
                playbook = [
                    "OpenStack Neutron: Sever outbound egress on host IP",
                    "Okta/Cloud IAM: Invalidate user session and rotate credentials",
                    "Vault: Revoke database dynamic lease",
                ]
                # Automatic containment needs strong evidence (a hard indicator or an extreme score). Anything weaker is recommended to a human.
                auto_eligible = hard_indicator or score >= settings.HIGH_CONFIDENCE_MALICIOUS_THRESHOLD
                if auto_eligible:
                    containment = self.remediation.automated_containment(
                        ip_address=event.source_ip,
                        user_id=event.user_id or "anonymous",
                        case_id=f"CASE-{event.event_id}",
                    )
                else:
                    containment = {"mode": settings.AUTO_REMEDIATION_MODE, "executed": False, "effective": False,
                                   "blocked_reason": "evidence does not meet the bar for automatic containment; analyst approval required",
                                   "actions": []}
                rem_status = RemediationStatus.AUTO_MITIGATED if containment.get("effective") else RemediationStatus.CONTAINMENT_RECOMMENDED
                state.tool_executions.append(AgentToolExecution(
                    tool_name="RemediationExecutionTool",
                    parameters={"ip": event.source_ip, "user_id": event.user_id, "auto_eligible": auto_eligible},
                    result={k: v for k, v in containment.items() if k != "actions"} | {"action_count": len(containment.get("actions", []))},
                    latency_ms=sum(a.get("latency_ms", 0.0) for a in containment.get("actions", [])),
                ))
            elif score >= settings.ANOMALY_DISPATCH_THRESHOLD_TAU or data_violation or has_ticket:
                verdict = "SUSPICIOUS_ANOMALY_PENDING_HITL"
                severity = SeverityLevel.MEDIUM
                final_risk_score = max(score, 0.65) if (data_violation or has_ticket) else score
                rem_status = RemediationStatus.HITL_PENDING
                primary_hyp = "H3: Accidental Data Spill / Non-Malicious Policy Violation"
                root_cause = (
                    f"Needs human confirmation. {signals}."
                    + (" A change ticket exists but other findings prevent auto-dismissal." if has_ticket else "")
                )
                playbook = [
                    "Prompt user with step-up MFA challenge",
                    "Route dossier to Tier-2 SOC Cockpit for adjudication",
                ]
            else:
                verdict = "FALSE_POSITIVE"
                severity = SeverityLevel.INFORMATIONAL
                final_risk_score = score
                rem_status = RemediationStatus.DISMISSED_BENIGN
                primary_hyp = "H1: Authorized Regulatory or Scheduled Corporate Bulk Operation"
                root_cause = f"Statistical variance within acceptable operational parameters. {signals}."
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
                "containment": {k: v for k, v in containment.items() if k != "actions"},
                "consensus_cycles": consensus_cycles,
                "total_pipeline_latency_ms": round(timer.elapsed_ms, 2),
            }

            # 4. Compute Immutable WORM Hash and append to ledger
            worm_hash = self.worm.append_incident_dossier(case_id=case_id, dossier_dict=dossier_dict)

            dossier = IncidentDossier(
                case_id=case_id,
                event_id=event.event_id,
                subject_ip=event.source_ip,
                subject_user_id=event.user_id,
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
                containment=containment,
                consensus_cycles=consensus_cycles,
                total_pipeline_latency_ms=round(timer.elapsed_ms, 2),
            )
            state.final_dossier = dossier

            agentic_metrics.record_investigation(completed=True, tool_calls=len(state.tool_executions), cycles=consensus_cycles)
            rag_metrics.record_retrieval(
                has_valid_ticket=has_ticket,
                rejected_reasons=[r["reason"].split(" (")[0][:80] for r in evidence.get("rejected_tickets", [])],
            )

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
