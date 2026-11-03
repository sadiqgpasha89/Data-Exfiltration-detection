"""Banking Regulatory Compliance and Statutory Liability Tool."""

import json
from typing import Any, Dict, List, Optional
from src.core.config import settings
from src.core.telemetry import TelemetryTimer


class ComplianceKnowledgebaseTool:
    """Evaluates regulatory frameworks (PCI-DSS, GDPR, GLBA, BCBS 239) and potential capital fines."""

    def __init__(self):
        self.frameworks: Dict[str, Dict[str, Any]] = {}
        self._load_frameworks()

    def _load_frameworks(self):
        path = settings.REGULATORY_FRAMEWORKS_PATH
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.frameworks = data.get("frameworks", {})

    def evaluate_compliance_impact(
        self,
        event_category: str,
        record_count: int,
        query: Optional[str] = None,
        triggered_rules: List[str] = None,
    ) -> Dict[str, Any]:
        with TelemetryTimer("compliance_tool_eval") as timer:
            triggered_rules = triggered_rules or []
            violated_frameworks = []
            statutory_window_hours = 72
            total_fine_usd = 0.0
            citations = []

            # Determine applicable frameworks based on query/rules/category
            text_corpus = f"{event_category} {query or ''} {' '.join(triggered_rules)}".lower()

            if "pci" in text_corpus or "card" in text_corpus or "4532" in text_corpus:
                fw = self.frameworks.get("PCI_DSS_v4", {})
                violated_frameworks.append("PCI-DSS v4.0")
                statutory_window_hours = min(statutory_window_hours, fw.get("statutory_reporting_window_hours", 24))
                per_rec = fw.get("per_record_fine_usd", 150.0)
                fine = min(fw.get("max_regulatory_penalty_usd", 5000000.0), record_count * per_rec)
                total_fine_usd += fine
                citations.append(f"PCI-DSS v4.0 [Req 10.2 / 11.5]: Unauthorized exfiltration of cardholder records. Mandatory report within {fw.get('statutory_reporting_window_hours')}h.")

            if "customer" in text_corpus or "ssn" in text_corpus or "gdpr" in text_corpus or "hnw" in text_corpus:
                fw = self.frameworks.get("GDPR", {})
                violated_frameworks.append("GDPR (Article 33/34)")
                statutory_window_hours = min(statutory_window_hours, fw.get("statutory_reporting_window_hours", 72))
                per_rec = fw.get("per_record_fine_usd", 250.0)
                fine = min(fw.get("max_regulatory_penalty_usd", 20000000.0), record_count * per_rec)
                total_fine_usd += fine
                citations.append(f"GDPR [Article 33]: Personal Data Breach risk. Supervisory authority notification required within {fw.get('statutory_reporting_window_hours')}h.")

            if "ledger" in text_corpus or "trade" in text_corpus or "quant" in text_corpus or "dump" in text_corpus:
                fw = self.frameworks.get("BCBS_239", {})
                violated_frameworks.append("BCBS 239 (Risk Data Aggregation)")
                statutory_window_hours = min(statutory_window_hours, fw.get("statutory_reporting_window_hours", 12))
                per_rec = fw.get("per_record_fine_usd", 500.0)
                fine = min(fw.get("max_regulatory_penalty_usd", 50000000.0), record_count * per_rec)
                total_fine_usd += fine
                citations.append(f"BCBS 239 [Principle 3]: Core banking ledger integrity compromised. Central bank reporting SLA: {fw.get('statutory_reporting_window_hours')}h.")

            if not violated_frameworks:
                violated_frameworks = ["Internal Acceptable Use Policy"]
                total_fine_usd = 25000.0
                citations.append("Corporate IT Security Charter: Unauthorized egress transmission.")

            assessment = {
                "applicable_frameworks": violated_frameworks,
                "statutory_reporting_window_hours": statutory_window_hours,
                "estimated_capital_risk_usd": round(total_fine_usd, 2),
                "record_count_evaluated": record_count,
                "compliance_citations": citations,
            }

        assessment["tool_latency_ms"] = round(timer.elapsed_ms, 2)
        return assessment


compliance_tool = ComplianceKnowledgebaseTool()
