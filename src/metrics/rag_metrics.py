"""Context-retrieval metrics.

Graph-RAG here is retrieval over the IAM graph, HR records and change tickets, followed by deterministic rules. There is
no generated text to grade for faithfulness. What is measurable is how retrieval decisions turn out, so that is what is
counted: how many context lookups ran, how many found an approved ticket, and how many tickets were rejected and why.
"""

import collections
import threading
from typing import Any, Dict


class RAGMetricsCalculator:
    """Counts context retrievals and ticket decisions."""

    def __init__(self):
        self._lock = threading.Lock()
        self.retrievals = 0
        self.with_valid_ticket = 0
        self.rejected_ticket_reasons: "collections.Counter[str]" = collections.Counter()

    def record_retrieval(self, has_valid_ticket: bool, rejected_reasons=()):
        with self._lock:
            self.retrievals += 1
            self.with_valid_ticket += int(has_valid_ticket)
            self.rejected_ticket_reasons.update(rejected_reasons)

    def calculate_metrics(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "measured": self.retrievals > 0,
                "context_retrievals": self.retrievals,
                "retrievals_with_valid_ticket": self.with_valid_ticket,
                "ticket_match_rate": round(self.with_valid_ticket / self.retrievals, 4) if self.retrievals else None,
                "rejected_ticket_reasons": dict(self.rejected_ticket_reasons.most_common(10)),
                "knowledge_graph_backend": "Enterprise IAM Graph + Jira ITSM + HR DB",
                "faithfulness": None,
                "not_applicable": "No generated text is produced, so faithfulness, answer relevancy and retrieval recall against a gold set do not apply.",
            }


rag_metrics = RAGMetricsCalculator()
