"""LLMOps Distributed Trace Logger.

Tracks agent reasoning steps, tool invocation spans, and inter-agent messages.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


class AgentTraceSpan:
    def __init__(self, trace_id: str, span_name: str, agent_name: str, start_time: float):
        self.trace_id = trace_id
        self.span_name = span_name
        self.agent_name = agent_name
        self.start_time = start_time
        self.end_time = 0.0
        self.duration_ms = 0.0
        self.attributes: Dict[str, Any] = {}

    def finish(self, end_time: float, attributes: Dict[str, Any] = None):
        self.end_time = end_time
        self.duration_ms = round((self.end_time - self.start_time) * 1000.0, 2)
        if attributes:
            self.attributes.update(attributes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_name": self.span_name,
            "agent_name": self.agent_name,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class AgentTraceLogger:
    """Collects and indexes distributed spans across multi-agent deliberations."""

    def __init__(self):
        self.spans: List[Dict[str, Any]] = []

    def record_span(self, trace_id: str, span_name: str, agent_name: str, duration_ms: float, attributes: Dict = None):
        entry = {
            "trace_id": trace_id,
            "span_name": span_name,
            "agent_name": agent_name,
            "duration_ms": duration_ms,
            "attributes": attributes or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.spans.append(entry)

    def get_recent_traces(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.spans[-limit:]


trace_logger = AgentTraceLogger()
