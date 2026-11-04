"""Agentic System Metrics Calculator.

The Layer 3 agents are deterministic tool-using components: there is no language model, so there is nothing to
hallucinate and no free-form trajectory to score. Those two figures are therefore reported as not applicable instead of
as invented numbers. What can be measured is measured: investigations run and completed, tool calls per investigation,
and how many verdicts ended with a human in the loop.
"""

import threading
from typing import Any, Dict, List


class AgenticMetricsCalculator:
    """Counts what the swarm actually did."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_tasks_attempted = 0
        self.total_tasks_completed = 0
        self.tool_calls: List[int] = []
        self.consensus_cycles_records: List[int] = []

    def record_investigation(self, completed: bool, tool_calls: int = 0, cycles: int = 1, **_legacy):
        with self._lock:
            self.total_tasks_attempted += 1
            if completed:
                self.total_tasks_completed += 1
            self.tool_calls.append(tool_calls)
            self.consensus_cycles_records.append(cycles)

    def calculate_metrics(self) -> Dict[str, Any]:
        with self._lock:
            n = self.total_tasks_attempted
            return {
                "measured": n > 0,
                "task_completion_rate_pct": round(self.total_tasks_completed / n * 100.0, 2) if n else None,
                "average_tool_calls_per_investigation": round(sum(self.tool_calls) / n, 2) if n else None,
                "average_consensus_convergence_cycles": round(sum(self.consensus_cycles_records) / n, 2) if n else None,
                "total_autonomous_swarms_executed": n,
                "tool_trajectory_accuracy": None,
                "hallucination_error_rate": None,
                "not_applicable": "Agents are deterministic (no language model), so trajectory accuracy and hallucination rate do not apply.",
            }


agentic_metrics = AgenticMetricsCalculator()
