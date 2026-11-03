"""LLMOps Token Consumption & Cost Tracker."""

from typing import Any, Dict


class LLMCostTracker:
    """Tracks prompt tokens, completion tokens, and dollar expenditures."""

    # Pricing per 1,000 tokens (e.g. Gemini 1.5 Pro / Flash equivalent tier)
    PROMPT_COST_PER_1K = 0.00125
    COMPLETION_COST_PER_1K = 0.00500

    def __init__(self):
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_requests = 0

    def record_usage(self, prompt_tokens: int, completion_tokens: int):
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_requests += 1

    def get_summary(self) -> Dict[str, Any]:
        prompt_cost = (self.total_prompt_tokens / 1000.0) * self.PROMPT_COST_PER_1K
        completion_cost = (self.total_completion_tokens / 1000.0) * self.COMPLETION_COST_PER_1K
        total_cost = prompt_cost + completion_cost

        return {
            "total_requests": self.total_requests,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "prompt_tokens": self.total_prompt_tokens,
            "completion_tokens": self.total_completion_tokens,
            "estimated_cost_usd": round(total_cost, 4),
            "cost_per_investigation_usd": round(total_cost / max(1, self.total_requests), 4),
        }


cost_tracker = LLMCostTracker()
