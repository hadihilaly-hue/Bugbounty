"""Anthropic reasoning client with per-call cost accounting.

The finder is the only credit consumer, so every call reports token usage and a
USD estimate that the orchestrator records against the budget caps and credit
window.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_MODEL = os.environ.get("BB_ANTHROPIC_MODEL", "claude-haiku-5-5")


def compute_usd(
    input_tokens: int,
    output_tokens: int,
    price_in_per_mtok: float = 3.0,
    price_out_per_mtok: float = 15.0,
) -> float:
    return input_tokens / 1e6 * price_in_per_mtok + output_tokens / 1e6 * price_out_per_mtok


@dataclass
class LlmResult:
    text: str
    input_tokens: int
    output_tokens: int
    usd: float


class AnthropicReasoner:
    def __init__(self, model: str | None = None, max_tokens: int = 4096) -> None:
        self.model = model or DEFAULT_MODEL
        self.max_tokens = max_tokens
        self.price_in = float(os.environ.get("BB_PRICE_IN_PER_MTOK", "3.0"))
        self.price_out = float(os.environ.get("BB_PRICE_OUT_PER_MTOK", "15.0"))

    def available(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def complete(self, system: str, user: str) -> LlmResult:
        import anthropic

        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        usage = resp.usage
        usd = compute_usd(usage.input_tokens, usage.output_tokens, self.price_in, self.price_out)
        return LlmResult(text, usage.input_tokens, usage.output_tokens, usd)
