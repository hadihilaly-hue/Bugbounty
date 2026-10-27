"""Budget metering: hard per-run caps, the global kill switch, and credit-window
spend warnings (50/75/90%).

The orchestrator calls ``check()`` before every unit of work and ``record()``
after. Exceeding a cap or engaging the kill switch aborts the batch rather than
silently continuing.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import BudgetCaps, Config
from .store import Store


class BudgetExceeded(Exception):
    """A hard per-run or credit-window cap was hit."""


class KillSwitchEngaged(Exception):
    """The global kill switch (flag or file) is set."""


@dataclass
class CreditWindow:
    """A time-boxed pool of credit. ``cap_usd <= 0`` means no credit cap set."""

    cap_usd: float = 0.0
    thresholds: tuple[float, ...] = (0.5, 0.75, 0.9)

    @classmethod
    def from_env(cls) -> CreditWindow:
        raw = os.environ.get("BB_CREDIT_CAP_USD", "").strip()
        return cls(cap_usd=float(raw) if raw else 0.0)


@dataclass
class BudgetMeter:
    caps: BudgetCaps
    store: Store
    credit: CreditWindow = field(default_factory=CreditWindow)
    kill_switch_file: str | None = None
    tokens: int = 0
    requests: int = 0
    usd: float = 0.0
    _started: float = field(default_factory=time.monotonic)
    _warned: set[float] = field(default_factory=set)

    def record(
        self,
        job: str,
        usd: float = 0.0,
        tokens: int = 0,
        requests: int = 0,
        batch_id: str | None = None,
        run_id: str | None = None,
        target_name: str | None = None,
    ) -> None:
        self.tokens += tokens
        self.requests += requests
        self.usd += usd
        self.store.record_spend(job, usd, tokens, requests, batch_id, run_id, target_name)

    def new_warnings(self) -> list[str]:
        """Return threshold-crossing messages not yet emitted this process."""
        if self.credit.cap_usd <= 0:
            return []
        total = self.store.total_spend_usd()
        pct = total / self.credit.cap_usd
        msgs: list[str] = []
        for th in sorted(self.credit.thresholds):
            if pct >= th and th not in self._warned:
                self._warned.add(th)
                msgs.append(
                    f"spend ${total:.2f} / ${self.credit.cap_usd:.2f} "
                    f"crossed {int(th * 100)}% of the credit window"
                )
        return msgs

    def _kill_switch_set(self, config: Config) -> bool:
        if config.kill_switch:
            return True
        return bool(self.kill_switch_file and Path(self.kill_switch_file).exists())

    def check(self, config: Config) -> None:
        if self._kill_switch_set(config):
            raise KillSwitchEngaged("kill switch engaged; aborting batch")
        c = self.caps
        if c.max_tokens and self.tokens > c.max_tokens:
            raise BudgetExceeded(f"max_tokens exceeded ({self.tokens} > {c.max_tokens})")
        if c.max_requests and self.requests > c.max_requests:
            raise BudgetExceeded(f"max_requests exceeded ({self.requests} > {c.max_requests})")
        if c.max_usd and self.usd > c.max_usd:
            raise BudgetExceeded(f"max_usd (per-run) exceeded (${self.usd:.2f} > ${c.max_usd:.2f})")
        if c.max_wall_clock_seconds:
            elapsed = time.monotonic() - self._started
            if elapsed > c.max_wall_clock_seconds:
                raise BudgetExceeded(f"max_wall_clock exceeded ({elapsed:.0f}s)")
        if self.credit.cap_usd > 0 and self.store.total_spend_usd() > self.credit.cap_usd:
            raise BudgetExceeded("credit-window cap exceeded; stopping")
