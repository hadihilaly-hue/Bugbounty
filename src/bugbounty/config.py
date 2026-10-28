"""Global runtime configuration and safety guardrails.

Every guardrail here is enforced in code, not just documented. The defaults are
deliberately conservative: dry-run on, active payloads off, tight budget caps.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean env var, failing loudly rather than failing open.

    An unset or blank value keeps the (safe) default. An unrecognised value
    raises instead of silently reading as False -- a typo in DRY_RUN must never
    be what turns active exploit payloads on.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(
        f"{name}={raw!r} is not a boolean; use one of {sorted(_TRUE_VALUES | _FALSE_VALUES)}"
    )


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return float(raw)


@dataclass(frozen=True)
class BudgetCaps:
    """Hard per-run ceilings. The orchestrator aborts a run when any is hit."""

    max_tokens: int = field(default_factory=lambda: _env_int("BB_MAX_TOKENS", 2_000_000))
    max_requests: int = field(default_factory=lambda: _env_int("BB_MAX_REQUESTS", 5_000))
    max_wall_clock_seconds: int = field(
        default_factory=lambda: _env_int("BB_MAX_WALL_CLOCK_SECONDS", 3 * 60 * 60)
    )
    max_usd: float = field(default_factory=lambda: _env_float("BB_MAX_USD", 10.0))


@dataclass(frozen=True)
class Config:
    """Process-wide settings.

    DRY_RUN defaults to True. In dry-run the harness does recon + static analysis
    + reasoning but sends NO active exploit payloads. Active payloads require
    DRY_RUN off AND the specific target's own ``dry_run`` cleared.
    """

    dry_run: bool = field(default_factory=lambda: _env_bool("DRY_RUN", True))
    kill_switch: bool = field(default_factory=lambda: _env_bool("BB_KILL_SWITCH", False))
    concurrency: int = field(default_factory=lambda: _env_int("BB_CONCURRENCY", 10))
    requests_per_second: float = field(
        default_factory=lambda: _env_float("BB_REQUESTS_PER_SECOND", 2.0)
    )
    # Per-host politeness: pace requests to a single target and back off on 429.
    # Conservative defaults so we never hammer one host even with concurrency.
    per_host_rps: float = field(default_factory=lambda: _env_float("BB_PER_HOST_RPS", 1.0))
    pacing_jitter: float = field(default_factory=lambda: _env_float("BB_PACING_JITTER", 0.1))
    max_retries_429: int = field(default_factory=lambda: _env_int("BB_MAX_RETRIES_429", 4))
    backoff_base_seconds: float = field(
        default_factory=lambda: _env_float("BB_BACKOFF_BASE_SECONDS", 0.5)
    )
    backoff_max_seconds: float = field(
        default_factory=lambda: _env_float("BB_BACKOFF_MAX_SECONDS", 30.0)
    )
    budget: BudgetCaps = field(default_factory=BudgetCaps)

    def active_payloads_allowed(self, target_dry_run: bool) -> bool:
        """Active exploit payloads are allowed only when every gate is open.

        Both the global ``dry_run`` and the per-target ``dry_run`` must be False,
        and the kill switch must be off.
        """
        return not self.dry_run and not target_dry_run and not self.kill_switch


def load_config() -> Config:
    return Config()
