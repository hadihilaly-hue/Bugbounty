"""Modular evaluation targets: one adapter per ground-truth sandbox.

Each adapter encodes a sandbox's KNOWN-bug list as labelled cases and grades the
validator against that answer key. Adapters never change the core validator or
its harnesses; they only build candidates + ground-truth and call the validator.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from ...config import Config
from ...scope import Target
from ...validator.benchmark import Metrics
from ...validator.engine import Validator
from ...validator.models import Candidate, ValidationStatus

EvalRow = tuple[str, str, str, bool, str, str, str]
# (candidate_id, vuln_class, category, vulnerable, validator_status, note, reason)


@dataclass
class EvalCase:
    candidate: Candidate
    vulnerable: bool
    # "supported" cases count toward the supported-only metrics; "limitation"/
    # "reflection" cases count only toward the all-cases metrics and flag a
    # deliberately weaker or uncovered proof.
    category: str = "supported"
    note: str = ""


@dataclass
class EvalResult:
    target: str
    available: bool
    metrics: Metrics = field(default_factory=Metrics)
    metrics_supported: Metrics = field(default_factory=Metrics)
    rows: list[EvalRow] = field(default_factory=list)
    note: str = ""


def grade(
    cases: list[EvalCase], validator: Validator, target: Target
) -> tuple[Metrics, Metrics, list[EvalRow]]:
    """Run every case through the validator and tally confusion metrics.

    Returns (all_cases_metrics, supported_only_metrics, rows)."""
    m, ms = Metrics(), Metrics()
    rows: list[EvalRow] = []
    for cs in cases:
        res = validator.validate(cs.candidate, target)
        confirmed = res.status is ValidationStatus.CONFIRMED
        outcome = (
            "tp"
            if (cs.vulnerable and confirmed)
            else "fn"
            if cs.vulnerable
            else "fp"
            if confirmed
            else "tn"
        )
        for meter in [m, ms] if cs.category == "supported" else [m]:
            setattr(meter, outcome, getattr(meter, outcome) + 1)
        rows.append(
            (
                cs.candidate.id,
                cs.candidate.vuln_class.value,
                cs.category,
                cs.vulnerable,
                res.status.value,
                cs.note,
                res.reason or "",
            )
        )
    return m, ms, rows


class EvalTarget(abc.ABC):
    """A gradable sandbox. Subclasses set name/base_url and implement run()."""

    name: str = "target"
    base_url: str = ""

    @abc.abstractmethod
    def docker_setup(self) -> str:
        """Human-runnable command(s) to stand the sandbox up locally."""

    @abc.abstractmethod
    def run(self, config: Config | None = None) -> EvalResult:
        """Grade the validator against this sandbox's answer key."""

    def available(self) -> bool:
        import httpx

        try:
            return httpx.get(self.base_url, timeout=5.0, follow_redirects=True).status_code < 500
        except Exception:  # noqa: BLE001 - unreachable sandbox is just "unavailable"
            return False


__all__ = ["EvalCase", "EvalResult", "EvalRow", "EvalTarget", "grade"]
