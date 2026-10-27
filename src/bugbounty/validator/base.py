"""Proof-harness contract.

A harness attempts to *prove* a candidate by executing against the target. It
never trusts the candidate's claim. If it cannot run a conclusive proof it
raises ``HarnessUnavailable`` (which the engine maps to UNCONFIRMED) rather than
guessing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..config import Config
from ..scope import Target
from .models import Candidate, ValidationResult, VulnClass


class HarnessUnavailable(Exception):
    """A proof could not be executed (missing dep/creds, unreachable target)."""


class ProofHarness(ABC):
    vuln_class: VulnClass
    # True if proving this class requires sending an active exploit payload.
    # The engine refuses to run such harnesses unless the dry-run gates are open.
    sends_active_payload: bool = True

    @abstractmethod
    def run(self, candidate: Candidate, target: Target, config: Config) -> ValidationResult:
        """Execute a proof and return CONFIRMED or REJECTED. Raise
        HarnessUnavailable if no conclusive proof could be executed."""
        raise NotImplementedError
