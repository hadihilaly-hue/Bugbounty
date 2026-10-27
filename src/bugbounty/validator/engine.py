"""The validator engine.

Adversarial by construction: a candidate is only ever CONFIRMED when a harness
executes a proof whose oracle demonstrates the bug. Anything else is REJECTED
(actively disproven) or UNCONFIRMED (could not be proven). Errors never yield
CONFIRMED.
"""

from __future__ import annotations

from ..config import Config
from ..scope import Target
from .base import HarnessUnavailable, ProofHarness
from .models import Candidate, ValidationResult, ValidationStatus, VulnClass


def _result(candidate: Candidate, status: ValidationStatus, reason: str, **kw) -> ValidationResult:
    return ValidationResult(
        candidate_id=candidate.id,
        vuln_class=candidate.vuln_class,
        status=status,
        reason=reason,
        **kw,
    )


class Validator:
    def __init__(
        self,
        config: Config,
        harnesses: dict[VulnClass, ProofHarness] | None = None,
    ) -> None:
        self.config = config
        if harnesses is None:
            from .harnesses import default_harnesses

            harnesses = default_harnesses()
        self.harnesses = harnesses

    def validate(self, candidate: Candidate, target: Target) -> ValidationResult:
        harness = self.harnesses.get(candidate.vuln_class)
        if harness is None:
            return _result(
                candidate,
                ValidationStatus.UNCONFIRMED,
                f"no proof harness for class {candidate.vuln_class.value!r}",
            )
        if harness.sends_active_payload and not self.config.active_payloads_allowed(target.dry_run):
            return _result(
                candidate,
                ValidationStatus.UNCONFIRMED,
                "active payloads disabled (global dry-run, target dry-run, or kill "
                "switch); cannot execute a proof",
            )
        try:
            return harness.run(candidate, target, self.config)
        except HarnessUnavailable as exc:
            return _result(candidate, ValidationStatus.UNCONFIRMED, f"proof could not run: {exc}")
        except Exception as exc:  # noqa: BLE001 - adversarial: errors never confirm
            return _result(
                candidate,
                ValidationStatus.UNCONFIRMED,
                f"harness error ({type(exc).__name__}): {exc}",
            )
