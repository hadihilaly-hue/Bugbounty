"""Engine-level tests: adversarial gating and status mapping with fake harnesses."""

from bugbounty.config import Config
from bugbounty.scope import Platform, Target
from bugbounty.validator import Candidate, Validator, VulnClass
from bugbounty.validator.base import HarnessUnavailable, ProofHarness
from bugbounty.validator.models import ValidationResult, ValidationStatus


def _target(dry_run: bool) -> Target:
    return Target(
        name="t",
        platform=Platform.SELF,
        safe_harbor_url="https://example.com/sh",
        in_scope=["localhost"],
        dry_run=dry_run,
    )


def _candidate(vc: VulnClass = VulnClass.XSS) -> Candidate:
    return Candidate(
        id="c1",
        target_name="t",
        vuln_class=vc,
        title="x",
        url="http://localhost/",
        host="localhost",
    )


class _Harness(ProofHarness):
    vuln_class = VulnClass.XSS

    def __init__(self, status=None, exc=None, active=True):
        self._status = status
        self._exc = exc
        self.sends_active_payload = active

    def run(self, candidate, target, config):
        if self._exc is not None:
            raise self._exc
        return ValidationResult(
            candidate_id=candidate.id,
            vuln_class=candidate.vuln_class,
            status=self._status,
            reason="fake",
        )


def _validator(harness, **cfg):
    return Validator(Config(**cfg), harnesses={VulnClass.XSS: harness})


def test_confirmed_passes_through_when_gates_open():
    v = _validator(_Harness(status=ValidationStatus.CONFIRMED), dry_run=False)
    r = v.validate(_candidate(), _target(dry_run=False))
    assert r.status is ValidationStatus.CONFIRMED
    assert r.in_review_queue is True


def test_global_dry_run_blocks_active_payload_as_unconfirmed():
    v = _validator(_Harness(status=ValidationStatus.CONFIRMED), dry_run=True)
    r = v.validate(_candidate(), _target(dry_run=False))
    assert r.status is ValidationStatus.UNCONFIRMED
    assert r.in_review_queue is False


def test_target_dry_run_blocks_active_payload():
    v = _validator(_Harness(status=ValidationStatus.CONFIRMED), dry_run=False)
    r = v.validate(_candidate(), _target(dry_run=True))
    assert r.status is ValidationStatus.UNCONFIRMED


def test_kill_switch_blocks_active_payload():
    v = _validator(_Harness(status=ValidationStatus.CONFIRMED), dry_run=False, kill_switch=True)
    r = v.validate(_candidate(), _target(dry_run=False))
    assert r.status is ValidationStatus.UNCONFIRMED


def test_passive_harness_runs_even_in_dry_run():
    v = _validator(_Harness(status=ValidationStatus.REJECTED, active=False), dry_run=True)
    r = v.validate(_candidate(), _target(dry_run=True))
    assert r.status is ValidationStatus.REJECTED


def test_unknown_class_is_unconfirmed():
    v = Validator(Config(dry_run=False), harnesses={})
    r = v.validate(_candidate(VulnClass.SSRF), _target(dry_run=False))
    assert r.status is ValidationStatus.UNCONFIRMED


def test_harness_error_never_confirms():
    v = _validator(_Harness(exc=RuntimeError("boom")), dry_run=False)
    r = v.validate(_candidate(), _target(dry_run=False))
    assert r.status is ValidationStatus.UNCONFIRMED
    assert "boom" in r.reason


def test_harness_unavailable_is_unconfirmed():
    v = _validator(_Harness(exc=HarnessUnavailable("no creds")), dry_run=False)
    r = v.validate(_candidate(), _target(dry_run=False))
    assert r.status is ValidationStatus.UNCONFIRMED
    assert "no creds" in r.reason
