"""Orchestrator: persistence, budgets, kill switch, resume, weak-target stop."""

import sqlite3

import pytest

from bugbounty.config import BudgetCaps, Config
from bugbounty.orchestrator import CreditWindow, Orchestrator, Store
from bugbounty.scope import Allowlist, Platform, Target
from bugbounty.validator import Candidate, VulnClass
from bugbounty.validator.models import ValidationResult, ValidationStatus


def _allowlist() -> Allowlist:
    return Allowlist(
        targets=[
            Target(
                name="t",
                platform=Platform.SELF,
                safe_harbor_url="https://x/sh",
                in_scope=["localhost"],
                dry_run=False,
            )
        ]
    )


def _cand(i: int, host: str = "localhost") -> Candidate:
    return Candidate(
        id=f"c{i}",
        target_name="t",
        vuln_class=VulnClass.XSS,
        title="x",
        url="http://localhost/",
        host=host,
    )


class _FakeValidator:
    def __init__(self, status: ValidationStatus) -> None:
        self._status = status

    def validate(self, cand, target) -> ValidationResult:
        return ValidationResult(
            candidate_id=cand.id, vuln_class=cand.vuln_class, status=self._status, reason="fake"
        )


def _cfg(**kw) -> Config:
    kw.setdefault("dry_run", False)
    kw.setdefault("concurrency", 1)
    return Config(**kw)


def _store(tmp_path) -> Store:
    return Store(tmp_path / "t.db")


def test_store_roundtrip(tmp_path):
    st = _store(tmp_path)
    res = ValidationResult(
        candidate_id="c1", vuln_class=VulnClass.XSS, status=ValidationStatus.CONFIRMED, reason="x"
    )
    st.record_validation("b1", "r1", "t", res)
    st.record_validation("b1", "r1", "t", res)  # dup ignored
    assert st.validated_candidate_ids("b1") == {"c1"}
    assert len(st.confirmed("b1")) == 1
    st.record_spend("j", usd=2.5, batch_id="b1", target_name="t")
    assert st.total_spend_usd() == 2.5
    assert st.spend_by_target("b1") == {"t": 2.5}


def test_run_batch_persists_and_counts(tmp_path):
    st = _store(tmp_path)
    orch = Orchestrator(_cfg(), st, validator=_FakeValidator(ValidationStatus.CONFIRMED))
    res = orch.run_batch(_allowlist(), [_cand(i) for i in range(3)])
    assert res.confirmed == 3 and not res.aborted
    assert len(st.confirmed(res.batch_id)) == 3


def test_out_of_scope_filtered(tmp_path):
    orch = Orchestrator(
        _cfg(), _store(tmp_path), validator=_FakeValidator(ValidationStatus.CONFIRMED)
    )
    res = orch.run_batch(_allowlist(), [_cand(0, host="evil.com"), _cand(1)])
    assert res.out_of_scope == 1 and res.confirmed == 1


def test_resume_skips_done(tmp_path):
    st = _store(tmp_path)
    orch = Orchestrator(_cfg(), st, validator=_FakeValidator(ValidationStatus.REJECTED))
    r1 = orch.run_batch(_allowlist(), [_cand(0), _cand(1)], batch_id="b")
    assert r1.rejected == 2
    r2 = orch.run_batch(_allowlist(), [_cand(0), _cand(1), _cand(2)], batch_id="b", resume=True)
    assert r2.rejected == 1  # only the new candidate re-validated
    assert st.validated_candidate_ids("b") == {"c0", "c1", "c2"}


def test_kill_switch_aborts(tmp_path):
    orch = Orchestrator(
        _cfg(kill_switch=True),
        _store(tmp_path),
        validator=_FakeValidator(ValidationStatus.CONFIRMED),
    )
    res = orch.run_batch(_allowlist(), [_cand(0)])
    assert res.aborted and "kill switch" in res.reason


def test_budget_usd_cap_aborts(tmp_path):
    caps = BudgetCaps(max_usd=2.0)
    orch = Orchestrator(
        _cfg(budget=caps),
        _store(tmp_path),
        validator=_FakeValidator(ValidationStatus.REJECTED),
        cost_fn=lambda r: (1.0, 0, 0),
    )
    res = orch.run_batch(_allowlist(), [_cand(i) for i in range(6)])
    assert res.aborted and "max_usd" in res.reason


def test_credit_window_warnings(tmp_path):
    orch = Orchestrator(
        _cfg(),
        _store(tmp_path),
        validator=_FakeValidator(ValidationStatus.REJECTED),
        credit=CreditWindow(cap_usd=10.0),
        cost_fn=lambda r: (3.0, 0, 0),
    )
    res = orch.run_batch(_allowlist(), [_cand(i) for i in range(4)])
    joined = " ".join(res.warnings)
    assert "50%" in joined and "75%" in joined and "90%" in joined


def test_weak_target_early_stop(tmp_path):
    st = _store(tmp_path)
    orch = Orchestrator(_cfg(), st, validator=_FakeValidator(ValidationStatus.REJECTED))
    res = orch.run_batch(
        _allowlist(), [_cand(i) for i in range(12)], batch_id="b", weak_target_min_attempts=4
    )
    assert not res.aborted
    con = sqlite3.connect(str(st.path))
    statuses = [r[0] for r in con.execute("SELECT status FROM runs WHERE batch_id='b'").fetchall()]
    con.close()
    assert "early_stop" in statuses
    assert res.rejected < 12  # stopped before validating all


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
