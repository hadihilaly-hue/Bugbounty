"""Deterministic tests for the modular evaluation-target adapters.

No live sandbox: grading is tested with a stub validator, answer-key parsing on a
temp CSV, and unavailability via monkeypatch.
"""

from __future__ import annotations

from bugbounty.jobs.eval_targets import (
    CrapiTarget,
    DvwaTarget,
    EvalCase,
    OwaspBenchmarkTarget,
    all_targets,
    grade,
)
from bugbounty.jobs.eval_targets import benchmark as bm
from bugbounty.jobs.report import build_report
from bugbounty.orchestrator.store import Store
from bugbounty.scope import Platform, Target
from bugbounty.validator.benchmark import Metrics
from bugbounty.validator.models import (
    Candidate,
    ValidationResult,
    ValidationStatus,
    VulnClass,
)


def _cand(cid: str, cls: VulnClass = VulnClass.OTHER) -> Candidate:
    return Candidate(id=cid, target_name="t", vuln_class=cls, title=cid, url="http://x", host="x")


def _target() -> Target:
    return Target(name="t", platform=Platform.SELF, safe_harbor_url="x", in_scope=["x"])


class _StubValidator:
    def __init__(self, confirm_ids: set[str]) -> None:
        self.confirm_ids = confirm_ids

    def validate(self, c: Candidate, _t: Target) -> ValidationResult:
        status = (
            ValidationStatus.CONFIRMED if c.id in self.confirm_ids else ValidationStatus.REJECTED
        )
        return ValidationResult(
            candidate_id=c.id, vuln_class=c.vuln_class, status=status, reason="stub"
        )


def test_registry_has_all_targets():
    assert set(all_targets()) == {"juiceshop", "dvwa", "crapi", "owasp-benchmark"}


def test_every_target_documents_docker_setup():
    for t in all_targets().values():
        assert t.docker_setup().strip()


def test_grade_perfect_classification():
    cases = [EvalCase(_cand("a"), True), EvalCase(_cand("b"), False)]
    m, ms, rows = grade(cases, _StubValidator({"a"}), _target())
    assert (m.tp, m.fp, m.tn, m.fn) == (1, 0, 1, 0)
    assert m.precision == 1.0 and m.recall == 1.0 and m.fp_rate == 0.0
    assert len(rows) == 2 and rows[0][0] == "a"


def test_grade_supported_split_from_all():
    cases = [
        EvalCase(_cand("a"), True, "supported"),
        EvalCase(_cand("b"), True, "limitation"),
    ]
    m, ms, _ = grade(cases, _StubValidator(set()), _target())  # nothing confirmed
    assert m.fn == 2  # both missed in all-cases
    assert ms.fn == 1  # supported-only ignores the limitation case


def test_unavailable_sandbox_returns_no_metrics(monkeypatch):
    t = DvwaTarget()
    monkeypatch.setattr(t, "available", lambda: False)
    res = t.run()
    assert res.available is False
    assert res.metrics.tp == 0 and "docker_setup" in res.note


def test_crapi_answer_key_shape():
    cases = CrapiTarget()._cases()
    assert len(cases) == 5
    assert sum(1 for c in cases if c.vulnerable) == 3
    idor = [c for c in cases if c.candidate.vuln_class == VulnClass.IDOR]
    assert idor and all("victim_marker" in c.candidate.params for c in idor)


def test_owasp_benchmark_answer_key(tmp_path, monkeypatch):
    csvf = tmp_path / "expectedresults-1.2.csv"
    csvf.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
        "BenchmarkTest00003,xss,true,79\n"
    )
    monkeypatch.setattr(bm, "_CSV_CANDIDATES", (str(csvf),))
    key = OwaspBenchmarkTarget().answer_key()
    assert key["total"] == 3 and key["true"] == 2 and key["false"] == 1
    assert key["by_category"]["sqli"] == {"true": 1, "false": 1}
    res = OwaspBenchmarkTarget().run()
    assert res.available is False and "3 cases" in res.note


def test_store_and_report_compare_targets(tmp_path):
    db = str(tmp_path / "bench.db")
    store = Store(db)
    store.record_benchmark("eval:juiceshop", Metrics(tp=10, fp=0, tn=6, fn=2))
    store.record_benchmark("eval:dvwa", Metrics(tp=4, fp=0, tn=4, fn=0))
    rows = store.latest_benchmarks_by_name()
    assert {r["name"] for r in rows} == {"eval:juiceshop", "eval:dvwa"}
    report = build_report(store)
    assert "Eval targets (latest per sandbox)" in report
    assert "eval:dvwa" in report and "eval:juiceshop" in report
