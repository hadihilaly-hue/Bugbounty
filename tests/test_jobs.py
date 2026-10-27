"""Tests for the FP benchmark and the nightly report."""

from bugbounty.jobs.fp_benchmark import run_fp_benchmark
from bugbounty.jobs.report import build_report
from bugbounty.orchestrator.budget import CreditWindow
from bugbounty.orchestrator.store import Store


def test_fp_benchmark_no_false_positives():
    metrics, rows = run_fp_benchmark()
    assert len(rows) == 6
    assert metrics.tp == 3 and metrics.tn == 3 and metrics.fp == 0 and metrics.fn == 0
    assert metrics.precision == 1.0 and metrics.recall == 1.0 and metrics.fp_rate == 0.0


def test_report_credit_warnings(tmp_path):
    st = Store(str(tmp_path / "r.db"))
    st.record_spend(job="finder", usd=90.0, target_name="t")
    text = build_report(st, CreditWindow(cap_usd=100.0))
    assert "crossed 50% of the credit window" in text
    assert "crossed 75% of the credit window" in text
    assert "crossed 90% of the credit window" in text


def test_report_over_cap(tmp_path):
    st = Store(str(tmp_path / "r.db"))
    st.record_spend(job="finder", usd=120.0, target_name="t")
    text = build_report(st, CreditWindow(cap_usd=100.0))
    assert "OVER the credit cap" in text


def test_report_records_benchmark(tmp_path):
    st = Store(str(tmp_path / "r.db"))
    metrics, _ = run_fp_benchmark()
    st.record_benchmark("fp-benchmark", metrics)
    text = build_report(st)
    assert "Sandbox benchmark" in text and "fp-benchmark" in text
