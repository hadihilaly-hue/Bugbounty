"""Deterministic tests for benchmark metrics (no network / no Juice Shop)."""

from bugbounty.validator.benchmark import Metrics, build_cases


def test_metrics_perfect_scores():
    m = Metrics(tp=3, fp=0, tn=3, fn=0)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.fp_rate == 0.0


def test_metrics_with_errors():
    m = Metrics(tp=2, fp=1, tn=2, fn=1)
    assert m.precision == 2 / 3
    assert m.recall == 2 / 3
    assert m.fp_rate == 1 / 3


def test_metrics_empty_is_safe():
    m = Metrics()
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.fp_rate == 0.0


def test_build_cases_are_balanced_and_scoped():
    cases = build_cases("http://localhost:3000", "http://localhost:3000/rest/basket/9", "Melon")
    expects = [exp for _, exp in cases]
    assert expects.count(True) == 3 and expects.count(False) == 3
    assert all(c.host == "localhost" for c, _ in cases)
