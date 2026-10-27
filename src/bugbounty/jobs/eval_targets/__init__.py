"""Registry of evaluation-target adapters (one adapter per ground-truth sandbox)."""

from __future__ import annotations

from .base import EvalCase, EvalResult, EvalRow, EvalTarget, grade
from .benchmark import OwaspBenchmarkTarget
from .crapi import CrapiTarget
from .dvwa import DvwaTarget
from .juiceshop import JuiceShopTarget


def all_targets() -> dict[str, EvalTarget]:
    targets: list[EvalTarget] = [
        JuiceShopTarget(),
        DvwaTarget(),
        CrapiTarget(),
        OwaspBenchmarkTarget(),
    ]
    return {t.name: t for t in targets}


__all__ = [
    "CrapiTarget",
    "DvwaTarget",
    "EvalCase",
    "EvalResult",
    "EvalRow",
    "EvalTarget",
    "JuiceShopTarget",
    "OwaspBenchmarkTarget",
    "all_targets",
    "grade",
]
