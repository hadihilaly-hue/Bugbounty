"""Adversarial validator: disprove candidate findings; require executed proofs."""

from .engine import Validator
from .models import (
    Candidate,
    Evidence,
    ValidationResult,
    ValidationStatus,
    VulnClass,
)

__all__ = [
    "Validator",
    "Candidate",
    "Evidence",
    "ValidationResult",
    "ValidationStatus",
    "VulnClass",
]
