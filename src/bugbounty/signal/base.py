"""Shared types for cheap deterministic signal sources (Semgrep, Nuclei)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Signal:
    source: str  # "semgrep" | "nuclei"
    kind: str  # rule id / template id
    severity: str
    location: str  # file:line or matched URL
    message: str


class SignalUnavailable(Exception):
    """A signal tool could not run (binary missing, bad output)."""
