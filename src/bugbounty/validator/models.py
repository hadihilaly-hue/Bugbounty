"""Data models for the adversarial validator.

The validator assumes the finder is lying. A candidate finding is never trusted
on its own; a status other than REJECTED/UNCONFIRMED requires the validator to
have *executed* a proof whose oracle positively demonstrated the bug.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class VulnClass(StrEnum):
    XSS = "xss"
    IDOR = "idor"
    SSRF = "ssrf"
    AUTH = "auth"  # broken authentication / OAuth
    INJECTION = "injection"  # sql / nosql / command
    OTHER = "other"


class ValidationStatus(StrEnum):
    # Our proof executed and its oracle demonstrated the bug. Only this status
    # reaches the default review queue.
    CONFIRMED = "confirmed"
    # Our proof executed and its oracle showed the bug is NOT present.
    REJECTED = "rejected"
    # No conclusive proof could run (dry-run, missing creds, target down,
    # unsupported class, harness error). We neither confirm nor disprove.
    UNCONFIRMED = "unconfirmed"


class Candidate(BaseModel):
    """A finding the finder *claims* exists. Treated as an unproven assertion."""

    id: str
    target_name: str
    vuln_class: VulnClass
    title: str
    url: str
    host: str
    description: str = ""
    # Class-specific inputs the harness needs to attempt a proof, e.g.
    # {"param": "q", "payload": "<script>...</script>"} for XSS, or
    # {"victim_path": "/api/orders/2", "marker": "victim@..."} for IDOR.
    params: dict = Field(default_factory=dict)
    source: str = "finder"


class Evidence(BaseModel):
    kind: str  # "screenshot" | "http" | "console" | "note"
    label: str
    content: str = ""  # inline text (request/response/console log)
    path: str | None = None  # artifact path (e.g. screenshot png)


class ValidationResult(BaseModel):
    candidate_id: str
    vuln_class: VulnClass
    status: ValidationStatus
    reason: str
    reproducible: bool = False
    poc: str | None = None  # rerunnable proof-of-concept (text / shell / http)
    evidence: list[Evidence] = Field(default_factory=list)
    validator: str = "deterministic"
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def in_review_queue(self) -> bool:
        """Only CONFIRMED findings surface in the default review queue."""
        return self.status is ValidationStatus.CONFIRMED
