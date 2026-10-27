"""Default proof-harness registry (one per vuln class)."""

from __future__ import annotations

from ..base import ProofHarness
from ..models import VulnClass


def default_harnesses() -> dict[VulnClass, ProofHarness]:
    from .httppoc import HttpPocHarness
    from .idor import IdorHarness
    from .xss import XssHarness

    return {
        VulnClass.XSS: XssHarness(),
        VulnClass.IDOR: IdorHarness(),
        VulnClass.SSRF: HttpPocHarness(VulnClass.SSRF),
        VulnClass.AUTH: HttpPocHarness(VulnClass.AUTH),
        VulnClass.INJECTION: HttpPocHarness(VulnClass.INJECTION),
        VulnClass.OTHER: HttpPocHarness(VulnClass.OTHER),
    }
