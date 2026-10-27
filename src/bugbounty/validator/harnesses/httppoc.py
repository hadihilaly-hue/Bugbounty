"""Generic rerunnable HTTP proof-of-concept harness (SSRF / auth / injection).

The candidate supplies an ordered request sequence and a success oracle. The
harness replays it, evaluates the oracle, and emits a curl-based PoC so a human
can rerun it. CONFIRMED only when the oracle positively matches.
"""

from __future__ import annotations

import json
import re
import shlex

from ...config import Config
from ...scope import Target
from ..base import HarnessUnavailable, ProofHarness
from ..models import Candidate, Evidence, ValidationResult, ValidationStatus, VulnClass


def _curl(req: dict) -> str:
    parts = ["curl", "-sS", "-X", req.get("method", "GET").upper()]
    headers = dict(req.get("headers") or {})
    body = req.get("body")
    # Mirror the harness's httpx call: a dict body is sent as JSON, so the PoC
    # must declare it too or the server form-decodes it and the bug won't fire.
    if isinstance(body, dict) and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"
    for k, v in headers.items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if body is not None:
        data = body if isinstance(body, str) else json.dumps(body)
        parts += ["--data", shlex.quote(data)]
    parts.append(shlex.quote(req["url"]))
    return " ".join(parts)


def _oracle_matches(oracle: dict, status_code: int, body: str) -> bool:
    kind = oracle.get("type", "contains")
    where = oracle.get("in", "body")
    target = body if where == "body" else str(status_code)
    if kind == "status":
        return status_code == int(oracle["value"])
    if kind == "contains":
        return str(oracle["value"]) in target
    if kind == "regex":
        return re.search(oracle["value"], target) is not None
    raise HarnessUnavailable(f"unknown oracle type {kind!r}")


class HttpPocHarness(ProofHarness):
    sends_active_payload = True

    def __init__(self, vuln_class: VulnClass) -> None:
        self.vuln_class = vuln_class

    def run(self, candidate: Candidate, target: Target, config: Config) -> ValidationResult:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise HarnessUnavailable("httpx not installed (pip install .[dynamic])") from exc

        requests = candidate.params.get("requests")
        oracle = candidate.params.get("oracle")
        if not requests or not oracle:
            raise HarnessUnavailable("candidate missing 'requests' and/or 'oracle' params")

        poc_lines: list[str] = []
        evidence: list[Evidence] = []
        last_status, last_body = 0, ""
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            for req in requests:
                method = req.get("method", "GET").upper()
                resp = client.request(
                    method,
                    req["url"],
                    headers=req.get("headers"),
                    content=(req["body"] if isinstance(req.get("body"), str) else None),
                    json=(req["body"] if isinstance(req.get("body"), dict) else None),
                )
                last_status, last_body = resp.status_code, resp.text
                poc_lines.append(_curl(req))
                evidence.append(
                    Evidence(
                        kind="http",
                        label=f"{method} {req['url']} -> {resp.status_code}",
                        content=last_body[:2000],
                    )
                )

        proved = _oracle_matches(oracle, last_status, last_body)
        poc = "\n".join(poc_lines)
        if proved:
            return ValidationResult(
                candidate_id=candidate.id,
                vuln_class=candidate.vuln_class,
                status=ValidationStatus.CONFIRMED,
                reason=f"oracle matched ({oracle.get('type')}={oracle.get('value')!r})",
                reproducible=True,
                poc=poc,
                evidence=evidence,
            )
        return ValidationResult(
            candidate_id=candidate.id,
            vuln_class=candidate.vuln_class,
            status=ValidationStatus.REJECTED,
            reason="oracle did not match; bug not demonstrated",
            poc=poc,
            evidence=evidence,
        )
