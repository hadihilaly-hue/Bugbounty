"""The finder: recon + cheap signal + optional Anthropic reasoning -> candidates.

Candidates are *claims*; the validator is the gate. The finder favours concrete,
checkable candidates (with the params a proof harness needs) over vague ones.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..config import Config
from ..recon.http import Recon, recon_http
from ..scope import Platform, Target
from ..signal.base import Signal, SignalUnavailable
from ..validator import Candidate
from .anthropic_client import AnthropicReasoner
from .heuristics import heuristic_candidates

SYSTEM_PROMPT = (
    "You are the FINDER in a validator-first bug-bounty harness. From the recon "
    "and scanner signals you are given, propose candidate vulnerabilities for the "
    "SPECIFIED host only. A separate adversarial validator will try to DISPROVE "
    "every candidate with an executed proof, so prefer concrete, checkable "
    "candidates and include the params a proof needs. Respond with ONLY a JSON "
    "array of objects with keys: id, vuln_class (one of xss, idor, ssrf, auth, "
    "injection, other), title, url, description, params. For injection/ssrf/auth "
    "set params.requests (list of {method,url,body}) and params.oracle "
    "({type: contains|status|regex, value, in: body|status}). For xss set url to "
    "a link whose load executes JS. Do not target any other host."
)


@dataclass
class FinderResult:
    candidates: list[Candidate]
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    notes: list[str] = field(default_factory=list)


def _extract_json_array(text: str) -> str | None:
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start : end + 1]


def parse_candidates_json(text: str, target_name: str, host: str) -> list[Candidate]:
    block = _extract_json_array(text)
    if block is None:
        return []
    try:
        items = json.loads(block)
    except json.JSONDecodeError:
        return []
    out: list[Candidate] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        item.setdefault(
            "id", f"llm-{re.sub(r'[^a-z0-9]+', '-', str(item.get('title', i)).lower())[:24]}"
        )
        item["target_name"] = target_name
        item.setdefault("host", host)
        item.setdefault("url", "")
        item.setdefault("source", "llm")
        try:
            out.append(Candidate.model_validate(item))
        except Exception:  # noqa: BLE001 - drop malformed LLM items
            continue
    return out


class Finder:
    def __init__(self, config: Config, reasoner: AnthropicReasoner | None = None) -> None:
        self.config = config
        self.reasoner = reasoner

    def find(
        self,
        target: Target,
        base_url: str | None = None,
        code_path: str | None = None,
        use_llm: bool = True,
        max_candidates: int = 25,
        recon: Recon | None = None,
        scope=None,
    ) -> FinderResult:
        notes: list[str] = []
        if recon is None:
            recon = (
                recon_http(
                    base_url,
                    config=self.config,
                    scope=scope,
                    headers=(target.required_headers or None),
                    per_host_rps=(target.rate_limit.per_host_rps if target.rate_limit else None),
                )
                if base_url
                else Recon(base_url=base_url or "")
            )
        notes.extend(recon.notes)

        signals: list[Signal] = []
        if code_path:
            try:
                from ..signal.semgrep import run_semgrep

                signals.extend(run_semgrep(code_path))
            except SignalUnavailable as exc:
                notes.append(f"semgrep skipped: {exc}")
        if base_url and target.platform is not Platform.SELF and target.required_headers:
            notes.append(
                "nuclei skipped: the scanner can't carry this target's required "
                "attribution headers, so it must not scan a real program"
            )
        elif base_url:
            try:
                from ..signal.nuclei import run_nuclei

                signals.extend(run_nuclei(base_url))
            except SignalUnavailable as exc:
                notes.append(f"nuclei skipped: {exc}")

        cands = heuristic_candidates(target.name, base_url, recon, signals) if base_url else []
        result = FinderResult(candidates=[], notes=notes)

        if use_llm and self.reasoner and self.reasoner.available():
            host = (urlparse(base_url).hostname or "") if base_url else ""
            try:
                llm = self.reasoner.complete(
                    SYSTEM_PROMPT, self._user_prompt(target, base_url, recon, signals)
                )
                result.cost_usd = llm.usd
                result.input_tokens = llm.input_tokens
                result.output_tokens = llm.output_tokens
                cands += parse_candidates_json(llm.text, target.name, host)
            except Exception as exc:  # noqa: BLE001 - LLM failure is non-fatal
                notes.append(f"llm finder skipped: {type(exc).__name__}: {exc}")

        seen: set[str] = set()
        deduped: list[Candidate] = []
        for cand in cands:
            if cand.id in seen:
                continue
            seen.add(cand.id)
            deduped.append(cand)
            if len(deduped) >= max_candidates:
                break
        result.candidates = deduped
        return result

    def _user_prompt(
        self, target: Target, base_url: str | None, recon: Recon, signals: list[Signal]
    ) -> str:
        payload = {
            "host": (urlparse(base_url).hostname if base_url else None),
            "base_url": base_url,
            "endpoints": recon.endpoints[:60],
            "params": recon.params[:40],
            "signals": [
                {"source": s.source, "kind": s.kind, "severity": s.severity, "where": s.location}
                for s in signals[:40]
            ],
        }
        return json.dumps(payload, indent=2)
