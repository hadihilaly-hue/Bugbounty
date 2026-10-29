"""Generic rerunnable HTTP proof-of-concept harness (SSRF / auth / injection).

The candidate supplies an ordered request sequence and a success oracle. The
harness replays it, threading captured values (e.g. an auth token from step 1
into step 2's header), evaluates the oracle against a chosen step, and emits a
rerunnable shell PoC. CONFIRMED only when the oracle positively matches.

Oracle strictness is the whole point: a "confirmed" must mean confirmed.

- ``contains`` / ``regex`` / ``status`` -- substring / pattern / status checks.
  Cheap and useful, but a short ``contains`` value false-positives easily; the
  stricter oracles below exist for exactly that reason.
- ``jwt``   -- the located value is a *structurally valid* JWT (three
  base64url segments, decodable JSON header+payload, a real ``alg``). This is
  the "a real auth token was returned" oracle, not "the word token appeared".
- ``oob``   -- an out-of-band callback fired. The harness mints a unique token,
  the request is expected to make the target call back to a collaborator, and
  the oracle asks an injected :class:`OobListener` whether *that* token was
  seen. No listener configured => UNCONFIRMED (we never guess an OOB hit).
- ``timing`` -- blind/time-based injection with no visible output: a baseline
  request and an injected (e.g. ``SLEEP(5)``) request are both timed, and the
  bug is confirmed only when the injected response is slower by a strict
  margin. Deliberately conservative so normal latency jitter cannot confirm it.

I/O is injectable (``transport`` / ``oob``) so the decision logic can be tested
deterministically without a live network or collaborator.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex
import statistics
import time
from typing import Any, Protocol

from ...config import Config
from ...scope import Target
from ..base import HarnessUnavailable, ProofHarness
from ..models import Candidate, Evidence, ValidationResult, ValidationStatus, VulnClass

_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")


class OobListener(Protocol):
    """Out-of-band interaction collaborator (e.g. an interactsh client).

    Kept abstract on purpose: wiring a concrete collaborator is a sandbox/
    adapter concern, not the validator's. The validator only needs a unique
    token and a truthful answer to "did this token receive a callback?".
    """

    def token(self) -> str:
        """Return a fresh unique token/subdomain to embed in the payload."""

    def received(self, token: str) -> bool:
        """True iff an out-of-band interaction for ``token`` was observed."""


# --------------------------------------------------------------------------- #
# Pure helpers (no I/O) -- these carry the false-positive-sensitive logic.     #
# --------------------------------------------------------------------------- #


def _substitute(value: Any, ctx: dict[str, str]) -> Any:
    """Replace ``{{name}}`` placeholders from ``ctx`` inside strings/dicts/lists.

    An unknown placeholder is left untouched (fail loud later rather than
    silently sending an empty value that might flip an oracle).
    """
    if isinstance(value, str):
        return _PLACEHOLDER.sub(lambda m: ctx.get(m.group(1), m.group(0)), value)
    if isinstance(value, dict):
        return {k: _substitute(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, ctx) for v in value]
    return value


def _dig(obj: Any, dotted: str) -> Any:
    """Walk a dotted JSON path (``a.b.0.c``) over dict/list; raise on miss."""
    cur = obj
    for key in dotted.split("."):
        if isinstance(cur, list):
            cur = cur[int(key)]
        else:
            cur = cur[key]
    return cur


def _capture(spec: dict, status: int, headers: dict[str, str], body: str) -> str:
    """Extract one value from a response per a capture spec. Raise on failure."""
    src = spec.get("from", "json")
    if src == "json":
        try:
            return str(_dig(json.loads(body), spec["path"]))
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise HarnessUnavailable(
                f"capture {spec.get('name')!r}: json path {spec.get('path')!r} not found"
            ) from exc
    if src == "header":
        name = spec["header"].lower()
        for k, v in headers.items():
            if k.lower() == name:
                return v
        raise HarnessUnavailable(f"capture {spec.get('name')!r}: header {spec['header']!r} absent")
    if src == "regex":
        m = re.search(spec["pattern"], body)
        if not m:
            raise HarnessUnavailable(f"capture {spec.get('name')!r}: regex did not match")
        return m.group(1) if m.groups() else m.group(0)
    if src == "status":
        return str(status)
    raise HarnessUnavailable(f"unknown capture source {src!r}")


def _is_jwt(token: str) -> bool:
    """Structural JWT validity: three base64url parts, decodable JSON header +
    payload, and a non-empty ``alg`` in the header. Not a signature check -- we
    cannot verify the server's key -- but far stricter than a substring match,
    and enough to reject echoes like ``{"token": null}`` or an error blob."""
    if not isinstance(token, str):
        return False
    parts = token.strip().split(".")
    if len(parts) != 3 or not all(parts[:2]):
        return False

    def _seg(s: str) -> Any:
        pad = "=" * (-len(s) % 4)
        try:
            raw = base64.urlsafe_b64decode(s + pad)
        except (binascii.Error, ValueError):
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    header, payload = _seg(parts[0]), _seg(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return False
    return bool(header.get("alg"))


def _locate(oracle: dict, step: dict) -> str | None:
    """Find the token string a jwt oracle should validate, from the step's
    captured context, response headers, or JSON body."""
    source = oracle.get("source", "json")
    if source == "capture":
        return step.get("captured", {}).get(oracle["name"])
    if source == "header":
        name = oracle["header"].lower()
        for k, v in step.get("headers", {}).items():
            if k.lower() == name:
                return v
        return None
    try:
        return str(_dig(json.loads(step.get("body", "")), oracle.get("path", "")))
    except (ValueError, KeyError, IndexError, TypeError):
        return None


def _select_step(oracle: dict, steps: list[dict]) -> dict:
    """Pick the step the oracle evaluates. Default: the last one."""
    on = oracle.get("on")
    if on is None:
        return steps[-1]
    if isinstance(on, int):
        return steps[on]
    for s in steps:
        if s.get("name") == on:
            return s
    raise HarnessUnavailable(f"oracle 'on' references unknown step {on!r}")


def _timing_samples(steps: list[dict], name: str) -> list[float]:
    """Elapsed times of every step with this name (supports repeated sampling)."""
    return [s["elapsed"] for s in steps if s.get("name") == name and "elapsed" in s]


def evaluate_timing(baseline: list[float], inject: list[float], min_delta_seconds: float) -> bool:
    """Blind time-based oracle: did the injected request run measurably slower?

    Strict against jitter: the injected median must beat the baseline median by
    at least ``min_delta_seconds``, the injected median must itself be at least
    ``min_delta_seconds`` (a sub-threshold blip can't confirm a claim that
    relies on an N-second sleep), and -- when several samples are taken -- every
    injected sample must be slower than every baseline sample. Pair it with a
    large sleep (e.g. ``SLEEP(5)``) and several samples for real confidence.
    """
    if not baseline or not inject:
        raise HarnessUnavailable("timing oracle needs >=1 baseline and >=1 inject sample")
    b, i = statistics.median(baseline), statistics.median(inject)
    return (i - b) >= min_delta_seconds and i >= min_delta_seconds and min(inject) > max(baseline)


def evaluate_oracle(oracle: dict, steps: list[dict], oob: OobListener | None = None) -> bool:
    """Decide whether the oracle proves the bug against the recorded ``steps``.

    ``steps`` is the list of per-request records:
    ``{name, status, headers, body, captured, elapsed}``. Pure except for the
    optional OOB listener (whose job is to report a real external interaction).
    """
    if not steps:
        raise HarnessUnavailable("no requests were executed")
    kind = oracle.get("type", "contains")

    if kind == "oob":
        if oob is None:
            raise HarnessUnavailable("oob oracle needs a collaborator; none configured")
        token = oracle.get("token")
        if not token:
            raise HarnessUnavailable("oob oracle missing minted token")
        return bool(oob.received(token))

    if kind == "timing":
        if "baseline" not in oracle or "inject" not in oracle:
            raise HarnessUnavailable("timing oracle needs 'baseline' and 'inject' step names")
        base = _timing_samples(steps, oracle["baseline"])
        inj = _timing_samples(steps, oracle["inject"])
        return evaluate_timing(base, inj, float(oracle.get("min_delta_seconds", 3.0)))

    step = _select_step(oracle, steps)
    status, body = step["status"], step.get("body", "")

    if kind == "jwt":
        located = _locate(oracle, step)
        return located is not None and _is_jwt(located)
    if kind == "status":
        return status == int(oracle["value"])

    where = oracle.get("in", "body")
    hay = body if where == "body" else str(status)
    if kind == "contains":
        return str(oracle["value"]) in hay
    if kind == "regex":
        return re.search(oracle["value"], hay) is not None
    raise HarnessUnavailable(f"unknown oracle type {kind!r}")


def _oracle_matches(oracle: dict, status_code: int, body: str) -> bool:
    """Back-compat shim: evaluate a simple oracle against a single response."""
    return evaluate_oracle(oracle, [{"status": status_code, "body": body, "headers": {}}])


# --------------------------------------------------------------------------- #
# PoC rendering                                                                #
# --------------------------------------------------------------------------- #


def _curl(req: dict) -> str:
    """Render one request as a standalone curl command (mirrors httpx: a dict
    body is sent as JSON, so the PoC must declare the content type too)."""
    parts = ["curl", "-sS", "-X", req.get("method", "GET").upper()]
    headers = dict(req.get("headers") or {})
    body = req.get("body")
    if isinstance(body, dict) and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"
    for k, v in headers.items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if body is not None:
        data = body if isinstance(body, str) else json.dumps(body)
        parts += ["--data", shlex.quote(data)]
    parts.append(shlex.quote(req["url"]))
    return " ".join(parts)


def _poc_script(requests: list[dict], oob_token: str | None) -> str:
    """Emit a rerunnable bash PoC. Captured values become shell variables (via
    curl|python3) and ``{{name}}`` references become ``"$name"`` so a reviewer
    can paste the whole thing and have token-threaded steps actually work."""
    lines = ["#!/usr/bin/env bash", "set -euo pipefail"]
    if oob_token:
        lines.append(f"# Out-of-band token embedded in the payload: {oob_token}")
    for req in requests:
        shell_req = _shellify(req)
        captures = req.get("capture") or []
        if captures:
            base = _curl({**shell_req, "headers": shell_req.get("headers")})
            for cap in captures:
                name = cap["name"]
                if cap.get("from", "json") == "json":
                    path = cap["path"]
                    expr = "d=json.load(sys.stdin)\n" + "".join(
                        f"d=d[{_pykey(k)}]\n" for k in path.split(".")
                    )
                    lines.append(
                        f"{name}=$({base} | python3 -c "
                        + shlex.quote(f"import sys,json\n{expr}print(d)")
                        + ")"
                    )
                else:
                    lines.append(f"# capture {name} from response of:")
                    lines.append(f"# {base}")
        else:
            lines.append(_curl(shell_req))
    return "\n".join(lines)


def _pykey(k: str) -> str:
    return str(int(k)) if k.isdigit() else repr(k)


def _shellify(req: dict) -> dict:
    """Turn ``{{name}}`` placeholders into shell ``"$name"`` for the PoC."""
    out = json.loads(json.dumps(req))  # deep copy of json-safe parts

    def conv(v: Any) -> Any:
        if isinstance(v, str):
            return _PLACEHOLDER.sub(lambda m: f'"${{{m.group(1)}}}"', v)
        if isinstance(v, dict):
            return {k: conv(x) for k, x in v.items()}
        if isinstance(v, list):
            return [conv(x) for x in v]
        return v

    for key in ("url", "headers", "body"):
        if key in out:
            out[key] = conv(out[key])
    return out


# --------------------------------------------------------------------------- #
# Harness                                                                      #
# --------------------------------------------------------------------------- #


class HttpPocHarness(ProofHarness):
    sends_active_payload = True

    def __init__(
        self,
        vuln_class: VulnClass,
        transport: Any | None = None,
        oob: OobListener | None = None,
    ) -> None:
        self.vuln_class = vuln_class
        self._transport = transport  # httpx transport for deterministic tests
        self._oob = oob

    def run(self, candidate: Candidate, target: Target, config: Config) -> ValidationResult:
        try:
            from ...net import build_client
        except ImportError as exc:  # pragma: no cover
            raise HarnessUnavailable("httpx not installed (pip install .[dynamic])") from exc

        requests = candidate.params.get("requests")
        oracle = candidate.params.get("oracle")
        if not requests or not oracle:
            raise HarnessUnavailable("candidate missing 'requests' and/or 'oracle' params")

        ctx: dict[str, str] = {}
        oob_token: str | None = None
        if oracle.get("type") == "oob":
            if self._oob is None:
                raise HarnessUnavailable("oob oracle needs a collaborator; none configured")
            oob_token = oracle.get("token") or self._oob.token()
            oracle = {**oracle, "token": oob_token}
            ctx["oob"] = oob_token

        # Optional authenticated run: when the candidate opts in (an `account`
        # label or `authenticated: true`) and the target carries creds, every
        # request is sent with the account's origin-pinned session headers. The
        # session may be a live one handed in via secrets (OAuth/SSO/MFA path).
        session = None
        want_auth = candidate.params.get("authenticated") or candidate.params.get("account")
        if want_auth:
            from ._sessions import build_account_session, origin_base

            session = build_account_session(
                target,
                config,
                candidate.params.get("account"),
                base_url=origin_base(requests[0]["url"]),
                transport=self._transport,
            )

        steps: list[dict] = []
        evidence: list[Evidence] = []
        # Route through the paced client so every proof request to the target is
        # per-host rate limited and 429-aware (shared timeline with recon/session).
        with build_client(
            config, inner=self._transport, timeout=15.0, follow_redirects=True
        ) as client:
            for i, raw in enumerate(requests):
                req = _substitute(raw, ctx)
                method = req.get("method", "GET").upper()
                sess_headers = session.headers_for(req["url"]) if session else {}
                merged_headers = {**sess_headers, **(req.get("headers") or {})}
                _t0 = time.perf_counter()
                resp = client.request(
                    method,
                    req["url"],
                    headers=merged_headers or None,
                    content=(req["body"] if isinstance(req.get("body"), str) else None),
                    json=(req["body"] if isinstance(req.get("body"), dict) else None),
                )
                # Full request time (headers AND body) minus the per-host pacing
                # wait: politeness delay must not count toward a timing oracle, but
                # a body-delayed blind-SQLi response still must. Sum the wait across
                # every hop (redirects) -- client.request returns only the final
                # response, so earlier hops' waits live on resp.history.
                paced = resp.extensions.get("bb_pacing_wait", 0.0) + sum(
                    h.extensions.get("bb_pacing_wait", 0.0) for h in resp.history
                )
                elapsed = max(0.0, (time.perf_counter() - _t0) - paced)
                if (
                    session
                    and session.is_manual
                    and sess_headers
                    and resp.status_code in (401, 403)
                ):
                    raise HarnessUnavailable(
                        "handed-in session appears expired/invalid: authenticated "
                        f"{method} {req['url']} returned {resp.status_code}; "
                        "hand in a fresh session"
                    )
                resp_headers = dict(resp.headers)
                captured: dict[str, str] = {}
                for cap in raw.get("capture") or []:
                    val = _capture(cap, resp.status_code, resp_headers, resp.text)
                    captured[cap["name"]] = val
                    ctx[cap["name"]] = val
                steps.append(
                    {
                        "name": raw.get("name", str(i)),
                        "status": resp.status_code,
                        "headers": resp_headers,
                        "body": resp.text,
                        "captured": captured,
                        "elapsed": elapsed,
                    }
                )
                evidence.append(
                    Evidence(
                        kind="http",
                        label=f"{method} {req['url']} -> {resp.status_code}",
                        content=resp.text[:2000],
                    )
                )

        proved = evaluate_oracle(oracle, steps, oob=self._oob)
        poc = _poc_script(requests, oob_token)
        if proved:
            return ValidationResult(
                candidate_id=candidate.id,
                vuln_class=candidate.vuln_class,
                status=ValidationStatus.CONFIRMED,
                reason=f"oracle matched (type={oracle.get('type', 'contains')})",
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
