"""Oracle logic for the generic HTTP PoC harness.

Pure oracle tests plus end-to-end runs over an httpx MockTransport (no network):
token threading (step 2 uses step 1's captured token), the strict JWT oracle
(a real token vs an echoed non-token), and the out-of-band SSRF oracle (a real
collaborator hit vs none, and "no collaborator" -> UNCONFIRMED).
"""

import base64
import json
import time

import httpx
import pytest

from bugbounty.config import Config
from bugbounty.scope import Platform, Target
from bugbounty.validator.base import HarnessUnavailable
from bugbounty.validator.harnesses.httppoc import (
    HttpPocHarness,
    _curl,
    _is_jwt,
    _oracle_matches,
    _poc_script,
    evaluate_oracle,
    evaluate_timing,
)
from bugbounty.validator.models import Candidate, ValidationStatus, VulnClass


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _jwt(payload=None) -> str:
    payload = payload or {"sub": "1", "exp": 9999999999}
    return f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(payload)}.c2ln"


def _target() -> Target:
    return Target(
        name="t",
        platform=Platform.SELF,
        safe_harbor_url="https://h.test/sh",
        in_scope=["h.test"],
        dry_run=False,
    )


def test_contains_oracle():
    assert _oracle_matches({"type": "contains", "value": "root:x:"}, 200, "root:x:0:0") is True
    assert _oracle_matches({"type": "contains", "value": "root:x:"}, 200, "nope") is False


def test_status_oracle():
    assert _oracle_matches({"type": "status", "value": 200}, 200, "") is True
    assert _oracle_matches({"type": "status", "value": 200}, 403, "") is False


def test_regex_oracle():
    assert _oracle_matches({"type": "regex", "value": r"id=\d+"}, 200, "id=42") is True


def test_unknown_oracle_raises():
    with pytest.raises(HarnessUnavailable):
        _oracle_matches({"type": "telepathy", "value": 1}, 200, "")


def test_curl_render():
    c = _curl({"method": "post", "url": "http://h/x", "headers": {"A": "b"}, "body": "d=1"})
    assert c.startswith("curl -sS -X POST")
    assert "'A: b'" in c and "--data d=1" in c


# ------------------------------ strict jwt oracle ------------------------------ #


def test_is_jwt_accepts_real_token_and_rejects_junk():
    assert _is_jwt(_jwt()) is True
    assert _is_jwt("authentication") is False
    assert _is_jwt("a.b.c") is False
    assert _is_jwt(_jwt().rsplit(".", 1)[0]) is False  # only two segments


def test_jwt_oracle_true_positive_and_hard_negative():
    good = [
        {"status": 200, "body": json.dumps({"authentication": {"token": _jwt()}}), "headers": {}}
    ]
    bad = [
        {"status": 200, "body": json.dumps({"authentication": {"token": "nope"}}), "headers": {}}
    ]
    oracle = {"type": "jwt", "source": "json", "path": "authentication.token"}
    assert evaluate_oracle(oracle, good) is True
    assert evaluate_oracle(oracle, bad) is False  # echoed word, not a real token


def test_oracle_on_selects_named_step():
    steps = [
        {"name": "login", "status": 200, "body": "first", "headers": {}},
        {"name": "read", "status": 200, "body": "SECRET", "headers": {}},
    ]
    assert evaluate_oracle({"type": "contains", "value": "SECRET", "on": "read"}, steps) is True
    assert evaluate_oracle({"type": "contains", "value": "SECRET", "on": "login"}, steps) is False


# ------------------------- token threading (end to end) ------------------------- #


def _thread_handler(request: httpx.Request) -> httpx.Response:
    if str(request.url).endswith("/login"):
        return httpx.Response(200, json={"authentication": {"token": _jwt()}})
    # protected resource: only serves the secret if the bearer token is a JWT
    auth = request.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ")
    if _is_jwt(token):
        return httpx.Response(200, json={"token": token, "secret": "FLAG"})
    return httpx.Response(403, text="forbidden")


def test_token_threading_end_to_end():
    candidate = Candidate(
        id="thread",
        target_name="t",
        vuln_class=VulnClass.AUTH,
        title="auth chain",
        url="https://h.test/me",
        host="h.test",
        params={
            "requests": [
                {
                    "name": "login",
                    "method": "POST",
                    "url": "https://h.test/login",
                    "body": {"email": "x", "password": "y"},
                    "capture": [{"name": "tok", "from": "json", "path": "authentication.token"}],
                },
                {
                    "name": "me",
                    "method": "GET",
                    "url": "https://h.test/me",
                    "headers": {"Authorization": "Bearer {{tok}}"},
                },
            ],
            # The secret is only reachable if step 2 really carried step 1's token.
            "oracle": {"type": "contains", "value": "FLAG", "on": "me"},
        },
    )
    harness = HttpPocHarness(VulnClass.AUTH, transport=httpx.MockTransport(_thread_handler))
    r = harness.run(candidate, _target(), Config(dry_run=False))
    assert r.status is ValidationStatus.CONFIRMED
    # PoC is genuinely rerunnable: captures tok via python3 and reuses $tok.
    assert "python3" in r.poc and "${tok}" in r.poc and "set -euo pipefail" in r.poc


def test_token_threading_hard_negative_when_token_not_threaded():
    # Same chain but the oracle demands a JWT in the /me response; if threading
    # failed the server would 403 and there'd be no token to validate.
    def broken(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/login"):
            return httpx.Response(200, json={"authentication": {"token": "not-a-jwt"}})
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if _is_jwt(token):
            return httpx.Response(200, json={"token": token})
        return httpx.Response(403, json={"error": "forbidden"})

    candidate = Candidate(
        id="thread-neg",
        target_name="t",
        vuln_class=VulnClass.AUTH,
        title="auth chain",
        url="https://h.test/me",
        host="h.test",
        params={
            "requests": [
                {
                    "name": "login",
                    "method": "POST",
                    "url": "https://h.test/login",
                    "body": {"email": "x", "password": "y"},
                    "capture": [{"name": "tok", "from": "json", "path": "authentication.token"}],
                },
                {
                    "name": "me",
                    "method": "GET",
                    "url": "https://h.test/me",
                    "headers": {"Authorization": "Bearer {{tok}}"},
                },
            ],
            "oracle": {"type": "jwt", "source": "json", "path": "token", "on": "me"},
        },
    )
    harness = HttpPocHarness(VulnClass.AUTH, transport=httpx.MockTransport(broken))
    r = harness.run(candidate, _target(), Config(dry_run=False))
    assert r.status is ValidationStatus.REJECTED


# ------------------------------- oob ssrf oracle ------------------------------- #


class _FakeOob:
    def __init__(self, hit: bool):
        self._hit = hit
        self._token = "oob7a1b2c3d"

    def token(self) -> str:
        return self._token

    def received(self, token: str) -> bool:
        return self._hit and token == self._token


def _ssrf_candidate() -> Candidate:
    return Candidate(
        id="ssrf",
        target_name="t",
        vuln_class=VulnClass.SSRF,
        title="ssrf via url param",
        url="https://h.test/fetch",
        host="h.test",
        params={
            "requests": [
                {"method": "GET", "url": "https://h.test/fetch?url=http://{{oob}}.oob.test/"}
            ],
            "oracle": {"type": "oob"},
        },
    )


def test_oob_true_positive_requires_real_callback():
    harness = HttpPocHarness(
        VulnClass.SSRF,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")),
        oob=_FakeOob(hit=True),
    )
    r = harness.run(_ssrf_candidate(), _target(), Config(dry_run=False))
    assert r.status is ValidationStatus.CONFIRMED


def test_oob_hard_negative_no_callback():
    harness = HttpPocHarness(
        VulnClass.SSRF,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")),
        oob=_FakeOob(hit=False),
    )
    r = harness.run(_ssrf_candidate(), _target(), Config(dry_run=False))
    assert r.status is ValidationStatus.REJECTED


def test_oob_without_collaborator_is_unavailable():
    harness = HttpPocHarness(
        VulnClass.SSRF,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")),
    )
    with pytest.raises(HarnessUnavailable):
        harness.run(_ssrf_candidate(), _target(), Config(dry_run=False))


def test_poc_script_threads_capture_as_shell_var():
    reqs = [
        {
            "method": "POST",
            "url": "https://h.test/login",
            "body": {"email": "x"},
            "capture": [{"name": "tok", "from": "json", "path": "authentication.token"}],
        },
        {
            "method": "GET",
            "url": "https://h.test/me",
            "headers": {"Authorization": "Bearer {{tok}}"},
        },
    ]
    script = _poc_script(reqs, None)
    assert script.startswith("#!/usr/bin/env bash")
    assert "tok=$(" in script and "python3" in script and "${tok}" in script


# ------------------------- timing oracle (blind/time-based) ------------------------- #


def test_evaluate_timing_true_positive():
    # ~5s injected sleep vs ~20ms baseline, threshold 3s -> confirmed.
    assert evaluate_timing([0.02, 0.03], [5.1, 5.2], 3.0) is True


def test_evaluate_timing_rejects_normal_jitter():
    # Sub-second jitter on both sides must not satisfy a 3s-sleep claim.
    assert evaluate_timing([0.05, 0.6], [0.1, 0.7], 3.0) is False


def test_evaluate_timing_absolute_floor():
    # A 2s delta cannot confirm a claim whose sleep is 3s: injected median < floor.
    assert evaluate_timing([0.0], [2.0], 3.0) is False


def test_evaluate_timing_rejects_overlapping_samples():
    # If any injected sample is not slower than every baseline sample, reject.
    assert evaluate_timing([0.1, 4.0], [3.9, 4.1], 3.0) is False


def test_evaluate_timing_requires_samples():
    with pytest.raises(HarnessUnavailable):
        evaluate_timing([], [5.0], 3.0)


def _timing_candidate(base_url: str, min_delta: float) -> Candidate:
    return Candidate(
        id="blind-sqli",
        target_name="t",
        vuln_class=VulnClass.INJECTION,
        title="blind time-based sqli",
        url=f"{base_url}/q",
        host="h.test",
        params={
            "requests": [
                {"name": "base", "method": "GET", "url": f"{base_url}/q?id=1"},
                {"name": "inj", "method": "GET", "url": f"{base_url}/q?id=1;sleep"},
            ],
            "oracle": {
                "type": "timing",
                "baseline": "base",
                "inject": "inj",
                "min_delta_seconds": min_delta,
            },
        },
    )


def test_timing_oracle_end_to_end_confirms_when_injected_is_slower():
    def handler(request: httpx.Request) -> httpx.Response:
        if "sleep" in str(request.url):
            time.sleep(0.3)
        return httpx.Response(200, text="ok")

    harness = HttpPocHarness(VulnClass.INJECTION, transport=httpx.MockTransport(handler))
    r = harness.run(_timing_candidate("https://h.test", 0.15), _target(), Config(dry_run=False))
    assert r.status is ValidationStatus.CONFIRMED


def test_timing_oracle_end_to_end_rejects_when_no_delay():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")  # no sleep for either request

    harness = HttpPocHarness(VulnClass.INJECTION, transport=httpx.MockTransport(handler))
    r = harness.run(_timing_candidate("https://h.test", 0.15), _target(), Config(dry_run=False))
    assert r.status is ValidationStatus.REJECTED
