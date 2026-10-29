"""Per-host pacing is enforced on the validator proof harnesses themselves.

READINESS #2: the IDOR and HTTP-PoC proof clients used to open their own
un-paced httpx clients, so validator traffic bypassed the per-host rate limit.
They now go through net.build_client, whose PacedTransport draws on the one
process-wide host clock. These tests drive the real harnesses over an in-memory
transport and assert (a) the target host is registered on that shared clock --
i.e. the proof requests really went through the paced path -- and (b) the timing
oracle still measures server time, not the pacing wait.
"""

from __future__ import annotations

import uuid

import httpx
import yaml

import bugbounty.net.pacing as pacing
from bugbounty.config import Config
from bugbounty.scope import Platform, Target, TargetAuth
from bugbounty.validator.harnesses.httppoc import HttpPocHarness
from bugbounty.validator.harnesses.idor import IdorHarness
from bugbounty.validator.models import Candidate, ValidationStatus, VulnClass

MARKER = "Victim-Marker-Paced-7c1"


def _host() -> str:
    # Unique host per test: the pacing clock is process-wide, so a fixed host
    # would inherit another test's timeline.
    return f"pace-{uuid.uuid4().hex[:8]}.test"


def test_httppoc_requests_go_through_the_paced_client(monkeypatch):
    monkeypatch.setenv("BB_PER_HOST_RPS", "5")  # 0.2s interval (tiny, keeps test fast)
    monkeypatch.setenv("BB_PACING_JITTER", "0")
    host = _host()
    cand = Candidate(
        id="pace-poc",
        target_name="t",
        vuln_class=VulnClass.AUTH,
        title="two same-host requests",
        url=f"https://{host}/a",
        host=host,
        params={
            "requests": [
                {"name": "one", "method": "GET", "url": f"https://{host}/a"},
                {"name": "two", "method": "GET", "url": f"https://{host}/b"},
            ],
            "oracle": {"type": "status", "value": 200, "on": "two"},
        },
    )
    target = Target(
        name="t",
        platform=Platform.SELF,
        safe_harbor_url=f"https://{host}/sh",
        in_scope=[host],
        dry_run=False,
    )
    harness = HttpPocHarness(
        VulnClass.AUTH,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")),
    )
    harness.run(cand, target, Config(dry_run=False))
    # Only the paced transport registers a host on the shared clock.
    assert host in pacing._SHARED_CLOCK._last


def test_idor_requests_go_through_the_paced_client(tmp_path, monkeypatch):
    monkeypatch.setenv("BB_PER_HOST_RPS", "5")
    monkeypatch.setenv("BB_PACING_JITTER", "0")
    host = _host()
    victim = f"https://{host}/obj/42"
    creds = tmp_path / "creds.yaml"
    creds.write_text(
        yaml.safe_dump(
            {
                "account_a": {"cookies": {"sid": "A"}},
                "account_b": {"cookies": {"sid": "B"}},
            }
        )
    )

    def handler(request: httpx.Request) -> httpx.Response:
        authed = "sid=" in request.headers.get("cookie", "")
        if authed:
            return httpx.Response(200, text=f'{{"m":"{MARKER}"}}')
        return httpx.Response(401, text="no")

    cand = Candidate(
        id="pace-idor",
        target_name="t",
        vuln_class=VulnClass.IDOR,
        title="idor",
        url=victim,
        host=host,
        params={"victim_url": victim, "victim_marker": MARKER},
    )
    target = Target(
        name="t",
        platform=Platform.SELF,
        safe_harbor_url=f"https://{host}/sh",
        in_scope=[host],
        dry_run=False,
        auth=TargetAuth(multi_account=True, creds_ref=str(creds)),
    )
    r = IdorHarness(transport=httpx.MockTransport(handler)).run(cand, target, Config(dry_run=False))
    assert r.status is ValidationStatus.CONFIRMED
    assert host in pacing._SHARED_CLOCK._last


def test_timing_oracle_excludes_pacing_wait(monkeypatch):
    """A fast endpoint must stay REJECTED even though the per-host pacing wait
    (0.2s) exceeds the 0.15s timing threshold: the oracle reads server time
    (bb_server_elapsed), not the pacing stall."""
    monkeypatch.setenv("BB_PER_HOST_RPS", "5")
    monkeypatch.setenv("BB_PACING_JITTER", "0")
    host = _host()
    cand = Candidate(
        id="pace-timing",
        target_name="t",
        vuln_class=VulnClass.INJECTION,
        title="blind sqli",
        url=f"https://{host}/q",
        host=host,
        params={
            "requests": [
                {"name": "base", "method": "GET", "url": f"https://{host}/q?id=1"},
                {"name": "inj", "method": "GET", "url": f"https://{host}/q?id=1;sleep"},
            ],
            "oracle": {
                "type": "timing",
                "baseline": "base",
                "inject": "inj",
                "min_delta_seconds": 0.15,
            },
        },
    )
    target = Target(
        name="t",
        platform=Platform.SELF,
        safe_harbor_url=f"https://{host}/sh",
        in_scope=[host],
        dry_run=False,
    )
    harness = HttpPocHarness(
        VulnClass.INJECTION,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")),  # instant
    )
    r = harness.run(cand, target, Config(dry_run=False))
    assert r.status is ValidationStatus.REJECTED  # honest: no real server delay
    assert host in pacing._SHARED_CLOCK._last  # pacing WAS applied to the proof requests
