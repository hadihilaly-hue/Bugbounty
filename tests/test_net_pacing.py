"""Per-host pacing and 429/Retry-After backoff."""

from __future__ import annotations

import datetime as dt
import email.utils

import httpx

from bugbounty.net.pacing import (
    PacingConfig,
    _HostClock,
    build_client,
    retry_after_seconds,
)


def test_host_clock_spaces_same_host():
    t = [100.0]
    sleeps: list[float] = []

    def sleep(d):
        sleeps.append(d)
        t[0] += d

    c = _HostClock(min_interval=2.0, jitter=0.0)
    for _ in range(3):
        c.acquire("h", sleep=sleep, now=lambda: t[0])
    assert sleeps == [2.0, 2.0]  # first slot free, then spaced by the interval


def test_host_clock_independent_hosts():
    sleeps: list[float] = []
    c = _HostClock(2.0, 0.0)
    c.acquire("a", sleep=lambda d: sleeps.append(d), now=lambda: 0.0)
    c.acquire("b", sleep=lambda d: sleeps.append(d), now=lambda: 0.0)
    assert sleeps == []  # a slow host does not delay a different host


def test_retry_after_parsing():
    assert retry_after_seconds("5") == 5.0
    assert retry_after_seconds(None) is None
    assert retry_after_seconds("garbage") is None
    future = email.utils.format_datetime(dt.datetime.now(dt.UTC) + dt.timedelta(seconds=30))
    v = retry_after_seconds(future)
    assert v is not None and 20 < v <= 31


def _client(handler, **pc):
    sleeps: list[float] = []
    client = build_client(
        pacing=PacingConfig(per_host_rps=0, **pc),  # per_host_rps=0 disables pacing sleeps
        inner=httpx.MockTransport(handler),
        sleep=lambda d: sleeps.append(d),
    )
    return client, sleeps


def test_429_honors_retry_after():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers=[("retry-after", "2")], text="slow down")
        return httpx.Response(200, text="ok")

    client, sleeps = _client(handler, max_retries_429=4)
    r = client.get("http://h/x")
    assert r.status_code == 200 and calls["n"] == 2 and sleeps == [2.0]


def test_429_exponential_backoff_without_retry_after():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(429 if calls["n"] <= 3 else 200, text="x")

    client, sleeps = _client(handler, max_retries_429=5, backoff_base=0.5, backoff_max=30)
    r = client.get("http://h/x")
    assert r.status_code == 200 and sleeps == [0.5, 1.0, 2.0]


def test_429_gives_up_after_max_retries():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(429, text="x")

    client, sleeps = _client(handler, max_retries_429=2, backoff_base=0.5)
    r = client.get("http://h/x")
    assert r.status_code == 429 and calls["n"] == 3 and len(sleeps) == 2
