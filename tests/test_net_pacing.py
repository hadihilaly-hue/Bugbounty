"""Per-host pacing and 429/Retry-After backoff."""

from __future__ import annotations

import datetime as dt
import email.utils

import httpx
import pytest

from bugbounty.net.pacing import (
    PacedTransport,
    PacingConfig,
    _HostClock,
    build_client,
    retry_after_seconds,
    shared_clock,
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
    """Client with an isolated clock and a fake time base that sleep advances."""
    sleeps: list[float] = []
    t = [1000.0]

    def sleep(d):
        sleeps.append(d)
        t[0] += d

    pacing = PacingConfig(per_host_rps=0, **pc)  # per_host_rps=0 disables interval pacing
    client = build_client(
        pacing=pacing,
        inner=httpx.MockTransport(handler),
        clock=_HostClock(pacing.min_interval, pacing.jitter),
        sleep=sleep,
        now=lambda: t[0],
    )
    return client, sleeps


def test_clients_share_one_host_clock():
    """Two clients for the same host must share a pacing budget, not get one each."""
    pacing = PacingConfig(per_host_rps=1.0)
    a = PacedTransport(httpx.MockTransport(lambda r: httpx.Response(200)), pacing)
    b = PacedTransport(httpx.MockTransport(lambda r: httpx.Response(200)), pacing)
    assert a._clock is b._clock is shared_clock(pacing)


def test_429_cooldown_blocks_other_callers_on_that_host():
    """A 429 is host-wide: a concurrent caller waits out Retry-After too."""
    clock = _HostClock(min_interval=0.0, jitter=0.0)
    t = [500.0]
    sleeps: list[float] = []

    def sleep(d):
        sleeps.append(d)
        t[0] += d

    client = build_client(
        pacing=PacingConfig(per_host_rps=0, max_retries_429=0),
        inner=httpx.MockTransport(
            lambda r: httpx.Response(429, headers=[("retry-after", "30")], text="slow")
        ),
        clock=clock,
        sleep=sleep,
        now=lambda: t[0],
    )
    assert client.get("http://h/x").status_code == 429  # no retries left; cooldown published
    other: list[float] = []
    clock.acquire("h", sleep=other.append, now=lambda: t[0])
    assert other == [30.0]  # a different caller for the same host is held back
    assert clock.acquire("other-host", sleep=other.append, now=lambda: t[0]) == 0.0


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


def _acquire_seq(clock, host, specs, start=7000.0):
    """Run acquires with the given intervals, returning the sleeps incurred."""
    t = [start]
    sleeps: list[float] = []

    def sleep(d):
        sleeps.append(d)
        t[0] += d

    for mi in specs:
        clock.acquire(host, min_interval=mi, jitter=0.0, sleep=sleep, now=lambda: t[0])
    return sleeps


def test_differently_paced_clients_share_one_host_timeline():
    """Mixed pacing must not hand each client its own free slot for a host."""
    # Lax client (10/s) first, then a strict one (1/s): the strict client waits
    # its own full interval from the last request, not the lax client's slot.
    assert _acquire_seq(shared_clock(), "mixed-a", [0.1, 1.0]) == pytest.approx([1.0])
    # Strict first, then lax: the lax client is spaced off the same timeline.
    assert _acquire_seq(shared_clock(), "mixed-b", [1.0, 0.1]) == pytest.approx([0.1])


def test_host_interval_does_not_leak_into_a_later_run():
    """A strict run must not permanently throttle a later, laxer run."""
    clock = shared_clock()
    assert _acquire_seq(clock, "later-run", [1.0]) == []
    # A subsequent client with pacing disabled is spaced only by its own interval.
    assert _acquire_seq(clock, "later-run", [0.0], start=9000.0) == []
