"""Per-host request pacing + 429/Retry-After backoff, as an httpx transport.

A global per-run request cap already lives in the budget meter. This adds
*per-host* politeness on top: never exceed a conservative requests/second to any
single target, add a little jitter, and on HTTP 429 honour ``Retry-After`` (or
fall back to capped exponential backoff) and retry. Pacing is applied to every
request that goes through :func:`build_client`, including DRY_RUN recon.
"""

from __future__ import annotations

import email.utils
import random
import threading
import time
from dataclasses import dataclass

import httpx

from ..config import Config


@dataclass
class PacingConfig:
    per_host_rps: float = 1.0
    jitter: float = 0.1  # up to this fraction of the interval, added randomly
    max_retries_429: int = 4
    backoff_base: float = 0.5
    backoff_max: float = 30.0

    @classmethod
    def from_config(cls, config: Config | None) -> PacingConfig:
        config = config or Config()
        return cls(
            per_host_rps=config.per_host_rps,
            jitter=config.pacing_jitter,
            max_retries_429=config.max_retries_429,
            backoff_base=config.backoff_base_seconds,
            backoff_max=config.backoff_max_seconds,
        )

    @property
    def min_interval(self) -> float:
        return 1.0 / self.per_host_rps if self.per_host_rps > 0 else 0.0


class _HostClock:
    """Thread-safe per-host spacing: hands out slots >= ``min_interval`` apart."""

    def __init__(self, min_interval: float, jitter: float) -> None:
        self.min_interval = min_interval
        self.jitter = jitter
        self._next: dict[str, float] = {}  # host cooldown deadline (see block())
        self._last: dict[str, float] = {}  # last slot handed out for a host
        self._lock = threading.Lock()

    def acquire(
        self,
        host: str,
        *,
        min_interval: float | None = None,
        jitter: float | None = None,
        sleep=time.sleep,
        now=time.monotonic,
    ) -> float:
        """Wait until this host's next slot, then reserve the one after it.

        A pending cooldown (see :meth:`block`) is honoured even when pacing is
        disabled, so a 429 still stops every caller for this host.

        Every client shares one timeline per host (``_last``), and a request is
        scheduled at ``last_request + its own interval``. With one pacing config
        -- the normal case, since pacing comes from ``Config`` -- that is exactly
        the configured per-host rate. With mixed configs each client still waits
        its own interval after the previous *actual* request, so bursts stay
        bounded, a stricter client waits in full from the first request, and no
        interval is memoised to leak into a later run.
        """
        with self._lock:
            t = now()
            mi = self.min_interval if min_interval is None else min_interval
            ji = self.jitter if jitter is None else jitter
            interval = mi * (1.0 + random.uniform(0.0, max(0.0, ji))) if mi > 0 else 0.0
            cooldown = self._next.get(host, 0.0)  # 429 deadline, host-wide
            earliest = self._last[host] + interval if host in self._last else t
            slot = max(t, cooldown, earliest)
            delay = slot - t
            self._last[host] = slot
        if delay > 0:
            sleep(delay)
        return delay

    def block(self, host: str, seconds: float, *, now=time.monotonic) -> None:
        """Hold back *every* caller for this host (a 429 cooldown is host-wide)."""
        if seconds <= 0:
            return
        with self._lock:
            self._next[host] = max(self._next.get(host, 0.0), now() + seconds)


# ONE clock process-wide, regardless of pacing settings: every client that talks
# to a host must draw on the same requests/second budget for it. Per-call pacing
# is passed to acquire(), where the strictest interval for that host wins.
_SHARED_CLOCK = _HostClock(min_interval=0.0, jitter=0.0)


def shared_clock(pacing: PacingConfig | None = None) -> _HostClock:
    return _SHARED_CLOCK


def retry_after_seconds(value: str | None) -> float | None:
    """Parse a Retry-After header (delta-seconds or HTTP-date) to seconds."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (ValueError, TypeError):
        return None
    if dt is None:
        return None
    import datetime as _dt

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.UTC)
    return max(0.0, (dt - _dt.datetime.now(_dt.UTC)).total_seconds())


class PacedTransport(httpx.BaseTransport):
    """Wraps an inner transport, pacing per host and retrying on 429."""

    def __init__(
        self,
        inner: httpx.BaseTransport,
        pacing: PacingConfig,
        *,
        clock: _HostClock | None = None,
        attribution: tuple[str, str] | None = None,
        sleep=time.sleep,
        now=time.monotonic,
    ) -> None:
        self._inner = inner
        self._pacing = pacing
        self._clock = clock if clock is not None else shared_clock(pacing)
        self._attribution = attribution
        self._sleep = sleep
        self._now = now

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Attribution rides on every request (recon, logins, proofs) so the
        # program can tie all harness traffic to the authorized researcher. We
        # set, not add, so our handle is the only value even after a retry.
        if self._attribution is not None:
            request.headers[self._attribution[0]] = self._attribution[1]
        host = request.url.host or ""
        attempt = 0
        paced_wait = 0.0  # total time spent waiting for this host's slot / cooldown
        while True:
            paced_wait += self._clock.acquire(
                host,
                min_interval=self._pacing.min_interval,
                jitter=self._pacing.jitter,
                sleep=self._sleep,
                now=self._now,
            )
            resp = self._inner.handle_request(request)
            if resp.status_code != 429:
                # Record the per-host pacing wait so a caller timing the whole
                # request (e.g. the blind-SQLi timing oracle) can subtract our
                # politeness delay. We expose the wait, not a server duration, so
                # the caller's own full-response timing (headers AND body) is kept.
                resp.extensions["bb_pacing_wait"] = paced_wait
                return resp
            retry = retry_after_seconds(resp.headers.get("retry-after"))
            if retry is None:
                retry = min(self._pacing.backoff_max, self._pacing.backoff_base * (2**attempt))
            resp.read()
            resp.close()
            # A 429 is host-wide: publish the cooldown so the retry (via acquire()
            # above) AND any other caller for this host wait it out -- even when we
            # have no retries left and are about to hand the 429 back.
            self._clock.block(host, retry, now=self._now)
            if attempt >= self._pacing.max_retries_429:
                resp.extensions["bb_pacing_wait"] = paced_wait
                return resp
            attempt += 1

    def close(self) -> None:
        self._inner.close()


def build_client(
    config: Config | None = None,
    *,
    pacing: PacingConfig | None = None,
    base_url: str = "",
    cookies=None,
    headers=None,
    timeout: float = 15.0,
    follow_redirects: bool = True,
    verify: bool = True,
    inner: httpx.BaseTransport | None = None,
    clock: _HostClock | None = None,
    sleep=time.sleep,
    now=time.monotonic,
) -> httpx.Client:
    """An httpx.Client whose every request is paced per host and 429-aware."""
    pacing = pacing or PacingConfig.from_config(config)
    inner = inner if inner is not None else httpx.HTTPTransport(verify=verify)
    attribution = (config or Config()).research_attribution()
    transport = PacedTransport(
        inner, pacing, clock=clock, attribution=attribution, sleep=sleep, now=now
    )
    return httpx.Client(
        transport=transport,
        base_url=base_url,
        cookies=cookies,
        headers=headers,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
