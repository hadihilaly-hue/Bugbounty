"""Recon must not follow a redirect that leaves the target's origin."""

from __future__ import annotations

import httpx

import bugbounty.net as net
from bugbounty.net.pacing import PacingConfig, _HostClock
from bugbounty.recon.http import recon_http


def _patch_client(monkeypatch, handler):
    real = net.build_client

    def fake(config=None, **kw):
        kw.pop("inner", None)
        return real(
            pacing=PacingConfig(per_host_rps=0),
            inner=httpx.MockTransport(handler),
            clock=_HostClock(0.0, 0.0),
            **kw,
        )

    monkeypatch.setattr(net, "build_client", fake)


def test_recon_stops_at_off_origin_redirect(monkeypatch):
    hosts: list[str] = []

    def handler(request):
        hosts.append(request.url.host)
        if request.url.host == "target":
            return httpx.Response(302, headers={"location": "http://elsewhere.example/landing"})
        return httpx.Response(200, text="<html>should never be fetched</html>")

    _patch_client(monkeypatch, handler)
    rec = recon_http("http://target")
    assert hosts == ["target"]  # the off-host destination is never contacted
    assert any("off-origin redirect" in n for n in rec.notes)


def test_recon_follows_same_origin_redirect(monkeypatch):
    paths: list[str] = []

    def handler(request):
        paths.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/home"})
        return httpx.Response(200, text='<html><a href="/a">a</a></html>')

    _patch_client(monkeypatch, handler)
    rec = recon_http("http://target/")
    assert paths == ["/", "/home"]
    assert not any("off-origin" in n for n in rec.notes)


def test_recon_follows_full_same_origin_chain(monkeypatch):
    chain = {"/": "/a", "/a": "/b", "/b": "/c", "/c": "/d", "/d": "/home"}
    paths: list[str] = []

    def handler(request):
        paths.append(request.url.path)
        nxt = chain.get(request.url.path)
        if nxt is not None:
            return httpx.Response(302, headers={"location": nxt})
        return httpx.Response(200, text='<html><a href="/api/orders">o</a></html>')

    _patch_client(monkeypatch, handler)
    rec = recon_http("http://target/")
    assert paths == ["/", "/a", "/b", "/c", "/d", "/home"]  # landing page reached
    assert not any("too many redirects" in n for n in rec.notes)
