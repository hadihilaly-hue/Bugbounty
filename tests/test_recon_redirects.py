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
        kw.pop("pacing", None)  # recon now passes an explicit pacing; the mock forces its own
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


def test_recon_follows_in_scope_cross_host_redirect(monkeypatch):
    """A redirect to another in-scope host IS followed (allowlist, not origin)."""
    hosts: list[str] = []

    def handler(request):
        hosts.append(request.url.host)
        if request.url.host == "app":
            return httpx.Response(302, headers={"location": "http://api/landing"})
        return httpx.Response(200, text='<html><a href="/x">x</a></html>')

    _patch_client(monkeypatch, handler)
    scope = lambda h: h in {"app", "api"}  # noqa: E731
    from bugbounty.recon.http import recon_http as _rh

    rec = _rh("http://app", scope=scope)
    assert hosts == ["app", "api"]  # cross-host hop allowed because api is in scope
    assert not any("redirect" in n for n in rec.notes)


def test_recon_refuses_out_of_scope_redirect(monkeypatch):
    """A redirect to a host the allowlist does not permit is refused and logged."""
    hosts: list[str] = []

    def handler(request):
        hosts.append(request.url.host)
        if request.url.host == "app":
            return httpx.Response(302, headers={"location": "http://evil.example/x"})
        return httpx.Response(200, text="<html>should never be fetched</html>")

    _patch_client(monkeypatch, handler)
    scope = lambda h: h in {"app", "api"}  # noqa: E731
    from bugbounty.recon.http import recon_http as _rh

    rec = _rh("http://app", scope=scope)
    assert hosts == ["app"]  # evil.example is never contacted
    assert any("out-of-scope redirect" in n for n in rec.notes)


def _prog_allowlist():
    """A real two-host allowlist, mirroring what the CLI hands recon."""
    from bugbounty.scope import Allowlist, Platform, Target

    return Allowlist(
        targets=[
            Target(
                name="prog",
                platform=Platform.SELF,
                safe_harbor_url="https://example.com/security",
                in_scope=["app.example.com", "api.example.com"],
                out_of_scope=["legacy.example.com"],
            )
        ]
    )


def test_recon_follows_in_scope_redirect_via_real_allowlist(monkeypatch):
    """The scope predicate is the target's own Allowlist.decide (not a lambda)."""
    al = _prog_allowlist()
    scope = lambda h: al.decide("prog", h).allowed  # noqa: E731
    hosts: list[str] = []

    def handler(request):
        hosts.append(request.url.host)
        if request.url.host == "app.example.com":
            return httpx.Response(302, headers={"location": "http://api.example.com/x"})
        return httpx.Response(200, text="<html></html>")

    _patch_client(monkeypatch, handler)
    rec = recon_http("http://app.example.com", scope=scope)
    assert hosts == ["app.example.com", "api.example.com"]
    assert not any("redirect" in n for n in rec.notes)


def test_recon_refuses_out_of_scope_redirect_via_real_allowlist(monkeypatch):
    """An explicitly out-of-scope destination is refused by the real allowlist."""
    al = _prog_allowlist()
    scope = lambda h: al.decide("prog", h).allowed  # noqa: E731
    hosts: list[str] = []

    def handler(request):
        hosts.append(request.url.host)
        if request.url.host == "app.example.com":
            return httpx.Response(302, headers={"location": "http://legacy.example.com/x"})
        return httpx.Response(200, text="<html>never fetched</html>")

    _patch_client(monkeypatch, handler)
    rec = recon_http("http://app.example.com", scope=scope)
    assert hosts == ["app.example.com"]
    assert any("out-of-scope redirect" in n for n in rec.notes)


def test_recon_refuses_scheme_downgrade_redirect(monkeypatch):
    """An https page must not be bounced to http, even on an in-scope host."""
    hosts: list[tuple[str, str]] = []

    def handler(request):
        hosts.append((request.url.scheme, request.url.host))
        if request.url.scheme == "https":
            return httpx.Response(302, headers={"location": "http://app.example.com/x"})
        return httpx.Response(200, text="<html>plaintext, never fetched</html>")

    _patch_client(monkeypatch, handler)
    scope = lambda h: h == "app.example.com"  # noqa: E731
    rec = recon_http("https://app.example.com", scope=scope)
    assert hosts == [("https", "app.example.com")]  # the http hop is never made
    assert any("scheme-downgrade redirect" in n for n in rec.notes)


def test_recon_resolves_links_against_redirect_destination(monkeypatch):
    """Endpoints from the landing page belong to the host that served it."""

    def handler(request):
        if request.url.host == "app.example.com":
            return httpx.Response(302, headers={"location": "http://api.example.com/home"})
        return httpx.Response(200, text='<html><a href="/orders">o</a></html>')

    _patch_client(monkeypatch, handler)
    scope = lambda h: h in {"app.example.com", "api.example.com"}  # noqa: E731
    rec = recon_http("http://app.example.com", scope=scope)
    assert "http://api.example.com/orders" in rec.endpoints
    assert not any("app.example.com/orders" in e for e in rec.endpoints)
    assert rec.base_url == "http://app.example.com"  # requested URL is preserved
