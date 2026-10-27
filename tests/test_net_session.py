"""Authenticated session handling: cookies, CSRF, re-auth, MFA, manual cookies."""

from __future__ import annotations

import urllib.parse as up

import httpx
import pytest

from bugbounty.net import AuthError, Credentials, MfaRequired, SessionManager
from bugbounty.net.pacing import build_client
from bugbounty.net.session import Account, _last_set_cookies, extract_csrf
from bugbounty.scope import LoginSpec


def _noop(*_):
    return None


def _client(handler):
    return build_client(
        inner=httpx.MockTransport(handler),
        base_url="http://t",
        follow_redirects=False,
        sleep=_noop,
    )


def test_last_set_cookies_keeps_last_duplicate():
    resp = httpx.Response(
        200,
        headers=[
            ("set-cookie", "PHPSESSID=a; path=/"),
            ("set-cookie", "PHPSESSID=b; path=/"),
            ("set-cookie", "sec=low"),
        ],
    )
    got = _last_set_cookies(resp)
    assert got["PHPSESSID"] == "b" and got["sec"] == "low"


def test_extract_csrf_both_orders():
    assert extract_csrf("<input name='user_token' value='TOK1'>", "user_token") == "TOK1"
    assert extract_csrf('<input value="TOK2" name="csrf">', "csrf") == "TOK2"


def test_form_login_with_csrf_and_cookie_reuse():
    def handler(request):
        p = request.url.path
        if p == "/login" and request.method == "GET":
            return httpx.Response(
                200,
                headers=[("set-cookie", "SID=s1")],
                text="<input name='user_token' value='TOK1'>",
            )
        if p == "/login" and request.method == "POST":
            form = up.parse_qs(request.content.decode())
            if form.get("user_token") != ["TOK1"]:
                return httpx.Response(403, text="bad csrf")
            if form.get("username") != ["u"] or form.get("password") != ["p"]:
                return httpx.Response(403, text="bad creds")
            return httpx.Response(302, headers=[("set-cookie", "SID=s2")], text="")
        if p == "/home":
            ok = "SID=s2" in (request.headers.get("cookie") or "")
            return httpx.Response(200, text="Logout" if ok else "login")
        return httpx.Response(404)

    login = LoginSpec(
        mode="form",
        url="http://t/login",
        csrf_field="user_token",
        success_url="http://t/home",
        success_marker="Logout",
        user_field="username",
        pass_field="password",
    )
    sm = SessionManager(login, client=_client(handler))
    sm.authenticate(Account("a", "u", "p"))
    assert sm.cookies["SID"] == "s2"
    assert "SID=s2" in sm.cookie_header()


def test_form_login_missing_csrf_raises():
    def handler(request):
        if request.url.path == "/login" and request.method == "GET":
            return httpx.Response(200, text="<form>no token</form>")
        return httpx.Response(200)

    login = LoginSpec(mode="form", url="http://t/login", csrf_field="user_token")
    sm = SessionManager(login, client=_client(handler))
    with pytest.raises(AuthError):
        sm.authenticate(Account("a", "u", "p"))


def test_json_token_login_nested_path():
    def handler(request):
        if request.url.path == "/auth":
            return httpx.Response(200, json={"authentication": {"token": "T123"}})
        return httpx.Response(404)

    login = LoginSpec(
        mode="json", url="http://t/auth", token_json_path="authentication.token", user_field="email"
    )
    sm = SessionManager(login, client=_client(handler))
    sm.authenticate(Account("a", "e@x", "p"))
    assert sm.bearer == "T123"
    assert sm.auth_headers()["Authorization"] == "Bearer T123"


def test_reauth_on_expiry():
    state = {"login": 0, "active": None}

    def handler(request):
        p = request.url.path
        if p == "/login" and request.method == "POST":
            state["login"] += 1
            state["active"] = f"s{state['login']}"
            return httpx.Response(302, headers=[("set-cookie", f"SID={state['active']}")])
        if p == "/data":
            ok = state["active"] and f"SID={state['active']}" in (
                request.headers.get("cookie") or ""
            )
            return httpx.Response(200 if ok else 401, text="ok" if ok else "expired")
        return httpx.Response(404)

    login = LoginSpec(
        mode="form",
        url="http://t/login",
        expiry_status=401,
        user_field="username",
        pass_field="password",
    )
    sm = SessionManager(login, client=_client(handler))
    sm.authenticate(Account("a", "u", "p"))
    assert state["login"] == 1
    state["active"] = "zzz"  # server-side expiry
    r = sm.request("GET", "http://t/data")
    assert r.status_code == 200 and state["login"] == 2


def test_mfa_marker_detected():
    def handler(request):
        if request.url.path == "/login" and request.method == "POST":
            return httpx.Response(200, text="Please enter your MFA code")
        return httpx.Response(200, text="")

    login = LoginSpec(mode="form", url="http://t/login", mfa_marker="MFA code")
    sm = SessionManager(login, client=_client(handler))
    with pytest.raises(MfaRequired):
        sm.authenticate(Account("a", "u", "p"))


def test_manual_cookie_injection_skips_login():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(500)  # login must never be hit

    login = LoginSpec(mode="form", url="http://t/login")
    sm = SessionManager(login, client=_client(handler))
    sm.authenticate(Account("a", cookies={"session": "LIVE"}))
    assert sm.cookies["session"] == "LIVE"
    assert "session=LIVE" in sm.auth_headers()["Cookie"]
    assert calls["n"] == 0


def test_credentials_load_formats(tmp_path):
    p1 = tmp_path / "a.yaml"
    p1.write_text(
        "accounts:\n  - label: account_a\n    username: u1\n    password: p1\n"
        "  - label: account_b\n    email: u2@x\n    password: p2\n"
    )
    c1 = Credentials.load(p1)
    assert len(c1.accounts) == 2
    assert c1.by_label("account_a").username == "u1"
    assert c1.by_label("account_b").username == "u2@x"

    p2 = tmp_path / "b.yaml"
    p2.write_text(
        "account_a:\n  email: a@x\n  password: pa\naccount_b:\n  email: b@x\n  password: pb\n"
    )
    c2 = Credentials.load(p2)
    assert {a.label for a in c2.accounts} == {"account_a", "account_b"}

    p3 = tmp_path / "c.yaml"
    p3.write_text("cookies:\n  - name: session\n    value: LIVE\n    domain: x\n")
    c3 = Credentials.load(p3)
    assert len(c3.accounts) == 1 and c3.accounts[0].is_manual
    assert c3.accounts[0].cookies["session"] == "LIVE"
