"""Authenticated session handling: cookies, CSRF, re-auth, MFA, manual cookies."""

from __future__ import annotations

import urllib.parse as up

import httpx
import pytest

from bugbounty.net import AuthError, Credentials, MfaRequired, SessionManager
from bugbounty.net.pacing import build_client
from bugbounty.net.session import Account, _last_set_cookies, extract_csrf
from bugbounty.scope import LoginSpec, TargetAuth


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


def test_manual_mode_without_live_session_refuses_to_log_in():
    """mode='manual' must report the missing session, never send a login request."""
    sent: list[str] = []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(200, text="ok")

    sm = SessionManager(
        LoginSpec(mode="manual", url="http://t/login"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(AuthError, match="manual"):
        sm.authenticate(Account("a", "u", "p"))
    assert sent == []


def test_manual_mode_uses_handed_in_cookie():
    sm = SessionManager(
        LoginSpec(mode="manual"),
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
    )
    sm.authenticate(Account("a", cookies={"session": "live-from-browser"}))
    assert sm.cookie_header() == "session=live-from-browser"


def test_declared_mfa_blocks_login_before_any_request():
    """auth.mfa_required must raise MfaRequired rather than attempt headless login."""
    sent: list[str] = []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(200, text="ok")

    auth = TargetAuth(mfa_required=True, login=LoginSpec(mode="form", url="http://t/login"))
    sm = SessionManager.from_auth(auth, client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(MfaRequired):
        sm.authenticate(Account("a", "u", "p"))
    assert sent == []  # never faked, never attempted


def test_session_is_not_leaked_to_another_host():
    """The cookie/bearer must not ride along to a host outside the target."""
    seen: dict[str, dict] = {}

    def handler(request):
        seen[request.url.host] = dict(request.headers)
        return httpx.Response(200, text="ok")

    sm = SessionManager(
        LoginSpec(mode="manual"),
        base_url="http://target",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sm.authenticate(Account("a", cookies={"session": "secret"}, bearer_token="tok"))
    sm.request("GET", "http://target/me")
    sm.request("GET", "http://evil.example/collect")
    assert seen["target"]["cookie"] == "session=secret"
    assert seen["target"]["authorization"] == "Bearer tok"
    assert "cookie" not in seen["evil.example"]
    assert "authorization" not in seen["evil.example"]


def test_declared_mfa_is_not_softened_by_a_response_marker():
    """An explicit declaration wins even when response detection is configured."""
    sent: list[str] = []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(200, text="ok")

    auth = TargetAuth(
        mfa_required=True,
        login=LoginSpec(mode="form", url="http://t/login", mfa_marker="OTP"),
    )
    sm = SessionManager.from_auth(auth, client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(MfaRequired):
        sm.authenticate(Account("a", "u", "p"))
    assert sent == []


def test_session_is_scoped_to_port_and_scheme():
    """A different service on the same host must not receive the session."""
    seen: dict[str, dict] = {}

    def handler(request):
        seen[f"{request.url.scheme}://{request.url.host}:{request.url.port}"] = dict(
            request.headers
        )
        return httpx.Response(200, text="ok")

    sm = SessionManager(
        LoginSpec(mode="manual"),
        base_url="http://target:8080",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sm.authenticate(Account("a", cookies={"session": "secret"}))
    sm.request("GET", "http://target:8080/me")
    sm.request("GET", "http://target:9999/other-service")
    sm.request("GET", "https://target:8080/tls")
    assert seen["http://target:8080"]["cookie"] == "session=secret"
    assert "cookie" not in seen["http://target:9999"]
    assert "cookie" not in seen["https://target:8080"]


def test_unconfigured_session_pins_to_first_origin_then_refuses_others():
    """A handed-in cookie with no base_url must not be sprayed at every host."""
    seen: dict[str, dict] = {}

    def handler(request):
        seen[request.url.host] = dict(request.headers)
        return httpx.Response(200, text="ok")

    sm = SessionManager(
        LoginSpec(mode="manual"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sm.authenticate(Account("a", cookies={"session": "secret"}))
    sm.request("GET", "http://first.example/a")
    sm.request("GET", "http://second.example/b")
    assert seen["first.example"]["cookie"] == "session=secret"
    assert "cookie" not in seen["second.example"]
