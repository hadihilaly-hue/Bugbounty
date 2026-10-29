"""End-to-end proof of the handed-in live-session path.

Stands up a local auth-gated sandbox (a stdlib HTTP server with cookie sessions,
two accounts, a cross-account object, and an auth-gated stored-XSS sink) and
drives the real harnesses against it using a session *handed in* via secrets --
no login attempted. Shows:

  * two-account IDOR/BOLA CONFIRMED with handed-in sessions (real HTTP),
  * an auth-gated stored XSS CONFIRMED in a real browser (cookie carried into
    the render), which could not be reached before,
  * the #11 origin pinning still holds for handed-in sessions (never sent to
    another host), and
  * an expired handed-in session surfaced loudly, not run silently.

Local sandbox only; DRY_RUN is irrelevant here (harnesses are driven directly).
Browser cases are gated like the other browser suite (skip without Chromium).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

from bugbounty.config import Config
from bugbounty.scope import Platform, Target, TargetAuth
from bugbounty.validator.base import HarnessUnavailable
from bugbounty.validator.harnesses._sessions import build_account_session
from bugbounty.validator.harnesses.idor import IdorHarness
from bugbounty.validator.harnesses.xss import XssHarness
from bugbounty.validator.models import Candidate, ValidationStatus, VulnClass


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    # These suites verify oracle/session logic, not politeness. Disable per-host
    # pacing so the now-paced proof client adds no real sleeps here; pacing has
    # its own coverage in tests/test_proof_harness_pacing.py.
    monkeypatch.setenv("BB_PER_HOST_RPS", "0")


MARKER = "Owner-B-Private-Ledger-7f21c9"
SID_A, SID_B = "sid-aaa-attacker", "sid-bbb-victim"
_VALID = {SID_A: "A", SID_B: "B"}
_STORE: dict[str, str] = {}


def _sid(handler: BaseHTTPRequestHandler) -> str | None:
    raw = handler.headers.get("Cookie", "")
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "sid":
            return v
    return None


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = urlparse(self.path).path
        authed = _sid(self) in _VALID
        if path == "/obj/42":  # B's private object; ANY authed user can read it (the BOLA)
            if authed:
                self._send(f'{{"id":42,"ledger":"{MARKER}"}}')
            else:
                self._send('{"error":"login required"}', 401)
        elif path == "/feed":  # auth-gated render of stored comments
            if authed:
                self._send(f"<html><body><div>{_STORE.get('c', '')}</div></body></html>")
            else:
                self._send("<html><body>please log in</body></html>")
        else:
            self._send("not found", 404)

    def do_POST(self):
        if urlparse(self.path).path == "/comment":
            if _sid(self) not in _VALID:
                self._send("login required", 401)
                return
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            _STORE["c"] = parse_qs(raw).get("c", [raw])[0]
            self._send("stored")
        else:
            self._send("not found", 404)


@pytest.fixture(scope="module")
def sandbox():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()


def _creds(tmp_path, body: dict) -> str:
    p = tmp_path / "live.yaml"
    p.write_text(yaml.safe_dump(body))
    return str(p)


def _target(creds_ref: str, *, multi: bool = True) -> Target:
    return Target(
        name="live",
        platform=Platform.SELF,
        safe_harbor_url="http://127.0.0.1/sh",
        in_scope=["127.0.0.1"],
        dry_run=False,
        auth=TargetAuth(multi_account=multi, creds_ref=creds_ref),
    )


# ----------------------------- pinning (always) ----------------------------- #


def test_handed_in_session_is_origin_pinned(tmp_path):
    creds = _creds(tmp_path, {"accounts": [{"label": "x", "bearer_token": "SECRET-TOKEN"}]})
    sm = build_account_session(
        _target(creds, multi=False), Config(dry_run=False), base_url="https://app.test"
    )
    assert sm.headers_for("https://app.test/api/thing")["Authorization"] == "Bearer SECRET-TOKEN"
    # The same session must never be attached to another host (the #11 fix).
    assert sm.headers_for("https://evil.test/steal") == {}
    assert sm.headers_for("http://app.test/downgrade") == {}  # scheme/port are part of origin


# --------------------------- IDOR over real HTTP ---------------------------- #


def test_two_account_idor_confirmed_with_handed_in_sessions(sandbox, tmp_path):
    creds = _creds(
        tmp_path,
        {
            "account_a": {"cookies": {"sid": SID_A}},  # attacker
            "account_b": {"cookies": {"sid": SID_B}},  # victim
        },
    )
    candidate = Candidate(
        id="idor-live",
        target_name="live",
        vuln_class=VulnClass.IDOR,
        title="BOLA: attacker reads victim's object with a handed-in session",
        url=f"{sandbox}/obj/42",
        host="127.0.0.1",
        params={"victim_url": f"{sandbox}/obj/42", "victim_marker": MARKER},
    )
    r = IdorHarness().run(candidate, _target(creds), Config(dry_run=False))
    assert r.status is ValidationStatus.CONFIRMED, r.reason
    labels = [e.label for e in r.evidence]
    assert any("owner(B)" in x for x in labels) and any("attacker(A)" in x for x in labels)


def test_idor_expired_handed_in_session_surfaces(sandbox, tmp_path):
    # account_b's cookie is not a valid session -> owner baseline 401 -> surfaced.
    creds = _creds(
        tmp_path,
        {
            "account_a": {"cookies": {"sid": SID_A}},
            "account_b": {"cookies": {"sid": "sid-EXPIRED"}},
        },
    )
    candidate = Candidate(
        id="idor-expired",
        target_name="live",
        vuln_class=VulnClass.IDOR,
        title="expired handed-in session",
        url=f"{sandbox}/obj/42",
        host="127.0.0.1",
        params={"victim_url": f"{sandbox}/obj/42", "victim_marker": MARKER},
    )
    with pytest.raises(HarnessUnavailable, match="expired/invalid"):
        IdorHarness().run(candidate, _target(creds), Config(dry_run=False))


# --------------------------- auth-gated stored XSS -------------------------- #

_PAYLOAD = "<img src=x onerror=\"alert('{NONCE}')\">"


@pytest.mark.browser
def test_auth_gated_stored_xss_confirmed_with_handed_in_session(browser_ready, sandbox, tmp_path):
    # Inject the comment (authenticated) and confirm it executes when the
    # auth-gated /feed renders it -- with the session carried into the browser.
    creds = _creds(tmp_path, {"accounts": [{"label": "victim", "cookies": {"sid": SID_B}}]})
    candidate = Candidate(
        id="stored-xss-auth",
        target_name="live",
        vuln_class=VulnClass.XSS,
        title="auth-gated stored XSS",
        url=f"{sandbox}/feed",
        host="127.0.0.1",
        params={
            "mode": "stored",
            "authenticated": True,
            "inject": {
                "method": "POST",
                "url": f"{sandbox}/comment",
                "body_template": f"c={_PAYLOAD}",
            },
            "view_url": f"{sandbox}/feed",
        },
    )
    r = XssHarness().run(candidate, _target(creds, multi=False), Config(dry_run=False))
    assert r.status is ValidationStatus.CONFIRMED, r.reason
    assert "script executed" in r.reason


def test_auth_gated_stored_xss_cannot_confirm_without_session(sandbox, tmp_path):
    # No session handed in -> the injection to the auth-gated sink is refused
    # (401), so the harness cannot confirm (UNCONFIRMED), never a false positive.
    # Raises before any browser launch, so this runs without a browser too.
    _STORE.pop("c", None)
    candidate = Candidate(
        id="stored-xss-noauth",
        target_name="live",
        vuln_class=VulnClass.XSS,
        title="auth-gated stored XSS without a session",
        url=f"{sandbox}/feed",
        host="127.0.0.1",
        params={
            "mode": "stored",
            "inject": {
                "method": "POST",
                "url": f"{sandbox}/comment",
                "body_template": f"c={_PAYLOAD}",
            },
            "view_url": f"{sandbox}/feed",
        },
    )
    with pytest.raises(HarnessUnavailable):
        XssHarness().run(
            candidate, _target(_creds(tmp_path, {}), multi=False), Config(dry_run=False)
        )
