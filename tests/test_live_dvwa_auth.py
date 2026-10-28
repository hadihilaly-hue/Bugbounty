"""Live integration: hold a real CSRF-protected session against DVWA.

DVWA uses a per-request anti-CSRF ``user_token`` and a cookie session -- a harder
target than Juice Shop's token API. Skipped unless a local DVWA is reachable on
:4280 (so CI, which has no sandbox, stays green). Exercises the real adapter
path: SessionManager logs in through the CSRF form, initialises the DB if needed,
holds the cookie across the security-level change, and reuses it on a protected
page.
"""

from __future__ import annotations

import httpx
import pytest

from bugbounty.config import Config
from bugbounty.jobs.eval_targets.dvwa import DvwaTarget
from bugbounty.net import SessionManager
from bugbounty.net.session import Account, extract_csrf

DVWA = "http://localhost:4280"


def _dvwa_up() -> bool:
    try:
        return httpx.get(f"{DVWA}/login.php", timeout=3.0).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _dvwa_up(), reason="DVWA sandbox not running on :4280")


def test_dvwa_csrf_session_held_via_adapter():
    # Adapter path handles DB-init; proves CSRF login + cookie reuse + security=low.
    cookie = DvwaTarget()._authenticate(Config(dry_run=False))
    assert "PHPSESSID=" in cookie and "security=low" in cookie


def test_dvwa_sessionmanager_csrf_login_direct():
    t = DvwaTarget()
    sm = SessionManager(t._login_spec(), base_url=DVWA)
    sm.authenticate(Account("admin", "admin", "password"))
    assert sm.cookies.get("PHPSESSID")  # a session cookie was captured
    # The held session is reused on a protected page without re-login.
    page = sm.request("GET", f"{DVWA}/index.php")
    assert "Logout" in page.text
    # And a per-page CSRF token is extractable on an authed page.
    sec = sm.request("GET", f"{DVWA}/security.php")
    assert extract_csrf(sec.text, "user_token") is not None
