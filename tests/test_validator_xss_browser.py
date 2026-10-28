"""Real-browser integration proof for the XSS harness.

Unlike the pure-core tests, these launch an actual headless Chromium and run the
real ``XssHarness.run`` against a local HTTP target, proving that
nonce-attributed execution genuinely fires end to end for reflected, DOM, and
stored XSS -- and that a reflected-but-escaped page is correctly REJECTED.

Gating: the module resolves a launchable Chromium (the bundled one, a
``BB_CHROMIUM_EXECUTABLE`` override, or the environment's provisioned build) and
``pytest.skip``s cleanly when none launches -- so CI without a browser skips,
while any machine with a browser runs it. Run just these with ``-m browser``.

Local target only; no external network. DRY_RUN is irrelevant here because the
harness is driven directly (the engine's dry-run gate is tested elsewhere).
"""

from __future__ import annotations

import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from bugbounty.config import Config
from bugbounty.scope import Platform, Target
from bugbounty.validator.harnesses.xss import XssHarness
from bugbounty.validator.models import Candidate, ValidationStatus, VulnClass

# A launchable Chromium is resolved by the shared ``browser_ready`` fixture
# (tests/conftest.py); this whole module is browser-gated.
pytestmark = pytest.mark.browser


# --------------------------- local vulnerable target --------------------------- #

_STORE: dict[str, str] = {}

_DOM_PAGE = (
    "<!doctype html><html><body><div id='sink'></div>"
    "<script>document.getElementById('sink').innerHTML="
    "decodeURIComponent(location.hash.slice(1));</script></body></html>"
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence test server logging
        pass

    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query).get("q", [""])[0]
        if parsed.path == "/reflect":
            self._send(f"<html><body><div>{q}</div></body></html>")  # unescaped sink
        elif parsed.path == "/safe":
            self._send(f"<html><body><div>{html.escape(q)}</div></body></html>")  # escaped
        elif parsed.path == "/dom":
            self._send(_DOM_PAGE)
        elif parsed.path == "/stored":
            self._send(f"<html><body><div>{_STORE.get('payload', '')}</div></body></html>")
        else:
            self._send("not found", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        _STORE["payload"] = parse_qs(raw).get("payload", [raw])[0]
        self._send("stored")


@pytest.fixture(scope="module")
def target_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()


def _target() -> Target:
    return Target(
        name="local",
        platform=Platform.SELF,
        safe_harbor_url="http://127.0.0.1/sh",
        in_scope=["127.0.0.1"],
        dry_run=False,
    )


_PAYLOAD = "<img src=x onerror=\"alert('{NONCE}')\">"


def _run(candidate: Candidate):
    return XssHarness().run(candidate, _target(), Config(dry_run=False))


def test_reflected_xss_executes_in_real_browser(browser_ready, target_url):
    c = Candidate(
        id="refl-tp",
        target_name="local",
        vuln_class=VulnClass.XSS,
        title="reflected",
        url=f"{target_url}/reflect",
        host="127.0.0.1",
        params={"mode": "reflected", "url_template": f"{target_url}/reflect?q={_PAYLOAD}"},
    )
    r = _run(c)
    assert r.status is ValidationStatus.CONFIRMED, r.reason
    assert "script executed" in r.reason


def test_dom_xss_executes_in_real_browser(browser_ready, target_url):
    c = Candidate(
        id="dom-tp",
        target_name="local",
        vuln_class=VulnClass.XSS,
        title="dom",
        url=f"{target_url}/dom",
        host="127.0.0.1",
        params={"mode": "dom", "url_template": f"{target_url}/dom#{_PAYLOAD}"},
    )
    r = _run(c)
    assert r.status is ValidationStatus.CONFIRMED, r.reason


def test_stored_xss_executes_on_a_different_page(browser_ready, target_url):
    # Inject on /store (one request), confirm execution when /stored renders it.
    c = Candidate(
        id="stored-tp",
        target_name="local",
        vuln_class=VulnClass.XSS,
        title="stored",
        url=f"{target_url}/stored",
        host="127.0.0.1",
        params={
            "mode": "stored",
            "inject": {
                "method": "POST",
                "url": f"{target_url}/store",
                "body_template": f"payload={_PAYLOAD}",
            },
            "view_url": f"{target_url}/stored",
        },
    )
    r = _run(c)
    assert r.status is ValidationStatus.CONFIRMED, r.reason


def test_reflected_but_escaped_is_rejected(browser_ready, target_url):
    # Hard negative: the payload is reflected but HTML-escaped, so it is inert.
    c = Candidate(
        id="refl-neg",
        target_name="local",
        vuln_class=VulnClass.XSS,
        title="escaped",
        url=f"{target_url}/safe",
        host="127.0.0.1",
        params={"mode": "reflected", "url_template": f"{target_url}/safe?q={_PAYLOAD}"},
    )
    r = _run(c)
    assert r.status is ValidationStatus.REJECTED, r.reason
