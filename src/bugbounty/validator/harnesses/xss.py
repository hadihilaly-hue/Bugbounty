"""XSS proof harness: require *nonce-attributed* script execution in a browser.

Reflection is not execution, and a dialog from the site's own JavaScript is not
our bug. So the oracle is deliberately strict:

  * The harness mints a high-entropy ``nonce`` and arranges for the candidate's
    payload to surface it -- ``alert('<nonce>')`` / ``console.log('<nonce>')``.
  * Execution is CONFIRMED only when a JS dialog *or* a console message is
    observed whose text contains that exact nonce. The site cannot have emitted
    the nonce on its own, so an attributed hit proves our injected script ran.
  * The payload merely being reflected into the DOM (as inert text/markup) is
    captured as evidence and REJECTED, never confirmed.

Three delivery modes:

  * ``reflected`` / ``dom`` -- navigate a single URL carrying the payload.
  * ``stored``              -- first *inject* the payload via an HTTP request,
    then navigate to the view URL where it should execute.

A screenshot is always captured. The browser interaction is kept thin; the
false-positive-sensitive decision lives in :func:`evaluate_execution`, which is
pure and unit-tested without a browser.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

from ...config import Config
from ...scope import Target
from ..base import HarnessUnavailable, ProofHarness
from ..models import Candidate, Evidence, ValidationResult, ValidationStatus, VulnClass

ARTIFACT_DIR = Path("runs/validator/xss")
_NONCE = "{NONCE}"


def _launch_kwargs() -> dict:
    """Chromium launch options. ``BB_CHROMIUM_EXECUTABLE`` points the harness at
    a provisioned browser binary when its build differs from the one bundled
    with the installed Playwright (otherwise the default launch is used, so
    behaviour is unchanged wherever the bundled browser matches)."""
    kw: dict = {"headless": True}
    exe = os.environ.get("BB_CHROMIUM_EXECUTABLE")
    if exe:
        kw["executable_path"] = exe
    return kw


def mint_nonce() -> str:
    """A token no site could already contain. Short enough to pass in a URL."""
    return f"xss{secrets.token_hex(8)}"


def expected_token(candidate: Candidate, nonce: str) -> str:
    """The token the executing payload is expected to surface.

    If the candidate uses a ``{NONCE}`` template we control the value, so the
    nonce is the token. Otherwise the finding must declare the exact marker its
    payload emits (e.g. ``alert('pwned')`` -> ``expect_marker='pwned'``); an
    unattributed dialog is never accepted.
    """
    p = candidate.params
    uses_template = any(
        isinstance(p.get(k), str) and _NONCE in p[k] for k in ("url_template", "body_template")
    ) or (isinstance((p.get("inject") or {}).get("body_template"), str))
    if uses_template:
        return nonce
    marker = p.get("expect_marker") or p.get("console_marker")
    if not marker:
        raise HarnessUnavailable(
            "XSS proof needs attribution: provide a '{NONCE}' url_template/"
            "body_template, or an 'expect_marker' naming the string the payload "
            "surfaces (we never confirm an unattributed dialog)"
        )
    return str(marker)


def evaluate_execution(events: list[dict], token: str) -> tuple[bool, str]:
    """Pure oracle: did an observed event prove *our* script executed?

    ``events`` is the list of observed browser events, each
    ``{"kind": "dialog"|"console", "text": ..., "dialog_type": ...}``. Returns
    (fired, via). A hit requires the token to appear in the event text.
    """
    for ev in events:
        text = ev.get("text") or ""
        if token in text:
            if ev.get("kind") == "dialog":
                return True, f"dialog:{ev.get('dialog_type', 'alert')} carried nonce"
            return True, "console message carried nonce"
    return False, ""


def _render(value: str, nonce: str) -> str:
    return value.replace(_NONCE, nonce)


def _seed_session(context: Any, session: Any, nav_url: str) -> None:
    """Carry a session into the browser for an auth-gated render: cookies via the
    context, and localStorage (SPA token apps) seeded at document start. Both are
    origin-scoped -- cookies are refused off the session's pinned origin, and the
    localStorage seed guards on ``location.origin`` -- so the session never leaks
    to another host."""
    if session is None:
        return
    from ._sessions import origin_base

    cookies = session.browser_cookies(nav_url)
    if cookies:
        context.add_cookies(cookies)
    ls = session.local_storage
    if ls:
        script = (
            "try { if (location.origin === " + json.dumps(origin_base(nav_url)) + ") {"
            " var d = " + json.dumps(ls) + ";"
            " for (var k in d) { localStorage.setItem(k, d[k]); } } } catch (e) {}"
        )
        context.add_init_script(script)


class XssHarness(ProofHarness):
    vuln_class = VulnClass.XSS
    sends_active_payload = True

    def run(self, candidate: Candidate, target: Target, config: Config) -> ValidationResult:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise HarnessUnavailable(
                "playwright not installed (pip install .[dynamic] && playwright install chromium)"
            ) from exc

        nonce = mint_nonce()
        token = expected_token(candidate, nonce)
        mode = candidate.params.get("mode", "reflected")
        timeout_ms = int(candidate.params.get("timeout_ms", 7000))
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        shot = ARTIFACT_DIR / f"{candidate.id}.png"

        # Optional authenticated render: carry a (possibly handed-in) session so
        # an auth-gated sink can be reached. Built before injection so the inject
        # request is authenticated too.
        session = None
        want_auth = candidate.params.get("authenticated") or candidate.params.get("auth_account")
        if want_auth:
            from ._sessions import build_account_session, origin_base

            nav_origin = origin_base(candidate.params.get("view_url") or candidate.url)
            session = build_account_session(
                target, config, candidate.params.get("auth_account"), base_url=nav_origin
            )

        if mode == "stored":
            self._inject(candidate, nonce, session)
            nav_url = candidate.params.get("view_url")
            if not nav_url:
                raise HarnessUnavailable("stored XSS needs a 'view_url' to observe execution")
        else:
            template = candidate.params.get("url_template")
            nav_url = _render(template, nonce) if template else candidate.url

        events: list[dict] = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(**_launch_kwargs())
                context = browser.new_context()
                _seed_session(context, session, nav_url)
                page = context.new_page()

                page.on(
                    "dialog",
                    lambda d: (
                        events.append({"kind": "dialog", "text": d.message, "dialog_type": d.type}),
                        d.dismiss(),
                    ),
                )
                page.on(
                    "console",
                    lambda m: events.append({"kind": "console", "text": m.text}),
                )
                try:
                    page.goto(nav_url, wait_until="load", timeout=timeout_ms)
                    page.wait_for_timeout(1500)
                except Exception as exc:  # navigation failure is not a confirmation
                    browser.close()
                    raise HarnessUnavailable(f"could not load {nav_url}: {exc}") from exc
                content = page.content()
                page.screenshot(path=str(shot))
                browser.close()
        except HarnessUnavailable:
            raise
        except Exception as exc:  # pragma: no cover
            raise HarnessUnavailable(f"browser error: {exc}") from exc

        fired, via = evaluate_execution(events, token)
        evidence = [Evidence(kind="screenshot", label="rendered page", path=str(shot))]
        if fired:
            return ValidationResult(
                candidate_id=candidate.id,
                vuln_class=VulnClass.XSS,
                status=ValidationStatus.CONFIRMED,
                reason=f"script executed, attributed to our payload ({via}, mode={mode})",
                reproducible=True,
                poc=f"Open in a browser ({mode}): {nav_url}",
                evidence=evidence,
            )

        reflected = token in content or (candidate.params.get("payload") or "") in content
        note = (
            "payload reflected into the DOM but did not execute (no attributed dialog/console)"
            if reflected
            else "payload neither executed nor reflected"
        )
        evidence.append(Evidence(kind="note", label="non-execution", content=note))
        return ValidationResult(
            candidate_id=candidate.id,
            vuln_class=VulnClass.XSS,
            status=ValidationStatus.REJECTED,
            reason=note,
            evidence=evidence,
        )

    def _inject(self, candidate: Candidate, nonce: str, session: Any = None) -> None:
        """Stored-XSS injection step: POST the payload to its sink (authenticated
        with the handed-in session's origin-pinned headers when one is given)."""
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise HarnessUnavailable("httpx not installed (pip install .[dynamic])") from exc
        inject: dict[str, Any] = candidate.params.get("inject") or {}
        if not inject.get("url"):
            raise HarnessUnavailable("stored XSS needs an 'inject' request with a url")
        body = inject.get("body_template")
        body = _render(body, nonce) if isinstance(body, str) else inject.get("body")
        headers = dict(inject.get("headers") or {})
        if session is not None:
            headers = {**session.headers_for(inject["url"]), **headers}
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.request(
                inject.get("method", "POST").upper(),
                inject["url"],
                headers=headers or None,
                content=body if isinstance(body, str) else None,
                json=body if isinstance(body, dict) else None,
            )
            if resp.status_code >= 400:
                raise HarnessUnavailable(f"stored XSS injection failed: {resp.status_code}")
