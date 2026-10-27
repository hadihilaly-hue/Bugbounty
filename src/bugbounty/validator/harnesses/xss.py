"""XSS proof harness: navigate a real browser and require script execution.

A reflected/stored XSS candidate must actually execute JS. The oracle is a
JS dialog (alert/confirm/prompt) firing, or a unique console marker appearing.
Payload merely being reflected in the DOM is REJECTED, not CONFIRMED. A
screenshot is always captured as evidence.
"""

from __future__ import annotations

from pathlib import Path

from ...config import Config
from ...scope import Target
from ..base import HarnessUnavailable, ProofHarness
from ..models import Candidate, Evidence, ValidationResult, ValidationStatus, VulnClass

ARTIFACT_DIR = Path("runs/validator/xss")


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

        marker = candidate.params.get("console_marker")
        timeout_ms = int(candidate.params.get("timeout_ms", 7000))
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        shot = ARTIFACT_DIR / f"{candidate.id}.png"

        fired = {"ok": False, "via": ""}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()

                def _on_dialog(dialog):  # alert/confirm/prompt == JS executed
                    fired["ok"] = True
                    fired["via"] = f"dialog:{dialog.type}"
                    dialog.dismiss()

                def _on_console(msg):
                    if marker and marker in msg.text:
                        fired["ok"] = True
                        fired["via"] = "console-marker"

                page.on("dialog", _on_dialog)
                page.on("console", _on_console)
                try:
                    page.goto(candidate.url, wait_until="load", timeout=timeout_ms)
                    page.wait_for_timeout(1500)
                except Exception as exc:  # navigation failure is not a confirmation
                    browser.close()
                    raise HarnessUnavailable(f"could not load {candidate.url}: {exc}") from exc
                page.screenshot(path=str(shot))
                browser.close()
        except HarnessUnavailable:
            raise
        except Exception as exc:  # pragma: no cover
            raise HarnessUnavailable(f"browser error: {exc}") from exc

        ev = [Evidence(kind="screenshot", label="rendered page", path=str(shot))]
        if fired["ok"]:
            return ValidationResult(
                candidate_id=candidate.id,
                vuln_class=VulnClass.XSS,
                status=ValidationStatus.CONFIRMED,
                reason=f"script executed ({fired['via']})",
                reproducible=True,
                poc=f"Open in a browser: {candidate.url}",
                evidence=ev,
            )
        return ValidationResult(
            candidate_id=candidate.id,
            vuln_class=VulnClass.XSS,
            status=ValidationStatus.REJECTED,
            reason="payload did not execute (no dialog/console marker observed)",
            evidence=ev,
        )
