"""IDOR proof harness: two accounts, prove A reads B's object.

Requires multi-account auth. Logs in as the attacker account, requests the
victim's resource, and CONFIRMS only when the victim marker appears with a
success status. A denial (401/403/404) is REJECTED. Missing creds or an
unreachable login is UNCONFIRMED (raised as HarnessUnavailable).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ...config import Config
from ...scope import Target
from ..base import HarnessUnavailable, ProofHarness
from ..models import Candidate, Evidence, ValidationResult, ValidationStatus, VulnClass


def _load_accounts(target: Target) -> dict:
    if not target.auth.multi_account or not target.auth.creds_ref:
        raise HarnessUnavailable("IDOR proof requires target.auth.multi_account + creds_ref")
    path = Path(target.auth.creds_ref)
    if not path.exists():
        raise HarnessUnavailable(f"creds file not found: {path}")
    data = yaml.safe_load(path.read_text()) or {}
    if "account_a" not in data or "account_b" not in data:
        raise HarnessUnavailable("creds file needs account_a and account_b")
    return data


class IdorHarness(ProofHarness):
    vuln_class = VulnClass.IDOR
    sends_active_payload = True

    def run(self, candidate: Candidate, target: Target, config: Config) -> ValidationResult:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise HarnessUnavailable("httpx not installed (pip install .[dynamic])") from exc

        accounts = _load_accounts(target)
        login = candidate.params.get(
            "login"
        )  # {"url","method","token_json_path","user_field","pass_field"}
        victim_url = candidate.params.get("victim_url")
        marker = candidate.params.get("victim_marker")
        if not (login and victim_url and marker):
            raise HarnessUnavailable("candidate needs login, victim_url, victim_marker params")

        attacker = accounts["account_a"]
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            auth = client.request(
                login.get("method", "POST"),
                login["url"],
                json={
                    login.get("user_field", "email"): attacker["email"],
                    login.get("pass_field", "password"): attacker["password"],
                },
            )
            if auth.status_code >= 400:
                raise HarnessUnavailable(f"attacker login failed: {auth.status_code}")
            token = None
            try:
                token = auth.json()
                for key in (login.get("token_json_path") or "authentication.token").split("."):
                    token = token[key]
            except Exception:
                token = None
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            resp = client.get(victim_url, headers=headers)

        ev = [
            Evidence(
                kind="http",
                label=f"attacker GET {victim_url} -> {resp.status_code}",
                content=resp.text[:2000],
            )
        ]
        poc = (
            "# Log in as attacker, then:\n"
            f"curl -sS -H 'Authorization: Bearer <token>' '{victim_url}'"
        )
        if resp.status_code < 400 and marker in resp.text:
            return ValidationResult(
                candidate_id=candidate.id,
                vuln_class=VulnClass.IDOR,
                status=ValidationStatus.CONFIRMED,
                reason=(
                    f"attacker read victim object (marker {marker!r} present, {resp.status_code})"
                ),
                reproducible=True,
                poc=poc,
                evidence=ev,
            )
        return ValidationResult(
            candidate_id=candidate.id,
            vuln_class=VulnClass.IDOR,
            status=ValidationStatus.REJECTED,
            reason=f"access control held ({resp.status_code}; victim marker absent)",
            poc=poc,
            evidence=ev,
        )
