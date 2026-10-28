"""IDOR / broken-access-control proof harness: two accounts, airtight.

The claim is "attacker A can read victim B's private object". Proving that is
not just "A got a 200 with the marker in it" -- a *public* or *shared* object
would pass that weak test and produce a false positive. This harness nails down
every leg of the argument before confirming:

  1. Log in as A and as B. Their tokens must differ (two real, distinct
     sessions -- otherwise the whole premise is void).
  2. Owner baseline: B requests B's object and *does* see the marker. This
     proves the marker genuinely identifies B's private object and that the
     endpoint is reachable. If the owner can't see it, the test is broken, not
     passed -> UNCONFIRMED.
  3. Public baseline: an *unauthenticated* client requests B's object. If it
     sees the marker, the object is public/shared, not an IDOR -> REJECTED.
  4. Attacker: A requests B's object.

CONFIRMED only when: owner sees it, the public sees it NOT, and attacker A DOES
see it with a success status. Every request (identity, method, URL, status) is
logged as evidence, and a curl PoC is emitted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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


def evaluate_idor(
    *,
    owner_sees_marker: bool,
    public_sees_marker: bool,
    attacker_status: int,
    attacker_sees_marker: bool,
) -> tuple[ValidationStatus, str]:
    """Pure decision over the four observations. No I/O.

    Returns (status, reason). The ordering matters: a broken setup (owner can't
    see its own object) is UNCONFIRMED, a public object is a REJECT (defends
    against the classic shared/public false positive), and only a clean
    attacker read is CONFIRMED.
    """
    if not owner_sees_marker:
        raise HarnessUnavailable(
            "owner (B) could not read its own object with the given marker; "
            "cannot prove anything (bad marker/victim_url or setup)"
        )
    if public_sees_marker:
        return (
            ValidationStatus.REJECTED,
            "object is public: an unauthenticated request already returns the "
            "marker, so attacker access is not a broken-access-control bug",
        )
    if attacker_status >= 400:
        return (
            ValidationStatus.REJECTED,
            f"access control held: attacker request denied ({attacker_status})",
        )
    if not attacker_sees_marker:
        return (
            ValidationStatus.REJECTED,
            f"access control held: attacker got {attacker_status} but the victim marker was absent",
        )
    return (
        ValidationStatus.CONFIRMED,
        f"attacker A read victim B's private object (marker present, "
        f"{attacker_status}); owner could read it, public could not",
    )


class IdorHarness(ProofHarness):
    vuln_class = VulnClass.IDOR
    sends_active_payload = True

    def __init__(self, transport: Any | None = None) -> None:
        self._transport = transport  # httpx transport for deterministic tests

    def _login(self, client: Any, login: dict, account: dict) -> str:
        auth = client.request(
            login.get("method", "POST"),
            login["url"],
            json={
                login.get("user_field", "email"): account["email"],
                login.get("pass_field", "password"): account["password"],
            },
        )
        if auth.status_code >= 400:
            raise HarnessUnavailable(f"login failed for {account['email']}: {auth.status_code}")
        token: Any = None
        try:
            token = auth.json()
            for key in (login.get("token_json_path") or "authentication.token").split("."):
                token = token[key]
        except Exception as exc:  # noqa: BLE001 - any shape miss means no token
            raise HarnessUnavailable(
                f"could not extract token for {account['email']}: {exc}"
            ) from exc
        if not token:
            raise HarnessUnavailable(f"empty token for {account['email']}")
        return str(token)

    def run(self, candidate: Candidate, target: Target, config: Config) -> ValidationResult:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise HarnessUnavailable("httpx not installed (pip install .[dynamic])") from exc

        accounts = _load_accounts(target)
        login = candidate.params.get("login")
        victim_url = candidate.params.get("victim_url")
        marker = candidate.params.get("victim_marker")
        if not (login and victim_url and marker):
            raise HarnessUnavailable("candidate needs login, victim_url, victim_marker params")

        client_kw: dict[str, Any] = {"timeout": 15.0, "follow_redirects": True}
        if self._transport is not None:
            client_kw["transport"] = self._transport

        evidence: list[Evidence] = []
        with httpx.Client(**client_kw) as client:
            tok_a = self._login(client, login, accounts["account_a"])
            tok_b = self._login(client, login, accounts["account_b"])
            if tok_a == tok_b:
                raise HarnessUnavailable(
                    "account_a and account_b resolved to the same session token; "
                    "two distinct accounts are required for an IDOR proof"
                )

            def _get(label: str, headers: dict[str, str]) -> Any:
                r = client.get(victim_url, headers=headers)
                evidence.append(
                    Evidence(
                        kind="http",
                        label=f"{label} GET {victim_url} -> {r.status_code}",
                        content=r.text[:2000],
                    )
                )
                return r

            owner = _get("owner(B)", {"Authorization": f"Bearer {tok_b}"})
            public = _get("public(anon)", {})
            attacker = _get("attacker(A)", {"Authorization": f"Bearer {tok_a}"})

        status, reason = evaluate_idor(
            owner_sees_marker=(owner.status_code < 400 and marker in owner.text),
            public_sees_marker=(public.status_code < 400 and marker in public.text),
            attacker_status=attacker.status_code,
            attacker_sees_marker=(marker in attacker.text),
        )
        poc = (
            "# Log in as attacker A and as victim B (distinct accounts).\n"
            "# Owner check (expect marker present):\n"
            f"curl -sS -H 'Authorization: Bearer <token_B>' '{victim_url}'\n"
            "# Public check (expect marker ABSENT -- else the object is public):\n"
            f"curl -sS '{victim_url}'\n"
            "# Attacker check (IDOR if marker present):\n"
            f"curl -sS -H 'Authorization: Bearer <token_A>' '{victim_url}'"
        )
        return ValidationResult(
            candidate_id=candidate.id,
            vuln_class=VulnClass.IDOR,
            status=status,
            reason=reason,
            reproducible=(status is ValidationStatus.CONFIRMED),
            poc=poc,
            evidence=evidence,
        )
