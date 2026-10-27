"""Juice Shop ground-truth benchmark for the validator.

Builds a labelled candidate set -- known-vulnerable endpoints (expect CONFIRMED)
and plausible false alarms on safe/defended endpoints (expect REJECTED) -- runs
the validator against a LOCAL Juice Shop sandbox, and reports precision / recall
/ false-positive rate.

Local sandbox only. Because it sends real payloads it requires the dry-run gate
to be cleared for the sandbox target (global DRY_RUN=false + target dry_run
false). The caller is responsible for scope-checking the base URL.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..config import Config
from ..scope import Target
from .engine import Validator
from .models import Candidate, ValidationResult, ValidationStatus, VulnClass

XSS_PAYLOAD = '<iframe src="javascript:alert(`xss-bench`)">'
_PW = "BenchPassw0rd!"


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def fp_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0


def _register(client, email: str) -> None:
    client.post(
        "/api/Users/",
        json={
            "email": email,
            "password": _PW,
            "passwordRepeat": _PW,
            "securityQuestion": {"id": 1},
            "securityAnswer": "bench",
        },
    )


def _login(client, email: str) -> tuple[str, int]:
    r = client.post("/rest/user/login", json={"email": email, "password": _PW})
    r.raise_for_status()
    auth = r.json()["authentication"]
    return auth["token"], int(auth["bid"])


def _prepare_victim(base_url: str) -> tuple[dict, str, str]:
    """Register two accounts, stock the victim (B) basket, return
    (accounts, victim_basket_path, marker_product_name)."""
    import httpx

    suffix = uuid.uuid4().hex[:8]
    a_email = f"bench_a_{suffix}@test.local"
    b_email = f"bench_b_{suffix}@test.local"
    with httpx.Client(base_url=base_url, timeout=20.0) as c:
        _register(c, a_email)
        _register(c, b_email)
        tok_b, bid_b = _login(c, b_email)
        c.post(
            "/api/BasketItems/",
            json={"BasketId": bid_b, "ProductId": 2, "quantity": 1},
            headers={"Authorization": f"Bearer {tok_b}"},
        )
        marker = c.get("/api/Products/2").json()["data"]["name"]
    accounts = {
        "account_a": {"email": a_email, "password": _PW},
        "account_b": {"email": b_email, "password": _PW},
    }
    return accounts, f"{base_url}/rest/basket/{bid_b}", marker


def build_cases(base_url: str, victim_url: str, victim_marker: str) -> list[tuple[Candidate, bool]]:
    inert = f"inert-{uuid.uuid4().hex[:6]}"
    login_spec = {
        "url": f"{base_url}/rest/user/login",
        "method": "POST",
        "token_json_path": "authentication.token",
    }
    return [
        # --- true positives (expect CONFIRMED) ---
        (
            Candidate(
                id="sqli-login-bypass",
                target_name="juice",
                vuln_class=VulnClass.INJECTION,
                title="SQLi auth bypass on /rest/user/login",
                url=f"{base_url}/rest/user/login",
                host="localhost",
                params={
                    "requests": [
                        {
                            "method": "POST",
                            "url": f"{base_url}/rest/user/login",
                            "body": {"email": "' OR 1=1--", "password": "x"},
                        }
                    ],
                    "oracle": {"type": "contains", "value": "authentication"},
                },
            ),
            True,
        ),
        (
            Candidate(
                id="xss-search-dom",
                target_name="juice",
                vuln_class=VulnClass.XSS,
                title="DOM XSS via search query",
                url=f"{base_url}/#/search?q={XSS_PAYLOAD}",
                host="localhost",
            ),
            True,
        ),
        (
            Candidate(
                id="idor-basket-read",
                target_name="juice",
                vuln_class=VulnClass.IDOR,
                title="IDOR: read another user's basket",
                url=victim_url,
                host="localhost",
                params={
                    "login": login_spec,
                    "victim_url": victim_url,
                    "victim_marker": victim_marker,
                },
            ),
            True,
        ),
        # --- true negatives / false alarms (expect REJECTED) ---
        (
            Candidate(
                id="sqli-false-alarm",
                target_name="juice",
                vuln_class=VulnClass.INJECTION,
                title="Claimed SQLi that is actually just a failed login",
                url=f"{base_url}/rest/user/login",
                host="localhost",
                params={
                    "requests": [
                        {
                            "method": "POST",
                            "url": f"{base_url}/rest/user/login",
                            "body": {"email": "nobody@test.local", "password": "wrong"},
                        }
                    ],
                    "oracle": {"type": "contains", "value": "authentication"},
                },
            ),
            False,
        ),
        (
            Candidate(
                id="xss-reflected-but-inert",
                target_name="juice",
                vuln_class=VulnClass.XSS,
                title="Reflected but non-executing content",
                url=f"{base_url}/#/search?q=<b>{inert}</b>",
                host="localhost",
            ),
            False,
        ),
        (
            Candidate(
                id="idor-defended",
                target_name="juice",
                vuln_class=VulnClass.IDOR,
                title="Claimed IDOR on an admin-only resource that is enforced",
                url=f"{base_url}/api/Users",
                host="localhost",
                params={
                    "login": login_spec,
                    "victim_url": f"{base_url}/api/Users",
                    "victim_marker": "totpSecret",
                },
            ),
            False,
        ),
    ]


def run_benchmark(
    target: Target, config: Config, base_url: str
) -> tuple[list[tuple[Candidate, bool, ValidationResult]], Metrics]:
    accounts, victim_url, marker = _prepare_victim(base_url)
    if target.auth.creds_ref:
        creds_path = Path(target.auth.creds_ref)
        creds_path.parent.mkdir(parents=True, exist_ok=True)
        creds_path.write_text(yaml.safe_dump(accounts))
    validator = Validator(config)
    rows: list[tuple[Candidate, bool, ValidationResult]] = []
    m = Metrics()
    for candidate, expect in build_cases(base_url, victim_url, marker):
        result = validator.validate(candidate, target)
        confirmed = result.status is ValidationStatus.CONFIRMED
        if expect and confirmed:
            m.tp += 1
        elif expect and not confirmed:
            m.fn += 1
        elif not expect and confirmed:
            m.fp += 1
        else:
            m.tn += 1
        rows.append((candidate, expect, result))
    return rows, m
