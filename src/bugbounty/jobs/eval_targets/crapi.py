"""crAPI adapter: graded against a local crAPI stack (OWASP API Top 10).

Uses crAPI's pre-seeded data as ground truth: BOLA on mechanic reports and shop
orders, excessive data exposure on community posts (leaks author PII), plus
false alarms where auth is actually enforced. Two accounts are registered at run
time for the IDOR harness; the seeded victims (adam007@example.com,
robot001@example.com) are what the attacker reads.

Local sandbox only; dry-run gate cleared for this local target.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import yaml

from ...config import Config
from ...net import build_client
from ...scope import Platform, Target, TargetAuth
from ...validator.engine import Validator
from ...validator.models import Candidate, VulnClass
from .base import EvalCase, EvalResult, EvalTarget, grade

_CREDS = "secrets/crapi-eval.yaml"
_PW = "Crapi.Test!123"
VICTIM = "adam007@example.com"  # seeded owner of mechanic report #1 / order #1
COMMUNITY_PII = "robot001@example.com"  # seeded community-post author e-mail


class CrapiTarget(EvalTarget):
    name = "crapi"
    base_url = "http://localhost:8888"

    def docker_setup(self) -> str:
        return (
            "git clone --depth 1 https://github.com/OWASP/crAPI /tmp/crAPI\n"
            "cd /tmp/crAPI && docker compose -f deploy/docker/docker-compose.yml pull\n"
            "docker compose -f deploy/docker/docker-compose.yml up -d\n"
            "# gateway/web on http://localhost:8888 ; seeded demo data loads on startup"
        )

    def _accounts(self, config: Config) -> dict | None:
        sfx = uuid.uuid4().hex[:6]
        # crAPI enforces unique email AND phone number, so a fixed number would
        # collide with a prior run's registrations in the long-lived DB. Derive a
        # fresh 10-digit number per run from the same suffix (fail-closed: grading
        # is skipped if signup/login fails rather than reusing stale accounts).
        base_num = int(sfx, 16) % 1_000_000_000
        accts = {
            "account_a": {"email": f"bench_a_{sfx}@example.com", "password": _PW},
            "account_b": {"email": f"bench_b_{sfx}@example.com", "password": _PW},
        }
        try:
            with build_client(config, base_url=self.base_url, timeout=30.0) as c:
                for i, key in enumerate(("account_a", "account_b")):
                    c.post(
                        "/identity/api/auth/signup",
                        json={
                            "name": "Bench",
                            "email": accts[key]["email"],
                            "number": f"9{(base_num + i) % 1_000_000_000:09d}",
                            "password": _PW,
                        },
                    )
                r = c.post(
                    "/identity/api/auth/login",
                    json={"email": accts["account_a"]["email"], "password": _PW},
                )
                if r.status_code >= 400 or not r.json().get("token"):
                    return None
        except Exception:  # noqa: BLE001
            return None
        return accts

    def _cases(self) -> list[EvalCase]:
        b = self.base_url
        login = {
            "url": f"{b}/identity/api/auth/login",
            "method": "POST",
            "token_json_path": "token",
            "user_field": "email",
            "pass_field": "password",
        }
        contains = lambda v: {"type": "contains", "value": v}  # noqa: E731

        def idor(cid, title, path, marker, vuln):
            url = f"{b}{path}"
            return EvalCase(
                Candidate(
                    id=cid,
                    target_name="crapi",
                    vuln_class=VulnClass.IDOR,
                    title=title,
                    url=url,
                    host="localhost",
                    params={"login": login, "victim_url": url, "victim_marker": marker},
                ),
                vuln,
            )

        report_url = f"{b}/workshop/api/mechanic/mechanic_report?report_id=1"
        fake_unauth = EvalCase(
            Candidate(
                id="crapi-fake-unauth-report",
                target_name="crapi",
                vuln_class=VulnClass.AUTH,
                title="Claim: mechanic report readable without authentication",
                url=report_url,
                host="localhost",
                params={
                    "requests": [{"method": "GET", "url": report_url}],
                    "oracle": contains(VICTIM),
                },
            ),
            False,
        )
        return [
            # ---- true positives ----
            idor(
                "crapi-bola-mechanic-report",
                "BOLA: read another user's mechanic report",
                "/workshop/api/mechanic/mechanic_report?report_id=1",
                VICTIM,
                True,
            ),
            # This crAPI build serves shop order #1 with NO auth (verified: an
            # unauthenticated GET returns the owner's PII), so the two-account
            # BOLA oracle correctly refuses to call a *public* object a broken-
            # access-control bug. Labelled a limitation (counts only toward the
            # all-cases metrics); the real bug is proven as missing-auth below.
            EvalCase(
                Candidate(
                    id="crapi-bola-shop-order",
                    target_name="crapi",
                    vuln_class=VulnClass.IDOR,
                    title="BOLA: read another user's shop order",
                    url=f"{b}/workshop/api/shop/orders/1",
                    host="localhost",
                    params={
                        "login": login,
                        "victim_url": f"{b}/workshop/api/shop/orders/1",
                        "victim_marker": VICTIM,
                    },
                ),
                True,
                category="limitation",
                note="endpoint is public in this build; BOLA needs an access boundary",
            ),
            # Real bug, proven under the correct class: the same order is readable
            # with no authentication at all (missing function-level authorization).
            EvalCase(
                Candidate(
                    id="crapi-unauth-shop-order",
                    target_name="crapi",
                    vuln_class=VulnClass.AUTH,
                    title="Missing auth: shop order readable unauthenticated",
                    url=f"{b}/workshop/api/shop/orders/1",
                    host="localhost",
                    params={
                        "requests": [{"method": "GET", "url": f"{b}/workshop/api/shop/orders/1"}],
                        "oracle": contains(VICTIM),
                    },
                ),
                True,
            ),
            idor(
                "crapi-exposure-community",
                "Excessive data exposure: community posts leak author PII",
                "/community/api/v2/community/posts/recent",
                COMMUNITY_PII,
                True,
            ),
            # ---- false alarms (expect REJECTED) ----
            fake_unauth,
            idor(
                "crapi-fake-idor-dashboard",
                "Claim: dashboard leaks another user's data",
                "/identity/api/v2/user/dashboard",
                VICTIM,
                False,
            ),
        ]

    def run(self, config: Config | None = None) -> EvalResult:
        if not self.available():
            return EvalResult(
                self.name, False, note="crAPI not reachable at :8888; run docker_setup"
            )
        config = config or Config(dry_run=False)  # local sandbox: clear the gate here only
        accts = self._accounts(config)
        if accts is None:
            return EvalResult(
                self.name, False, note="crAPI signup/login failed; stack may still be seeding"
            )
        Path(_CREDS).parent.mkdir(parents=True, exist_ok=True)
        Path(_CREDS).write_text(yaml.safe_dump(accts))
        target = Target(
            name="crapi",
            platform=Platform.SELF,
            safe_harbor_url="https://github.com/OWASP/crAPI",
            in_scope=["localhost", "127.0.0.1"],
            dry_run=False,
            auth=TargetAuth(multi_account=True, creds_ref=_CREDS),
        )
        m, ms, rows = grade(self._cases(), Validator(config), target)
        return EvalResult(self.name, True, m, ms, rows)
