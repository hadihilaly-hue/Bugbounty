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
                            "number": f"41528{i:05d}",
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
            idor(
                "crapi-bola-shop-order",
                "BOLA: read another user's shop order",
                "/workshop/api/shop/orders/1",
                VICTIM,
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
