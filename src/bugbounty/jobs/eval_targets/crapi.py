"""crAPI adapter: graded against a local crAPI stack (OWASP API Top 10).

Uses crAPI's pre-seeded data as ground truth: BOLA on mechanic reports and shop
orders, excessive data exposure on community posts (leaks author PII), plus
false alarms where auth is actually enforced. Two accounts are registered at run
time for the IDOR harness; the seeded victims (adam007@example.com,
robot001@example.com) are what the attacker reads.

Beyond the password-login IDOR cases, one case is graded through a *handed-in*
session: both accounts' bearer tokens are captured at setup and written to a
separate gitignored secrets file, and the BOLA is proved with those live
sessions (no scripted login) -- exercising the #14 handoff path end to end in
the graded eval, the way an OAuth/SSO/MFA target would be tested.

Local sandbox only; dry-run gate cleared for this local target.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import uuid
from pathlib import Path

import yaml

from ...config import Config
from ...net import build_client
from ...scope import Platform, Target, TargetAuth
from ...validator.benchmark import Metrics
from ...validator.engine import Validator
from ...validator.models import Candidate, VulnClass
from .base import EvalCase, EvalResult, EvalTarget, grade

_CREDS = "secrets/crapi-eval.yaml"
_SESSION_CREDS = "secrets/crapi-eval-session.yaml"
_PW = "Crapi.Test!123"
VICTIM = "adam007@example.com"  # seeded owner of mechanic report #1 / order #1
COMMUNITY_PII = "robot001@example.com"  # seeded community-post author e-mail


def _merge(a: Metrics, b: Metrics) -> Metrics:
    return Metrics(tp=a.tp + b.tp, fp=a.fp + b.fp, tn=a.tn + b.tn, fn=a.fn + b.fn)


def _write_secret(path: str, data: dict) -> None:
    """Write a credentials file atomically, 0600, without following a symlink.

    It holds live passwords/bearer tokens, so a pre-planted symlink at ``path``
    must never redirect the write and no other local user may read the result.
    ``mkstemp`` creates a fresh 0600 file in the same directory; ``os.replace``
    then atomically renames it onto ``path`` -- which replaces a symlink at that
    name rather than following it to its target."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".crapi-creds-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(yaml.safe_dump(data))
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


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

    def _accounts(self, config: Config) -> tuple[dict, dict] | None:
        """Register two accounts and capture both a password record (login path)
        and a live bearer token (handed-in-session path). Fail-closed: returns
        None if signup/login fails rather than reusing stale accounts."""
        sfx = uuid.uuid4().hex[:6]
        # crAPI enforces unique email AND phone number, so a fixed number would
        # collide with a prior run's registrations in the long-lived DB. Derive a
        # fresh 10-digit number per run from the same suffix.
        base_num = int(sfx, 16) % 1_000_000_000
        accts = {
            "account_a": {"email": f"bench_a_{sfx}@example.com", "password": _PW},
            "account_b": {"email": f"bench_b_{sfx}@example.com", "password": _PW},
        }
        tokens: dict[str, str] = {}
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
                for key in ("account_a", "account_b"):
                    r = c.post(
                        "/identity/api/auth/login",
                        json={"email": accts[key]["email"], "password": _PW},
                    )
                    tok = r.json().get("token") if r.status_code < 400 else None
                    if not tok:
                        return None
                    tokens[key] = tok
        except Exception:  # noqa: BLE001
            return None
        # Handed-in sessions: live bearer tokens, no password -> the IDOR harness
        # takes its manual (origin-pinned) path, never a scripted login.
        session_accts = {
            "account_a": {"bearer_token": tokens["account_a"]},
            "account_b": {"bearer_token": tokens["account_b"]},
        }
        return accts, session_accts

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

    def _session_cases(self) -> list[EvalCase]:
        """Auth-gated case graded through handed-in bearer sessions (no login spec
        on the candidate -> the IDOR harness uses its manual, origin-pinned path)."""
        b = self.base_url
        report_url = f"{b}/workshop/api/mechanic/mechanic_report?report_id=1"
        return [
            EvalCase(
                Candidate(
                    id="crapi-bola-mechanic-report-session",
                    target_name="crapi",
                    vuln_class=VulnClass.IDOR,
                    title="BOLA via handed-in session: read another user's mechanic report",
                    url=report_url,
                    host="localhost",
                    params={"victim_url": report_url, "victim_marker": VICTIM},
                ),
                True,
                note="two-account BOLA proved with handed-in bearer sessions (no scripted login)",
            ),
        ]

    def run(self, config: Config | None = None) -> EvalResult:
        if not self.available():
            return EvalResult(
                self.name, False, note="crAPI not reachable at :8888; run docker_setup"
            )
        config = config or Config(dry_run=False)  # local sandbox: clear the gate here only
        prepared = self._accounts(config)
        if prepared is None:
            return EvalResult(
                self.name, False, note="crAPI signup/login failed; stack may still be seeding"
            )
        accts, session_accts = prepared
        _write_secret(_CREDS, accts)
        _write_secret(_SESSION_CREDS, session_accts)

        def _target(creds_ref: str) -> Target:
            return Target(
                name="crapi",
                platform=Platform.SELF,
                safe_harbor_url="https://github.com/OWASP/crAPI",
                in_scope=["localhost", "127.0.0.1"],
                dry_run=False,
                auth=TargetAuth(multi_account=True, creds_ref=creds_ref),
            )

        validator = Validator(config)
        m, ms, rows = grade(self._cases(), validator, _target(_CREDS))
        sm, sms, srows = grade(self._session_cases(), validator, _target(_SESSION_CREDS))
        return EvalResult(self.name, True, _merge(m, sm), _merge(ms, sms), rows + srows)
