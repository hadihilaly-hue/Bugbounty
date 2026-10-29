"""IDOR harness: airtight two-account logic + public-object guard.

Pure-decision tests cover every branch; the end-to-end tests drive the real
``IdorHarness.run`` over an httpx MockTransport (no network) for a true positive
and the hard negative that matters most -- a public object that the old weak
oracle would have false-positived on.
"""

import json

import httpx
import pytest

from bugbounty.config import Config
from bugbounty.scope import Platform, Target, TargetAuth
from bugbounty.validator.base import HarnessUnavailable
from bugbounty.validator.harnesses.idor import IdorHarness, evaluate_idor
from bugbounty.validator.models import Candidate, ValidationStatus, VulnClass


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    # These suites verify oracle/session logic, not politeness. Disable per-host
    # pacing so the now-paced proof client adds no real sleeps here; pacing has
    # its own coverage in tests/test_proof_harness_pacing.py.
    monkeypatch.setenv("BB_PER_HOST_RPS", "0")


MARKER = "Victim-Secret-Melon-9f3a"
A_EMAIL = "attacker_a@test.local"
B_EMAIL = "victim_b@test.local"


# --------------------------- pure decision logic --------------------------- #


def test_confirmed_when_attacker_reads_private_object():
    status, reason = evaluate_idor(
        owner_sees_marker=True,
        public_sees_marker=False,
        attacker_status=200,
        attacker_sees_marker=True,
    )
    assert status is ValidationStatus.CONFIRMED
    assert "victim" in reason.lower()


def test_rejected_public_object_is_not_idor():
    status, reason = evaluate_idor(
        owner_sees_marker=True,
        public_sees_marker=True,  # anon already sees it
        attacker_status=200,
        attacker_sees_marker=True,
    )
    assert status is ValidationStatus.REJECTED
    assert "public" in reason.lower()


def test_rejected_when_access_control_denies_attacker():
    status, _ = evaluate_idor(
        owner_sees_marker=True,
        public_sees_marker=False,
        attacker_status=403,
        attacker_sees_marker=False,
    )
    assert status is ValidationStatus.REJECTED


def test_rejected_when_marker_absent_despite_200():
    status, reason = evaluate_idor(
        owner_sees_marker=True,
        public_sees_marker=False,
        attacker_status=200,
        attacker_sees_marker=False,
    )
    assert status is ValidationStatus.REJECTED
    assert "absent" in reason.lower()


def test_broken_setup_when_owner_cannot_read_own_object():
    with pytest.raises(HarnessUnavailable):
        evaluate_idor(
            owner_sees_marker=False,
            public_sees_marker=False,
            attacker_status=200,
            attacker_sees_marker=True,
        )


# ------------------------------- end to end ------------------------------- #

BASE = "https://shop.test"
LOGIN = f"{BASE}/rest/user/login"
VICTIM = f"{BASE}/rest/basket/42"
_TOKENS = {A_EMAIL: "token-A-abc", B_EMAIL: "token-B-xyz"}


def _handler(*, public: bool):
    def handle(request: httpx.Request) -> httpx.Response:
        if str(request.url) == LOGIN:
            email = json.loads(request.content)["email"]
            return httpx.Response(200, json={"authentication": {"token": _TOKENS[email]}})
        # victim object GET
        authed = request.headers.get("authorization", "").startswith("Bearer ")
        if public or authed:
            return httpx.Response(200, text=f'{{"id":42,"item":"{MARKER}"}}')
        return httpx.Response(401, text='{"error":"unauthenticated"}')

    return handle


def _target(creds_path) -> Target:
    return Target(
        name="shop",
        platform=Platform.SELF,
        safe_harbor_url=f"{BASE}/sh",
        in_scope=["shop.test"],
        dry_run=False,
        auth=TargetAuth(multi_account=True, creds_ref=str(creds_path)),
    )


def _candidate(victim_url: str) -> Candidate:
    return Candidate(
        id="idor-e2e",
        target_name="shop",
        vuln_class=VulnClass.IDOR,
        title="read victim basket",
        url=victim_url,
        host="shop.test",
        params={
            "login": {"url": LOGIN, "method": "POST", "token_json_path": "authentication.token"},
            "victim_url": victim_url,
            "victim_marker": MARKER,
        },
    )


def _creds(tmp_path):
    import yaml

    p = tmp_path / "creds.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "account_a": {"email": A_EMAIL, "password": "pw"},
                "account_b": {"email": B_EMAIL, "password": "pw"},
            }
        )
    )
    return p


def test_e2e_true_positive_private_basket(tmp_path):
    harness = IdorHarness(transport=httpx.MockTransport(_handler(public=False)))
    r = harness.run(_candidate(VICTIM), _target(_creds(tmp_path)), Config(dry_run=False))
    assert r.status is ValidationStatus.CONFIRMED
    assert r.reproducible is True
    # Every identity's request is logged, in order.
    labels = [e.label for e in r.evidence]
    assert any("owner(B)" in x for x in labels)
    assert any("public(anon)" in x for x in labels)
    assert any("attacker(A)" in x for x in labels)


def test_e2e_hard_negative_public_object(tmp_path):
    harness = IdorHarness(transport=httpx.MockTransport(_handler(public=True)))
    r = harness.run(_candidate(VICTIM), _target(_creds(tmp_path)), Config(dry_run=False))
    assert r.status is ValidationStatus.REJECTED
    assert "public" in r.reason.lower()


def test_e2e_same_token_for_both_accounts_is_unavailable(tmp_path, monkeypatch):
    # If the two "accounts" resolve to one session, the premise is void.
    monkeypatch.setitem(_TOKENS, B_EMAIL, _TOKENS[A_EMAIL])
    harness = IdorHarness(transport=httpx.MockTransport(_handler(public=False)))
    with pytest.raises(HarnessUnavailable):
        harness.run(_candidate(VICTIM), _target(_creds(tmp_path)), Config(dry_run=False))
    monkeypatch.setitem(_TOKENS, B_EMAIL, "token-B-xyz")
