"""Real-target safety: attribution headers, per-target pacing, fail-loud schema.

Covers the first real authorized program (Nebius AI VDP) wiring: unknown target
keys must fail loud (never silently dropped), a required attribution header
(HackerOne's X-HackerOne-Research) must ride on every proof request and must
block a run while it is still a placeholder, and a per-target rate_limit must
override the global pace.
"""

from __future__ import annotations

import httpx
import pytest
import yaml
from pydantic import ValidationError

from bugbounty.config import Config
from bugbounty.net.pacing import PacingConfig
from bugbounty.scope import Platform, Target, load_allowlist
from bugbounty.validator.base import HarnessUnavailable
from bugbounty.validator.harnesses.idor import IdorHarness
from bugbounty.validator.models import Candidate, ValidationStatus, VulnClass

MARKER = "Owner-Private-Ledger-NEB"


def test_nebius_loads_and_scope_is_fail_closed():
    al = load_allowlist("targets.yaml")
    n = al.target_by_name("Nebius AI VDP")
    assert n is not None and n.platform is Platform.HACKERONE
    assert n.required_headers == {"X-HackerOne-Research": "YOUR_H1_USERNAME"}
    assert n.rate_limit and n.rate_limit.per_host_rps == 1
    assert n.auth.mode == "manual" and n.auth.creds_ref == "secrets/nebius.yaml"
    assert al.decide("Nebius AI VDP", "console.nebius.com").allowed
    assert al.decide("Nebius AI VDP", "api.nebius.cloud").allowed
    # out-of-scope wildcard subdomains of critical assets, and fail-closed default
    assert not al.decide("Nebius AI VDP", "testing.console.nebius.com").allowed
    assert not al.decide("Nebius AI VDP", "staging.api.nebius.cloud").allowed
    assert not al.decide("Nebius AI VDP", "evil.com").allowed


def test_unknown_target_key_fails_loud():
    with pytest.raises(ValidationError):
        Target.model_validate(
            {"name": "x", "platform": "self", "safe_harbor_url": "y", "required_header": {}}
        )


def test_unfilled_required_headers_flags_placeholders():
    t = Target(
        name="n",
        platform=Platform.HACKERONE,
        safe_harbor_url="https://h1/sh",
        required_headers={"X-HackerOne-Research": "YOUR_H1_USERNAME", "X-Empty": ""},
    )
    assert set(t.unfilled_required_headers()) == {"X-HackerOne-Research", "X-Empty"}
    t2 = Target(
        name="n",
        platform=Platform.HACKERONE,
        safe_harbor_url="https://h1/sh",
        required_headers={"X-HackerOne-Research": "realuser"},
    )
    assert t2.unfilled_required_headers() == []


def test_per_host_rps_override():
    assert PacingConfig.from_config(Config(), per_host_rps=5).per_host_rps == 5
    assert PacingConfig.from_config(Config()).per_host_rps == 1.0  # global default


def _nebius_like_target(tmp_path, header_value: str):
    creds = tmp_path / "neb.yaml"
    creds.write_text(
        yaml.safe_dump(
            {"account_a": {"cookies": {"sid": "A"}}, "account_b": {"cookies": {"sid": "B"}}}
        )
    )
    from bugbounty.scope import TargetAuth

    return Target(
        name="Nebius AI VDP",
        platform=Platform.HACKERONE,
        safe_harbor_url="https://hackerone.com/nebius_ai_vdp",
        in_scope=["app.test"],
        dry_run=True,
        required_headers={"X-HackerOne-Research": header_value},
        auth=TargetAuth(multi_account=True, creds_ref=str(creds), mode="manual"),
    )


def _idor_candidate(victim: str) -> Candidate:
    return Candidate(
        id="neb-bola",
        target_name="Nebius AI VDP",
        vuln_class=VulnClass.IDOR,
        title="cross-account read",
        url=victim,
        host="app.test",
        params={"victim_url": victim, "victim_marker": MARKER},
    )


def test_required_header_rides_on_every_proof_request(tmp_path):
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-hackerone-research"))
        authed = "sid=" in request.headers.get("cookie", "")
        return httpx.Response(
            200 if authed else 401, text=f'{{"m":"{MARKER}"}}' if authed else "no"
        )

    target = _nebius_like_target(tmp_path, "realuser")
    victim = "https://app.test/obj/1"
    r = IdorHarness(transport=httpx.MockTransport(handler)).run(
        _idor_candidate(victim), target, Config(dry_run=True)
    )
    assert r.status is ValidationStatus.CONFIRMED
    assert seen and all(v == "realuser" for v in seen)  # attribution on owner/public/attacker


def test_proof_refuses_unfilled_attribution_header(tmp_path):
    target = _nebius_like_target(tmp_path, "YOUR_H1_USERNAME")
    victim = "https://app.test/obj/1"
    with pytest.raises(HarnessUnavailable, match="required header"):
        IdorHarness(transport=httpx.MockTransport(lambda r: httpx.Response(200))).run(
            _idor_candidate(victim), target, Config(dry_run=True)
        )


def test_rate_limit_rejects_nonpositive_rps():
    from bugbounty.scope import RateLimit

    with pytest.raises(ValidationError):
        RateLimit(per_host_rps=0)
    with pytest.raises(ValidationError):
        RateLimit(per_host_rps=-1)


def test_engine_refuses_unfilled_attribution_for_real_target(tmp_path):
    """Central guard: a direct Validator.validate against a real target whose
    required header is a placeholder must not run any harness."""
    from bugbounty.validator import Validator

    target = _nebius_like_target(tmp_path, "YOUR_H1_USERNAME")
    cand = _idor_candidate("https://app.test/obj/1")
    res = Validator(Config(dry_run=True)).validate(cand, target)
    assert res.status is ValidationStatus.UNCONFIRMED
    assert "unfilled" in res.reason or "placeholder" in res.reason


def test_candidate_header_cannot_erase_required_attribution(tmp_path):
    """A proof step that sets X-HackerOne-Research must not override the validated
    client default -- required_headers win last."""
    from bugbounty.scope import Platform, Target
    from bugbounty.validator.harnesses.httppoc import HttpPocHarness

    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-hackerone-research"))
        return httpx.Response(200, text="ok")

    target = Target(
        name="Nebius AI VDP",
        platform=Platform.HACKERONE,
        safe_harbor_url="https://hackerone.com/nebius_ai_vdp",
        in_scope=["app.test"],
        dry_run=True,
        required_headers={"X-HackerOne-Research": "realuser"},
    )
    cand = Candidate(
        id="neb-poc",
        target_name="Nebius AI VDP",
        vuln_class=VulnClass.AUTH,
        title="poc",
        url="https://app.test/x",
        host="app.test",
        params={
            "requests": [
                {
                    "name": "one",
                    "method": "GET",
                    "url": "https://app.test/x",
                    "headers": {"X-HackerOne-Research": "attacker-spoof"},
                }
            ],
            "oracle": {"type": "status", "value": 200, "on": "one"},
        },
    )
    HttpPocHarness(VulnClass.AUTH, transport=httpx.MockTransport(handler)).run(
        cand, target, Config(dry_run=True)
    )
    assert seen == ["realuser"]  # the candidate's spoofed value did not win


def test_xss_refuses_real_target_with_required_headers(tmp_path):
    from bugbounty.scope import Platform, Target
    from bugbounty.validator.harnesses.xss import XssHarness

    target = Target(
        name="Nebius AI VDP",
        platform=Platform.HACKERONE,
        safe_harbor_url="https://hackerone.com/nebius_ai_vdp",
        in_scope=["app.test"],
        dry_run=True,
        required_headers={"X-HackerOne-Research": "realuser"},
    )
    cand = Candidate(
        id="neb-xss",
        target_name="Nebius AI VDP",
        vuln_class=VulnClass.XSS,
        title="xss",
        url="https://app.test/?q={NONCE}",
        host="app.test",
        params={"expect_marker": "{NONCE}"},
    )
    with pytest.raises(HarnessUnavailable, match="not yet enforced"):
        XssHarness().run(cand, target, Config(dry_run=True))


def test_poc_renders_effective_required_header_not_candidate_spoof(tmp_path):
    """A confirmed HTTP proof's PoC must reproduce the request actually sent:
    required_headers (winning) appear in the rendered curl, not the spoof."""
    from bugbounty.scope import Platform, Target
    from bugbounty.validator.harnesses.httppoc import HttpPocHarness

    target = Target(
        name="Nebius AI VDP",
        platform=Platform.HACKERONE,
        safe_harbor_url="https://hackerone.com/nebius_ai_vdp",
        in_scope=["app.test"],
        dry_run=True,
        required_headers={"X-HackerOne-Research": "realuser"},
    )
    cand = Candidate(
        id="neb-poc2",
        target_name="Nebius AI VDP",
        vuln_class=VulnClass.AUTH,
        title="poc",
        url="https://app.test/x",
        host="app.test",
        params={
            "requests": [
                {
                    "name": "one",
                    "method": "GET",
                    "url": "https://app.test/x",
                    "headers": {"X-HackerOne-Research": "attacker-spoof"},
                }
            ],
            "oracle": {"type": "status", "value": 200, "on": "one"},
        },
    )
    r = HttpPocHarness(
        VulnClass.AUTH, transport=httpx.MockTransport(lambda rq: httpx.Response(200, text="ok"))
    ).run(cand, target, Config(dry_run=True))
    assert "realuser" in r.poc and "attacker-spoof" not in r.poc
