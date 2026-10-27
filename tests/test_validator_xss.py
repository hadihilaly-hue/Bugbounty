"""XSS harness: nonce-attributed execution oracle.

The browser leg needs a provisioned Chromium (exercised by the Juice Shop
benchmark, not here); the false-positive-sensitive logic lives in the pure
functions, which is what these tests pin down -- a true positive (our nonce
fires in a dialog) and the hard negatives (reflection without execution, and a
dialog that does NOT carry our nonce, i.e. the site's own alert).
"""

import pytest

from bugbounty.validator.base import HarnessUnavailable
from bugbounty.validator.harnesses.xss import (
    evaluate_execution,
    expected_token,
    mint_nonce,
)
from bugbounty.validator.models import Candidate, VulnClass

NONCE = "xssdeadbeef0123"


def _candidate(**params) -> Candidate:
    return Candidate(
        id="x",
        target_name="t",
        vuln_class=VulnClass.XSS,
        title="x",
        url="http://localhost/#/search?q=payload",
        host="localhost",
        params=params,
    )


def test_nonce_is_high_entropy_and_unique():
    a, b = mint_nonce(), mint_nonce()
    assert a != b and a.startswith("xss") and len(a) > 10


def test_true_positive_dialog_carries_nonce():
    events = [{"kind": "dialog", "text": NONCE, "dialog_type": "alert"}]
    fired, via = evaluate_execution(events, NONCE)
    assert fired is True and "dialog" in via


def test_true_positive_console_carries_nonce():
    events = [{"kind": "console", "text": f"debug {NONCE} end"}]
    fired, via = evaluate_execution(events, NONCE)
    assert fired is True and "console" in via


def test_hard_negative_reflection_without_execution():
    # No dialog/console at all -- payload was reflected as inert text.
    fired, _ = evaluate_execution([], NONCE)
    assert fired is False


def test_hard_negative_unattributed_dialog_is_not_our_bug():
    # The site popped its own alert; it does not carry our nonce -> not proof.
    events = [{"kind": "dialog", "text": "Welcome to the site!", "dialog_type": "alert"}]
    fired, _ = evaluate_execution(events, NONCE)
    assert fired is False


def test_expected_token_prefers_nonce_when_template_used():
    c = _candidate(url_template="http://h/?q=<svg onload=alert('{NONCE}')>")
    assert expected_token(c, NONCE) == NONCE


def test_expected_token_uses_declared_marker_for_static_url():
    c = _candidate(expect_marker="pwned42")
    assert expected_token(c, NONCE) == "pwned42"


def test_expected_token_refuses_unattributed_candidate():
    # No template and no declared marker -> we cannot attribute a dialog -> refuse.
    with pytest.raises(HarnessUnavailable):
        expected_token(_candidate(), NONCE)


def test_stored_template_body_counts_as_attributed():
    c = _candidate(mode="stored", inject={"url": "http://h/c", "body_template": "x={NONCE}"})
    assert expected_token(c, NONCE) == NONCE
