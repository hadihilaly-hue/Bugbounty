"""Oracle logic for the generic HTTP PoC harness (no network)."""

import pytest

from bugbounty.validator.base import HarnessUnavailable
from bugbounty.validator.harnesses.httppoc import _curl, _oracle_matches


def test_contains_oracle():
    assert _oracle_matches({"type": "contains", "value": "root:x:"}, 200, "root:x:0:0") is True
    assert _oracle_matches({"type": "contains", "value": "root:x:"}, 200, "nope") is False


def test_status_oracle():
    assert _oracle_matches({"type": "status", "value": 200}, 200, "") is True
    assert _oracle_matches({"type": "status", "value": 200}, 403, "") is False


def test_regex_oracle():
    assert _oracle_matches({"type": "regex", "value": r"id=\d+"}, 200, "id=42") is True


def test_unknown_oracle_raises():
    with pytest.raises(HarnessUnavailable):
        _oracle_matches({"type": "telepathy", "value": 1}, 200, "")


def test_curl_render():
    c = _curl({"method": "post", "url": "http://h/x", "headers": {"A": "b"}, "body": "d=1"})
    assert c.startswith("curl -sS -X POST")
    assert "'A: b'" in c and "--data d=1" in c
