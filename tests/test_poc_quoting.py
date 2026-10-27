"""The httppoc curl PoC must be copy-paste rerunnable even with quotes in it."""

import shlex

from bugbounty.validator.harnesses.httppoc import _curl


def test_curl_is_shell_safe_with_apostrophe_payload():
    cmd = _curl(
        {
            "method": "POST",
            "url": "http://h/rest/user/login",
            "body": {"email": "' OR 1=1--", "password": "x"},
        }
    )
    toks = shlex.split(cmd)  # raises ValueError if quoting is broken
    assert toks[0] == "curl"
    assert "http://h/rest/user/login" in toks
    assert any("OR 1=1--" in t for t in toks)


def test_curl_quotes_header_and_url():
    cmd = _curl({"method": "GET", "url": "http://h/a b", "headers": {"X": "y z"}})
    toks = shlex.split(cmd)
    assert "http://h/a b" in toks and "X: y z" in toks


def test_curl_dict_body_sets_json_content_type():
    cmd = _curl({"method": "POST", "url": "http://h/x", "body": {"a": 1}})
    assert "Content-Type: application/json" in cmd
