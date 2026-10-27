import textwrap

import pytest
from pydantic import ValidationError

from bugbounty.scope import AiPolicy, Platform, Target, load_allowlist


def _write(tmp_path, body: str):
    p = tmp_path / "targets.yaml"
    p.write_text(textwrap.dedent(body))
    return p


def test_in_scope_exact_and_wildcard(tmp_path):
    al = load_allowlist(
        _write(
            tmp_path,
            """
            targets:
              - name: "Prog"
                platform: "hackerone"
                safe_harbor_url: "https://x/sh"
                in_scope: ["app.example.com", "*.api.example.com"]
                out_of_scope: []
            """,
        )
    )
    assert al.decide("Prog", "app.example.com").allowed is True
    assert al.decide("Prog", "v1.api.example.com").allowed is True


def test_out_of_scope_wins_over_in_scope(tmp_path):
    al = load_allowlist(
        _write(
            tmp_path,
            """
            targets:
              - name: "Prog"
                platform: "hackerone"
                safe_harbor_url: "https://x/sh"
                in_scope: ["*.example.com"]
                out_of_scope: ["blog.example.com"]
            """,
        )
    )
    d = al.decide("Prog", "blog.example.com")
    assert d.allowed is False
    assert "out of scope" in d.reason


def test_unmatched_host_fails_closed(tmp_path):
    al = load_allowlist(
        _write(
            tmp_path,
            """
            targets:
              - name: "Prog"
                platform: "self"
                safe_harbor_url: "https://x/sh"
                in_scope: ["localhost"]
                out_of_scope: []
            """,
        )
    )
    d = al.decide("Prog", "evil.com")
    assert d.allowed is False
    assert "fail closed" in d.reason


def test_unknown_target_blocked(tmp_path):
    al = load_allowlist(
        _write(
            tmp_path,
            """
            targets:
              - name: "Prog"
                platform: "self"
                safe_harbor_url: "https://x/sh"
                in_scope: ["localhost"]
            """,
        )
    )
    assert al.decide("Nope", "localhost").allowed is False


def test_safe_harbor_required(tmp_path):
    with pytest.raises(ValidationError):
        load_allowlist(
            _write(
                tmp_path,
                """
                targets:
                  - name: "Prog"
                    platform: "self"
                    safe_harbor_url: ""
                    in_scope: ["localhost"]
                """,
            )
        )


def test_duplicate_names_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_allowlist(
            _write(
                tmp_path,
                """
                targets:
                  - name: "Dup"
                    platform: "self"
                    safe_harbor_url: "https://x/sh"
                    in_scope: ["localhost"]
                  - name: "Dup"
                    platform: "self"
                    safe_harbor_url: "https://x/sh"
                    in_scope: ["127.0.0.1"]
                """,
            )
        )


def test_target_defaults():
    t = Target(name="t", platform=Platform.SELF, safe_harbor_url="https://x/sh")
    assert t.dry_run is True
    assert t.ai_policy is AiPolicy.UNKNOWN
    assert t.pays_cash is False
    assert t.auth.multi_account is False
