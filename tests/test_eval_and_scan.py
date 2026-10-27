"""Deterministic tests for the expanded eval + scan-code rulesets (no network)."""

import bugbounty.signal.semgrep as sg
from bugbounty.jobs.juiceshop_eval import build_cases
from bugbounty.signal.semgrep import DEFAULT_RULESETS
from bugbounty.validator.harnesses import default_harnesses
from bugbounty.validator.models import VulnClass


def test_default_rulesets():
    assert "p/python" in DEFAULT_RULESETS
    assert "p/security-audit" in DEFAULT_RULESETS
    assert "p/javascript" in DEFAULT_RULESETS


def test_run_semgrep_builds_multiple_configs(monkeypatch):
    captured = {}

    class _Proc:
        stdout = '{"results": []}'

    monkeypatch.setattr(sg.shutil, "which", lambda _n: "/usr/bin/semgrep")
    monkeypatch.setattr(
        sg.subprocess, "run", lambda cmd, **kw: captured.setdefault("cmd", cmd) or _Proc()
    )
    sg.run_semgrep("somepath", config=["p/python", "p/security-audit"])
    cmd = captured["cmd"]
    assert cmd.count("--config") == 2
    assert "p/python" in cmd and "p/security-audit" in cmd
    assert cmd[-1] == "somepath"


def test_other_class_has_a_harness():
    assert VulnClass.OTHER in default_harnesses()


def test_eval_case_set_shape():
    cases = build_cases("http://localhost:3000", "http://localhost:3000/rest/basket/1", "Marker")
    assert len(cases) == 18
    assert sum(1 for c in cases if c.vulnerable) == 12
    assert sum(1 for c in cases if c.category == "limitation") == 2
    assert sum(1 for c in cases if not c.vulnerable) == 6
