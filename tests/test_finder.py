"""Deterministic finder tests: no network, no LLM, no external binaries."""

from bugbounty.config import Config
from bugbounty.finder import compute_usd, parse_candidates_json
from bugbounty.finder.finder import Finder, FinderResult
from bugbounty.finder.heuristics import heuristic_candidates
from bugbounty.recon.http import Recon, extract_api_paths, extract_from_html
from bugbounty.scope import Platform, Target
from bugbounty.signal.nuclei import parse_nuclei_jsonl
from bugbounty.signal.semgrep import parse_semgrep_json
from bugbounty.validator import VulnClass

HTML = """
<html><body>
  <a href="/#/search?q=1">search</a>
  <a href="https://other.com/x">off-host</a>
  <script src="/main.js"></script>
  <form><input name="email"><input name="password"></form>
</body></html>
"""


def _target() -> Target:
    return Target(
        name="t",
        platform=Platform.SELF,
        safe_harbor_url="https://x/sh",
        in_scope=["localhost"],
        dry_run=False,
    )


def test_extract_from_html():
    links, scripts, inputs = extract_from_html("http://localhost:3000/", HTML)
    assert "http://localhost:3000/main.js" in scripts
    assert "email" in inputs and "password" in inputs
    assert any("other.com" in x for x in links)


def test_extract_api_paths():
    text = 'fetch("/rest/user/login"); x="/api/Users/"; y="/nope"'
    assert extract_api_paths(text) == ["/api/Users/", "/rest/user/login"]


def test_parse_semgrep_json():
    data = {
        "results": [
            {
                "check_id": "r1",
                "path": "a.py",
                "start": {"line": 10},
                "extra": {"severity": "ERROR", "message": "bad"},
            }
        ]
    }
    sigs = parse_semgrep_json(data)
    assert sigs[0].kind == "r1" and sigs[0].location == "a.py:10" and sigs[0].severity == "ERROR"


def test_parse_nuclei_jsonl():
    text = '{"template-id":"t1","info":{"severity":"high","name":"X"},"matched-at":"http://h/a"}\nnot-json\n'
    sigs = parse_nuclei_jsonl(text)
    assert len(sigs) == 1 and sigs[0].kind == "t1" and sigs[0].severity == "high"


def test_compute_usd():
    assert compute_usd(1_000_000, 1_000_000, 3.0, 15.0) == 18.0
    assert compute_usd(0, 0) == 0.0


def test_heuristics_from_recon():
    rec = Recon(
        base_url="http://localhost:3000",
        endpoints=["http://localhost:3000/rest/user/login"],
        params=["q"],
    )
    cands = heuristic_candidates("t", "http://localhost:3000", rec, [])
    classes = {c.vuln_class for c in cands}
    assert VulnClass.INJECTION in classes and VulnClass.XSS in classes
    assert all(c.host == "localhost" for c in cands)
    # ids are stable across calls
    again = heuristic_candidates("t", "http://localhost:3000", rec, [])
    assert [c.id for c in cands] == [c.id for c in again]


def test_parse_candidates_json_filters_invalid():
    text = (
        'noise [{"title":"A","vuln_class":"xss","url":"http://localhost/"},'
        '{"vuln_class":"not-a-class","url":"x"}] trailing'
    )
    cands = parse_candidates_json(text, "t", "localhost")
    assert len(cands) == 1 and cands[0].vuln_class is VulnClass.XSS
    assert cands[0].target_name == "t" and cands[0].host == "localhost"


def test_finder_no_llm_uses_heuristics():
    rec = Recon(
        base_url="http://localhost:3000",
        endpoints=["http://localhost:3000/rest/user/login"],
        params=["q"],
    )
    res = Finder(Config(dry_run=False), reasoner=None).find(
        _target(), base_url="http://localhost:3000", use_llm=False, recon=rec
    )
    assert isinstance(res, FinderResult)
    assert res.cost_usd == 0.0 and len(res.candidates) >= 2
