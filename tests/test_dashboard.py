"""Dashboard tests via FastAPI TestClient against a tmp SQLite store."""

from fastapi.testclient import TestClient

from bugbounty.dashboard import create_app
from bugbounty.orchestrator.store import Store
from bugbounty.validator import VulnClass
from bugbounty.validator.models import Evidence, ValidationResult, ValidationStatus


def _seed(db) -> Store:
    st = Store(db)
    st.record_validation(
        "b",
        "r",
        "t",
        ValidationResult(
            candidate_id="good",
            vuln_class=VulnClass.INJECTION,
            status=ValidationStatus.CONFIRMED,
            reason="oracle matched",
            reproducible=True,
            poc="curl ...",
            evidence=[Evidence(kind="http", label="req", content="HTTP/1.1 200")],
        ),
    )
    st.record_validation(
        "b",
        "r",
        "t",
        ValidationResult(
            candidate_id="bad",
            vuln_class=VulnClass.XSS,
            status=ValidationStatus.REJECTED,
            reason="no exec",
        ),
    )
    st.record_validation(
        "b",
        "r",
        "t",
        ValidationResult(
            candidate_id="maybe",
            vuln_class=VulnClass.SSRF,
            status=ValidationStatus.UNCONFIRMED,
            reason="target down",
        ),
    )
    return st


def test_queue_lists_confirmed_first(tmp_path):
    _seed(tmp_path / "d.db")
    c = TestClient(create_app(str(tmp_path / "d.db")))
    r = c.get("/")
    assert r.status_code == 200
    body = r.text
    assert "Review queue (CONFIRMED)" in body and "good" in body
    assert body.index(">good<") < body.index(">bad<")  # confirmed above rejected
    assert "needs a human" in body  # unconfirmed flagged


def test_detail_shows_poc_and_report(tmp_path):
    st = _seed(tmp_path / "d.db")
    vid = st.list_validations(["confirmed"])[0]["id"]
    c = TestClient(create_app(str(tmp_path / "d.db")))
    d = c.get(f"/finding/{vid}")
    assert d.status_code == 200 and "curl ..." in d.text and "oracle matched" in d.text
    rep = c.get(f"/finding/{vid}/report")
    assert "Proof of concept" in rep.text


def test_review_persists(tmp_path):
    st = _seed(tmp_path / "d.db")
    vid = st.list_validations(["confirmed"])[0]["id"]
    c = TestClient(create_app(str(tmp_path / "d.db")))
    r = c.post(
        f"/finding/{vid}/review",
        params={"decision": "accept", "note": "ship it"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert st.reviews_map("b")["good"] == "accept"


def test_missing_finding_404(tmp_path):
    _seed(tmp_path / "d.db")
    c = TestClient(create_app(str(tmp_path / "d.db")))
    assert c.get("/finding/9999").status_code == 404


def test_invalid_decision_rejected(tmp_path):
    st = _seed(tmp_path / "d.db")
    vid = st.list_validations(["confirmed"])[0]["id"]
    c = TestClient(create_app(str(tmp_path / "d.db")))
    r = c.post(f"/finding/{vid}/review", params={"decision": "weird_e2e"})
    assert r.status_code == 400
    assert "good" not in st.reviews_map("b")


def test_note_is_displayed(tmp_path):
    st = _seed(tmp_path / "d.db")
    vid = st.list_validations(["confirmed"])[0]["id"]
    c = TestClient(create_app(str(tmp_path / "d.db")))
    c.post(f"/finding/{vid}/review", params={"decision": "accept", "note": "ship it e2e"})
    body = c.get(f"/finding/{vid}").text
    assert "ship it e2e" in body


def test_artifact_path_traversal_forbidden(tmp_path):
    _seed(tmp_path / "d.db")
    c = TestClient(create_app(str(tmp_path / "d.db")))
    assert c.get("/artifact", params={"path": "/etc/passwd"}).status_code == 403
