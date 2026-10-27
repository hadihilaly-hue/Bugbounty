"""Local review dashboard (FastAPI).

Confirmed findings first, each with its executed proof, evidence, and validator
reasoning, plus one-click review actions. Reads the orchestrator's SQLite store;
nothing leaves the machine.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse

from ..orchestrator.store import Store

_ALLOWED_DECISIONS = {"accept", "dismiss", "needs_info"}
_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

_CSS = """
body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111;max-width:60rem}
h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:1.5rem}
table{border-collapse:collapse;width:100%} td,th{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}
.badge{padding:.1rem .5rem;border-radius:.4rem;color:#fff;font-size:.8rem}
.confirmed{background:#1a7f37}.rejected{background:#b35900}.unconfirmed{background:#9a6700}
pre{background:#f6f8fa;padding:.75rem;border-radius:.4rem;overflow:auto;white-space:pre-wrap}
a{color:#0969da;text-decoration:none} .flag{color:#9a6700;font-weight:600}
button{margin-right:.5rem;padding:.35rem .7rem}
img{margin-top:.5rem}
"""


def _is_image(path: str) -> bool:
    return any(path.lower().endswith(ext) for ext in _IMAGE_EXTS)


def _badge(status: str) -> str:
    cls = status if status in ("confirmed", "rejected", "unconfirmed") else "unconfirmed"
    return f'<span class="badge {cls}">{html.escape(status.upper())}</span>'


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>"
        + html.escape(title)
        + "</title><style>"
        + _CSS
        + "</style></head><body>"
        + body
        + "</body></html>"
    )


def create_app(db_path: str = "runs/bugbounty.db") -> FastAPI:
    app = FastAPI(title="bugbounty review")
    store = Store(db_path)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        rows = store.list_validations()
        reviews = store.reviews_map()
        counts = store.status_counts()
        summary = (
            " · ".join(f"{_badge(k)} {v}" for k, v in sorted(counts.items())) or "no findings yet"
        )
        confirmed = [r for r in rows if r["status"] == "confirmed"]
        others = [r for r in rows if r["status"] != "confirmed"]

        def row_html(r) -> str:
            decision = reviews.get(r["candidate_id"], "")
            flag = (
                " <span class='flag'>⚠ needs a human</span>" if r["status"] == "unconfirmed" else ""
            )
            return (
                "<tr><td><a href='/finding/{id}'>{cid}</a>{flag}</td>"
                "<td>{vc}</td><td>{badge}</td><td>{tn}</td><td>{dec}</td></tr>"
            ).format(
                id=r["id"],
                cid=html.escape(r["candidate_id"]),
                flag=flag,
                vc=html.escape(r["vuln_class"]),
                badge=_badge(r["status"]),
                tn=html.escape(r["target_name"]),
                dec=html.escape(decision),
            )

        def table(title, rs) -> str:
            if not rs:
                return ""
            head = "<tr><th>candidate</th><th>class</th><th>status</th><th>target</th><th>review</th></tr>"
            return f"<h2>{html.escape(title)}</h2><table>{head}{''.join(row_html(r) for r in rs)}</table>"

        body = (
            "<h1>bugbounty review queue</h1><p>"
            + summary
            + "</p>"
            + table("Review queue (CONFIRMED)", confirmed)
            + table("Everything else", others)
        )
        return _page("bugbounty review", body)

    @app.get("/finding/{vid}", response_class=HTMLResponse)
    def finding(vid: int) -> HTMLResponse:
        r = store.get_validation(vid)
        if r is None:
            return HTMLResponse(_page("not found", "<h1>404</h1>"), status_code=404)
        evidence = json.loads(r["evidence"] or "[]")
        ev_html = ""
        for e in evidence:
            inner = ""
            path = e.get("path")
            if path:
                inner += f"<div>artifact: <code>{html.escape(path)}</code></div>"
                if _is_image(path):
                    inner += (
                        f"<img src='/artifact?path={quote(path)}' "
                        "style='max-width:40rem;border:1px solid #ddd'>"
                    )
            if e.get("content"):
                inner += f"<pre>{html.escape(e['content'][:4000])}</pre>"
            ev_html += f"<h3>{html.escape(e.get('label', e.get('kind', 'evidence')))}</h3>{inner}"
        rev = store.review_detail(r["batch_id"], r["candidate_id"])
        decision = rev["decision"] if rev else "none"
        note = (rev["note"] if rev else "") or ""
        note_html = f"<div>note: {html.escape(note)}</div>" if note else ""
        poc = html.escape(r["poc"] or "(none)")
        body = (
            f"<p><a href='/'>&larr; queue</a></p><h1>{html.escape(r['candidate_id'])} {_badge(r['status'])}</h1>"
            f"<p>class <b>{html.escape(r['vuln_class'])}</b> · target {html.escape(r['target_name'])} · "
            f"reproducible {'yes' if r['reproducible'] else 'no'} · review: <b>{html.escape(decision)}</b></p>"
            f"{note_html}"
            f"<h2>validator reasoning</h2><pre>{html.escape(r['reason'] or '')}</pre>"
            f"<h2>proof of concept</h2><pre>{poc}</pre>"
            f"<h2>evidence</h2>{ev_html or '<p>(none)</p>'}"
            "<h2>review</h2><textarea id='note' rows='2' cols='60' placeholder='note'></textarea><br>"
            "<button onclick=\"rev('accept')\">Accept</button>"
            "<button onclick=\"rev('dismiss')\">Dismiss</button>"
            "<button onclick=\"rev('needs_info')\">Needs info</button>"
            '<button onclick="copyReport()">Copy report</button>'
            f" · <a href='/finding/{vid}/report'>raw report</a>"
            "<script>"
            "function rev(d){fetch(location.pathname+'/review?decision='+d+'&note='+"
            "encodeURIComponent(document.getElementById('note').value),{method:'POST'}).then(()=>location.reload())}"
            "function copyReport(){fetch(location.pathname+'/report').then(r=>r.text())"
            ".then(t=>navigator.clipboard.writeText(t)).then(()=>alert('report copied to clipboard'))}"
            "</script>"
        )
        return HTMLResponse(_page(r["candidate_id"], body))

    @app.get("/artifact")
    def artifact(path: str):
        base = Path("runs").resolve()
        rp = Path(path).resolve()
        try:
            rp.relative_to(base)
        except ValueError:
            return PlainTextResponse("forbidden", status_code=403)
        if not rp.is_file():
            return PlainTextResponse("not found", status_code=404)
        return FileResponse(str(rp))

    @app.post("/finding/{vid}/review")
    def review(vid: int, decision: str = Query(...), note: str | None = Query(None)):
        if decision not in _ALLOWED_DECISIONS:
            return PlainTextResponse(f"invalid decision {decision!r}", status_code=400)
        r = store.get_validation(vid)
        if r is None:
            return PlainTextResponse("not found", status_code=404)
        store.record_review(r["batch_id"], r["candidate_id"], decision, note)
        return RedirectResponse(f"/finding/{vid}", status_code=303)

    @app.get("/finding/{vid}/report", response_class=PlainTextResponse)
    def report(vid: int) -> PlainTextResponse:
        r = store.get_validation(vid)
        if r is None:
            return PlainTextResponse("not found", status_code=404)
        text = (
            f"# {r['candidate_id']} ({r['vuln_class']})\n\n"
            f"Status: {r['status']}\nTarget: {r['target_name']}\n"
            f"Reproducible: {'yes' if r['reproducible'] else 'no'}\n\n"
            f"## Validator reasoning\n{r['reason'] or ''}\n\n"
            f"## Proof of concept\n{r['poc'] or '(none)'}\n"
        )
        return PlainTextResponse(text)

    return app
