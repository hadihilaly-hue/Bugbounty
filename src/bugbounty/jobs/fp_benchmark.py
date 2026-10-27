"""Validator false-positive benchmark: known-vulnerable vs known-patched fixtures.

Spins a local fixture HTTP server exposing vulnerable AND patched variants of the
same endpoints, runs the validator against candidates for both, and reports
precision / recall / false-positive rate. The patched variants are the point:
they must be REJECTED, so fp_rate measures the validator's false alarms on code
that is NOT actually vulnerable.
"""

from __future__ import annotations

import html
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..config import Config
from ..scope import Platform, Target
from ..validator import Candidate, VulnClass
from ..validator.benchmark import Metrics
from ..validator.engine import Validator
from ..validator.models import ValidationStatus

_TARGET_NAME = "FP fixtures (local sandbox)"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # silence
        return

    def _send(self, code: int, body: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:
        u = urlparse(self.path)
        q = parse_qs(u.query).get("q", [""])[0]
        if u.path == "/vuln/search":
            self._send(200, f"results for {q}")
        elif u.path == "/safe/search":
            self._send(200, f"results for {html.escape(q)}")
        elif u.path == "/vuln/item":
            self._send(500, "You have an error in your SQL syntax near '1''")
        elif u.path == "/safe/item":
            self._send(404, "not found")
        else:
            self._send(404, "nope")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if self.path == "/vuln/login":
            self._send(200, json.dumps({"authentication": {"token": "t"}}))
        elif self.path == "/safe/login":
            self._send(401, json.dumps({"error": "invalid credentials"}))
        else:
            self._send(404, "nope")


@contextmanager
def _fixture_server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


def _fixture_target() -> Target:
    return Target(
        name=_TARGET_NAME,
        platform=Platform.SELF,
        safe_harbor_url="https://example.invalid/safe-harbor",
        in_scope=["127.0.0.1", "localhost"],
        dry_run=False,
    )


def _candidate(cid: str, method: str, url: str, oracle_value: str, body=None) -> Candidate:
    req: dict = {"method": method, "url": url}
    if body is not None:
        req["body"] = body
    return Candidate(
        id=cid,
        target_name=_TARGET_NAME,
        vuln_class=VulnClass.INJECTION,
        title=cid,
        url=url,
        host="127.0.0.1",
        source="fp-benchmark",
        params={"requests": [req], "oracle": {"type": "contains", "value": oracle_value}},
    )


def _cases(base: str) -> list[tuple[Candidate, bool]]:
    inj = {"email": "' OR 1=1--", "password": "x"}
    return [
        (_candidate("fp-auth-vuln", "POST", f"{base}/vuln/login", "authentication", inj), True),
        (_candidate("fp-auth-safe", "POST", f"{base}/safe/login", "authentication", inj), False),
        (_candidate("fp-sqlerr-vuln", "GET", f"{base}/vuln/item?id=1'", "SQL syntax"), True),
        (_candidate("fp-sqlerr-safe", "GET", f"{base}/safe/item?id=1'", "SQL syntax"), False),
        (
            _candidate(
                "fp-reflect-vuln", "GET", f"{base}/vuln/search?q=<b>MARK</b>", "<b>MARK</b>"
            ),
            True,
        ),
        (
            _candidate(
                "fp-reflect-safe", "GET", f"{base}/safe/search?q=<b>MARK</b>", "<b>MARK</b>"
            ),
            False,
        ),
    ]


def run_fp_benchmark(config: Config | None = None) -> tuple[Metrics, list[tuple[str, bool, str]]]:
    """Run the benchmark against the local fixtures. Returns metrics + per-case rows.

    The fixtures are a local sandbox we own (127.0.0.1), so active payloads are
    allowed by default here.
    """
    config = config or Config(dry_run=False)
    target = _fixture_target()
    validator = Validator(config)
    metrics = Metrics()
    rows: list[tuple[str, bool, str]] = []
    with _fixture_server() as base:
        for candidate, vulnerable in _cases(base):
            result = validator.validate(candidate, target)
            confirmed = result.status is ValidationStatus.CONFIRMED
            if vulnerable and confirmed:
                metrics.tp += 1
            elif vulnerable and not confirmed:
                metrics.fn += 1
            elif not vulnerable and confirmed:
                metrics.fp += 1
            else:
                metrics.tn += 1
            rows.append((candidate.id, vulnerable, result.status.value))
    return metrics, rows
