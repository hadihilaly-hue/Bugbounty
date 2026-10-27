"""OWASP Benchmark adapter: labelled true/false-positive answer key.

OWASP BenchmarkJava ships expectedresults-1.2.csv: ~2740 test cases labelled
true (real vulnerability) or false (safe) across 11 CWE categories -- a ready-made
answer key for a real false-positive-rate measurement. The Benchmark is a
Java/Maven/Tomcat WAR with no Dockerfile; standing it up and generating faithful
per-test attack traffic needs Maven + the Benchmark crawler, so a live graded
DAST run is NOT performed by this harness. The answer key + setup are wired so it
can be graded once the app is built.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ...config import Config
from .base import EvalResult, EvalTarget

_CSV_CANDIDATES = (
    "/home/ubuntu/sandboxes/BenchmarkJava/expectedresults-1.2.csv",
    "sandboxes/BenchmarkJava/expectedresults-1.2.csv",
)


class OwaspBenchmarkTarget(EvalTarget):
    name = "owasp-benchmark"
    base_url = "https://localhost:8443/benchmark/"

    def docker_setup(self) -> str:
        return (
            "git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava"
            " /tmp/BenchmarkJava\n"
            "cd /tmp/BenchmarkJava && ./runBenchmark.sh   # needs Maven + JDK; builds WAR, "
            "runs Tomcat on :8443\n"
            "# grade with the Benchmark crawler (runCrawler.sh) to generate per-test attack traffic"
        )

    def answer_key(self) -> dict:
        path = next((p for p in _CSV_CANDIDATES if Path(p).exists()), None)
        if not path:
            return {}
        counts: dict = {"total": 0, "true": 0, "false": 0, "by_category": {}}
        with open(path) as f:
            for row in csv.reader(f):
                if not row or not row[0].startswith("BenchmarkTest"):
                    continue
                cat, real = row[1], row[2].strip().lower() == "true"
                counts["total"] += 1
                counts["true" if real else "false"] += 1
                bucket = counts["by_category"].setdefault(cat, {"true": 0, "false": 0})
                bucket["true" if real else "false"] += 1
        return counts

    def run(self, config: Config | None = None) -> EvalResult:
        key = self.answer_key()
        if not key:
            return EvalResult(
                self.name,
                False,
                note="answer key expectedresults-1.2.csv not found; run docker_setup to clone",
            )
        note = (
            f"answer key loaded: {key['total']} cases "
            f"({key['true']} true / {key['false']} false, {len(key['by_category'])} categories). "
            "Live graded run needs a Maven+Tomcat build and the Benchmark crawler; not stood up "
            "in this environment."
        )
        return EvalResult(self.name, False, note=note)
