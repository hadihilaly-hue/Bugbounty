"""Juice Shop adapter: wraps the expanded 18-case evaluation."""

from __future__ import annotations

from ...config import Config
from ..juiceshop_eval import run_eval
from .base import EvalResult, EvalTarget


class JuiceShopTarget(EvalTarget):
    name = "juiceshop"
    base_url = "http://localhost:3000"

    def docker_setup(self) -> str:
        return "docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop"

    def run(self, config: Config | None = None) -> EvalResult:
        if not self.available():
            return EvalResult(self.name, False, note="sandbox not reachable; run docker setup")
        # Local sandbox: clear the dry-run gate so proofs execute (global DRY_RUN
        # stays on; this Config is scoped to the local eval only).
        config = config or Config(dry_run=False)
        m, m_sup, rows = run_eval(self.base_url, config)
        return EvalResult(self.name, True, m, m_sup, rows)
