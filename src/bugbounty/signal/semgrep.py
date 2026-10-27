"""Semgrep static-analysis signal (used mainly for own-code scanning)."""

from __future__ import annotations

import json
import shutil
import subprocess

from .base import Signal, SignalUnavailable


def parse_semgrep_json(data: dict) -> list[Signal]:
    out: list[Signal] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        line = r.get("start", {}).get("line", "?")
        out.append(
            Signal(
                source="semgrep",
                kind=r.get("check_id", "?"),
                severity=str(extra.get("severity", "INFO")),
                location=f"{r.get('path', '?')}:{line}",
                message=extra.get("message", ""),
            )
        )
    return out


def run_semgrep(code_path: str, config: str = "auto", timeout: int = 600) -> list[Signal]:
    if shutil.which("semgrep") is None:
        raise SignalUnavailable("semgrep not on PATH")
    proc = subprocess.run(
        ["semgrep", "scan", "--json", "--quiet", "--config", config, code_path],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SignalUnavailable(f"semgrep output was not JSON: {exc}") from exc
    return parse_semgrep_json(data)
