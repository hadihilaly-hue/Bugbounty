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


# Registry rulesets used for own-code scanning (work offline once cached).
DEFAULT_RULESETS = ("p/python", "p/security-audit", "p/javascript")


def run_semgrep(
    code_path: str, config: str | list[str] = "auto", timeout: int = 600
) -> list[Signal]:
    if shutil.which("semgrep") is None:
        raise SignalUnavailable("semgrep not on PATH")
    configs = [config] if isinstance(config, str) else list(config)
    cmd = ["semgrep", "scan", "--json", "--quiet"]
    for cfg in configs:
        cmd += ["--config", cfg]
    cmd.append(code_path)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SignalUnavailable(f"semgrep output was not JSON: {exc}") from exc
    return parse_semgrep_json(data)
