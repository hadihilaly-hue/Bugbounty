"""Nuclei dynamic-signal wrapper (templated web checks)."""

from __future__ import annotations

import json
import shutil
import subprocess

from .base import Signal, SignalUnavailable


def parse_nuclei_jsonl(text: str) -> list[Signal]:
    out: list[Signal] = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {})
        out.append(
            Signal(
                source="nuclei",
                kind=d.get("template-id", "?"),
                severity=str(info.get("severity", "info")),
                location=d.get("matched-at", d.get("host", "?")),
                message=info.get("name", ""),
            )
        )
    return out


def run_nuclei(url: str, timeout: int = 600, extra_args: list[str] | None = None) -> list[Signal]:
    if shutil.which("nuclei") is None:
        raise SignalUnavailable("nuclei not on PATH")
    cmd = ["nuclei", "-u", url, "-jsonl", "-silent", "-disable-update-check", *(extra_args or [])]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return parse_nuclei_jsonl(proc.stdout or "")
