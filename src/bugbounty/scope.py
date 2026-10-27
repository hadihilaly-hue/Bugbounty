"""Allowlist / scope enforcement — the only thing that authorizes a target.

Load ``targets.yaml`` into validated models and answer, for any host, whether it
is in scope and why. Out-of-scope always wins over in-scope. A host that matches
nothing is out of scope by default (fail closed).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


class AiPolicy(StrEnum):
    ASSISTED_OK = "assisted_ok"
    DISCLOSURE_REQUIRED = "disclosure_required"
    AUTONOMOUS_BANNED = "autonomous_banned"
    UNKNOWN = "unknown"


class Platform(StrEnum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    VDP = "vdp"
    SELF = "self"


class TargetAuth(BaseModel):
    multi_account: bool = False
    creds_ref: str | None = None


class Target(BaseModel):
    name: str
    platform: Platform
    safe_harbor_url: str = Field(..., min_length=1)
    ai_policy: AiPolicy = AiPolicy.UNKNOWN
    pays_cash: bool = False
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    auth: TargetAuth = Field(default_factory=TargetAuth)
    notes: str | None = None
    dry_run: bool = True

    @field_validator("safe_harbor_url")
    @classmethod
    def _require_safe_harbor(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("safe_harbor_url is required for every target")
        return v


class ScopeDecision(BaseModel):
    host: str
    allowed: bool
    reason: str
    matched_pattern: str | None = None


def _host_matches(host: str, pattern: str) -> bool:
    return fnmatch.fnmatch(host.lower().strip(), pattern.lower().strip())


@dataclass
class Allowlist:
    targets: list[Target]

    def target_by_name(self, name: str) -> Target | None:
        for t in self.targets:
            if t.name == name:
                return t
        return None

    def decide(self, name: str, host: str) -> ScopeDecision:
        """Decide whether ``host`` may be touched for the named target."""
        target = self.target_by_name(name)
        if target is None:
            return ScopeDecision(
                host=host, allowed=False, reason=f"no target named {name!r} in allowlist"
            )
        for pattern in target.out_of_scope:
            if _host_matches(host, pattern):
                return ScopeDecision(
                    host=host,
                    allowed=False,
                    reason=f"host is explicitly out of scope (matched {pattern!r})",
                    matched_pattern=pattern,
                )
        for pattern in target.in_scope:
            if _host_matches(host, pattern):
                return ScopeDecision(
                    host=host,
                    allowed=True,
                    reason=f"host is in scope (matched {pattern!r})",
                    matched_pattern=pattern,
                )
        return ScopeDecision(
            host=host,
            allowed=False,
            reason="host matched no in-scope entry (fail closed)",
        )


def load_allowlist(path: str | Path) -> Allowlist:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"allowlist not found: {path}")
    data = yaml.safe_load(path.read_text()) or {}
    raw_targets = data.get("targets") or []
    targets = [Target.model_validate(t) for t in raw_targets]
    names = [t.name for t in targets]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ValueError(f"duplicate target names in allowlist: {sorted(dupes)}")
    return Allowlist(targets=targets)
