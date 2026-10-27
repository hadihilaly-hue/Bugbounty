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


class LoginSpec(BaseModel):
    """How to establish an authenticated session for a target.

    ``mode``: 'form' (cookie session, optional CSRF token), 'json' (token API),
    or 'manual' (use a handed-in cookie/bearer from secrets; no login request).
    Everything is optional so existing targets keep working.
    """

    mode: str = "form"
    url: str | None = None
    csrf_url: str | None = None  # page carrying the CSRF token (defaults to url)
    csrf_field: str | None = None  # hidden input name, e.g. "user_token"
    user_field: str = "username"
    pass_field: str = "password"
    extra_fields: dict[str, str] = Field(default_factory=dict)  # static fields, e.g. Login=Login
    token_json_path: str | None = None  # json mode: dotted path to the bearer token
    success_url: str | None = None  # page to confirm auth succeeded
    success_marker: str | None = None  # string that must be present when authed
    expiry_status: int = 401  # status that means the session expired -> re-auth
    expiry_marker: str | None = None  # body string that means expired (e.g. a login form)
    mfa_marker: str | None = None  # body string that means MFA is required
    mfa_status: int | None = None  # status that means MFA is required


class TargetAuth(BaseModel):
    multi_account: bool = False
    creds_ref: str | None = None
    login: LoginSpec | None = None
    mfa_required: bool = False  # declared; the session manager surfaces, never fakes, MFA


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
