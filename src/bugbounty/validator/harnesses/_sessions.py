"""Shared helper: build a pinned, authenticated session for a proof harness.

The harnesses used to open their own httpx clients and attempt their own logins,
so post-auth testing only worked where a plain form/token login did. This wires
them to the networking layer's :class:`SessionManager`, which already holds a
real session, **surfaces (never fakes) MFA**, and -- critically -- pins the
session's cookie/bearer to its own origin (the #11 fix). A session can be
*handed in* (live cookies/bearer/localStorage captured from a real browser,
supplied via the gitignored per-target secrets) so OAuth/SSO/MFA/anti-bot
targets can still be tested post-auth.

Kept thin and injectable (``client``/``transport``) so harness auth paths stay
deterministically testable without a network.
"""

from __future__ import annotations

from typing import Any

import httpx

from ...config import Config
from ...net import AuthError, Credentials, MfaRequired, SessionInvalid, SessionManager
from ...scope import Target
from ..base import HarnessUnavailable


def origin_base(url: str) -> str:
    """The scheme://host[:port] origin of ``url`` (used to pin a session)."""
    u = httpx.URL(url)
    netloc = u.host or ""
    if u.port:
        netloc = f"{netloc}:{u.port}"
    return f"{u.scheme}://{netloc}" if netloc else ""


def has_session_config(target: Target) -> bool:
    """True when the target carries creds/auth from which a session can be built."""
    auth = target.auth
    return bool(auth.creds_ref or auth.login)


def build_account_session(
    target: Target,
    config: Config,
    label: str | None = None,
    *,
    base_url: str = "",
    client: httpx.Client | None = None,
    transport: Any | None = None,
    headers: dict[str, str] | None = None,
) -> SessionManager:
    """Authenticate one account and return its pinned :class:`SessionManager`.

    ``label`` selects the account from the secrets file (first account if None).
    A handed-in (manual) account is used as-is; otherwise the target's login spec
    runs. Every failure mode -- missing creds, unknown account, MFA, bad login,
    expired handed-in session -- is raised as :class:`HarnessUnavailable` with a
    message the engine surfaces, so we never silently run unauthenticated.
    """
    if not target.auth.creds_ref:
        raise HarnessUnavailable("authenticated proof needs target.auth.creds_ref (secrets file)")
    try:
        creds = Credentials.load(target.auth.creds_ref)
    except FileNotFoundError as exc:
        raise HarnessUnavailable(f"creds file not found: {target.auth.creds_ref}") from exc
    if not creds.accounts:
        raise HarnessUnavailable(f"no accounts in {target.auth.creds_ref}")

    account = creds.by_label(label) if label else creds.accounts[0]
    if account is None:
        have = ", ".join(a.label for a in creds.accounts)
        raise HarnessUnavailable(f"account {label!r} not in secrets (have: {have})")

    if client is None and transport is not None:
        client = httpx.Client(transport=transport, base_url=base_url, follow_redirects=False)

    sm = SessionManager.from_auth(
        target.auth, config=config, base_url=base_url, client=client, headers=headers
    )
    try:
        sm.authenticate(account)
    except MfaRequired as exc:
        raise HarnessUnavailable(f"MFA required for {account.label!r}: {exc}") from exc
    except (AuthError, SessionInvalid) as exc:
        raise HarnessUnavailable(f"could not authenticate {account.label!r}: {exc}") from exc
    return sm
