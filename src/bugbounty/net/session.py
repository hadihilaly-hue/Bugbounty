"""Authenticated session handling for live-style targets.

Holds a real session across requests within a run: cookie capture/reuse (robust
to apps that set a cookie name more than once -- the last value wins), CSRF-token
extraction and inclusion, form or token-API login, re-authentication when the
session expires, a manual handed-in cookie/bearer path (for MFA or anti-bot
defeat), and MFA detection that pauses and surfaces rather than faking anything.

Credentials come from gitignored ``secrets/<target>.yaml`` referenced by the
target's auth block. Two accounts enable the IDOR two-account test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

from ..config import Config
from ..scope import LoginSpec, TargetAuth
from .pacing import PacingConfig, build_client


class AuthError(Exception):
    """Login failed (bad creds, missing CSRF token, unexpected response)."""


class MfaRequired(Exception):
    """The target needs MFA. We never fake it; the caller must hand in a live
    session cookie/bearer (secrets ``cookies``/``bearer_token``) or solve MFA
    out of band."""


class SessionInvalid(AuthError):
    """A handed-in session is expired/invalid. We surface this rather than
    silently running unauthenticated, and (for manual sessions) never re-auth."""


@dataclass
class Account:
    label: str
    username: str | None = None
    password: str | None = None
    bearer_token: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    # Browser storage to seed for SPA targets that read their token/session from
    # localStorage (e.g. Juice Shop's 'token'); carried into the XSS render only.
    local_storage: dict[str, str] = field(default_factory=dict)

    @property
    def is_manual(self) -> bool:
        """True when a live session was handed in (skip the login request)."""
        return bool(self.bearer_token or self.cookies or self.local_storage)


@dataclass
class Credentials:
    accounts: list[Account]

    def by_label(self, label: str) -> Account | None:
        return next((a for a in self.accounts if a.label == label), None)

    @classmethod
    def load(cls, path: str | Path) -> Credentials:
        data = yaml.safe_load(Path(path).read_text()) or {}
        accounts: list[Account] = []
        shared_cookies = _cookie_list_to_dict(data.get("cookies"))
        shared_bearer = data.get("bearer_token")
        shared_ls = dict(data.get("local_storage") or {})

        def _mk(label: str, raw: dict) -> Account:
            return Account(
                label=label,
                username=raw.get("username") or raw.get("email"),
                password=raw.get("password"),
                bearer_token=raw.get("bearer_token") or shared_bearer,
                cookies=_cookie_list_to_dict(raw.get("cookies")) or dict(shared_cookies),
                local_storage={str(k): str(v) for k, v in (raw.get("local_storage") or {}).items()}
                or dict(shared_ls),
            )

        if isinstance(data.get("accounts"), list):
            for i, raw in enumerate(data["accounts"]):
                accounts.append(_mk(str(raw.get("label") or f"account_{i}"), raw))
        else:
            # account_a / account_b dict form (used by the eval adapters)
            for label, raw in data.items():
                if isinstance(raw, dict):
                    accounts.append(_mk(label, raw))
        if not accounts and (shared_cookies or shared_bearer or shared_ls):
            accounts.append(
                Account(
                    label="account_0",
                    bearer_token=shared_bearer,
                    cookies=dict(shared_cookies),
                    local_storage=dict(shared_ls),
                )
            )
        return cls(accounts=accounts)


def _cookie_list_to_dict(raw) -> dict[str, str]:
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    out: dict[str, str] = {}
    if isinstance(raw, list):
        for c in raw:
            if isinstance(c, dict) and c.get("name") is not None:
                out[str(c["name"])] = str(c.get("value", ""))
    return out


def _last_set_cookies(resp: httpx.Response) -> dict[str, str]:
    """Collect Set-Cookie values, keeping the LAST value per name.

    Some apps (e.g. DVWA) set the same cookie name twice on one response as the
    session regenerates; httpx's jar then raises on lookup. Taking the last value
    is what a browser effectively does and keeps the session coherent.
    """
    out: dict[str, str] = {}
    for k, v in resp.headers.multi_items():
        if k.lower() == "set-cookie" and "=" in v:
            name, _, rest = v.partition("=")
            out[name.strip()] = rest.split(";", 1)[0].strip()
    return out


_CSRF_PATTERNS = (
    r"name=['\"]{f}['\"][^>]*value=['\"]([^'\"]*)['\"]",
    r"value=['\"]([^'\"]*)['\"][^>]*name=['\"]{f}['\"]",
)


def extract_csrf(html: str, field_name: str) -> str | None:
    for pat in _CSRF_PATTERNS:
        m = re.search(pat.format(f=re.escape(field_name)), html)
        if m:
            return m.group(1)
    return None


class SessionManager:
    """Establishes and holds one authenticated session for a target."""

    def __init__(
        self,
        login: LoginSpec | None = None,
        *,
        config: Config | None = None,
        base_url: str = "",
        client: httpx.Client | None = None,
        mfa_required: bool = False,
        headers: dict[str, str] | None = None,
        per_host_rps: float | None = None,
    ) -> None:
        self.login = login or LoginSpec()
        self.config = config or Config()
        self.base_url = base_url
        self._mfa_required = mfa_required
        self._pinned_origin: tuple[str, str, int] | None = None
        # follow_redirects=False so we can read Set-Cookie and spot login bounces.
        self.client = client or build_client(
            self.config,
            pacing=PacingConfig.from_config(self.config, per_host_rps=per_host_rps),
            base_url=base_url,
            follow_redirects=False,
            headers=headers,
        )
        self.cookies: dict[str, str] = {}
        self.bearer: str | None = None
        self._account: Account | None = None

    @classmethod
    def from_auth(cls, auth: TargetAuth, **kw) -> SessionManager:
        """Build from a target's auth block, carrying its MFA declaration."""
        return cls(auth.login, mfa_required=auth.mfa_required, **kw)

    # -- public API ---------------------------------------------------------
    def authenticate(self, account: Account) -> SessionManager:
        self._account = account
        self.cookies, self.bearer = {}, None
        if account.is_manual:
            # Handed-in live session (MFA / anti-bot path): use it as-is.
            self.cookies.update(account.cookies)
            self.bearer = account.bearer_token
            return self
        if self.login.mode == "manual":
            raise AuthError(
                f"login.mode is 'manual' but no live session was supplied for "
                f"{account.label!r}; put cookies/bearer_token in the target's secrets file"
            )
        if self._mfa_declared():
            # An explicit declaration is final: response-based detection (marker /
            # status) is for targets whose MFA requirement is unknown, and never
            # softens a declaration.
            raise MfaRequired(
                f"target declares MFA for {account.label!r}; hand in a live cookie/bearer "
                "in secrets (cookies/bearer_token) or solve MFA out of band"
            )
        if self.login.mode == "json":
            self._login_json(account)
        else:
            self._login_form(account)
        self._verify()
        return self

    def auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.cookies:
            headers["Cookie"] = self.cookie_header()
        if self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        return headers

    def headers_for(self, url: str) -> dict[str, str]:
        """Public: origin-pinned auth headers for ``url`` (see _auth_headers_for).

        The session's cookie/bearer is returned only when ``url`` is this
        session's own origin (scheme+host+port); any other host gets ``{}``.
        """
        return self._auth_headers_for(url)

    @property
    def is_manual(self) -> bool:
        """True when this session was handed in (no login request was made)."""
        return bool(self._account and self._account.is_manual)

    @property
    def local_storage(self) -> dict[str, str]:
        """localStorage to seed in a browser for this session (SPA token apps)."""
        return dict(self._account.local_storage) if self._account else {}

    def browser_cookies(self, url: str) -> list[dict]:
        """Playwright-style cookie dicts for ``url``, only if it is this session's
        pinned origin (so the browser never carries the session off-origin).

        Scoped by ``url`` (origin), which is robust for IPs/localhost where a
        bare ``domain`` is rejected; the browser keeps them on that origin."""
        req, own = self._origin(url), self._session_origin()
        if req is not None and own is not None and req != own:
            return []
        u = httpx.URL(url)
        base = f"{u.scheme}://{u.host}" + (f":{u.port}" if u.port else "")
        return [{"name": k, "value": v, "url": base} for k, v in self.cookies.items() if u.host]

    def check_live(self, probe_url: str, *, marker: str | None = None) -> httpx.Response:
        """Probe that a (typically handed-in) session is still valid.

        Raises :class:`SessionInvalid` on an expiry signal, a 401/403, or a
        missing success marker -- so an expired handed-in session is surfaced
        loudly instead of running unauthenticated and reporting nothing.
        """
        resp = self.request("GET", probe_url, _allow_reauth=False)
        bad = (
            self._expired(resp)
            or resp.status_code in (401, 403)
            or (marker is not None and marker not in resp.text)
        )
        if bad:
            raise SessionInvalid(
                f"session for {self._account.label if self._account else '?'!r} is "
                f"expired/invalid against {probe_url} (HTTP {resp.status_code}); "
                "hand in a fresh session"
            )
        return resp

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int] | None:
        """(scheme, host, port) for an absolute URL; None for a relative path."""
        u = httpx.URL(url)
        if not u.host:
            return None
        return (u.scheme, u.host, u.port or (443 if u.scheme == "https" else 80))

    def _session_origin(self) -> tuple[str, str, int] | None:
        for src in (self.base_url, self.login.url, self.login.success_url):
            if src:
                origin = self._origin(src)
                if origin:
                    return origin
        return self._pinned_origin

    def _auth_headers_for(self, url: str) -> dict[str, str]:
        """Only ever hand this session's cookie/bearer to its own origin.

        Scheme and port are part of the origin, so a different service on the
        same host (or a plain-HTTP downgrade) never sees the session. When no
        origin is configured (e.g. a handed-in cookie with no base_url) the first
        absolute URL used pins it, and everything else is refused.
        """
        req = self._origin(url)  # None => relative path, resolved against base_url
        if req is None:
            return self.auth_headers()
        own = self._session_origin()
        if own is None:
            self._pinned_origin = req
            return self.auth_headers()
        return {} if req != own else self.auth_headers()

    def request(
        self, method: str, url: str, *, _allow_reauth: bool = True, headers=None, **kw
    ) -> httpx.Response:
        merged = {**self._auth_headers_for(url), **(headers or {})}
        resp = self.client.request(method, url, headers=merged, **kw)
        self.cookies.update(_last_set_cookies(resp))
        if _allow_reauth and self._account and not self._account.is_manual and self._expired(resp):
            self.authenticate(self._account)  # re-auth without losing the run
            return self.request(method, url, _allow_reauth=False, headers=headers, **kw)
        return resp

    # -- internals ----------------------------------------------------------
    def _mfa_declared(self) -> bool:
        # Declared either on the target's auth block (via from_auth) or on the spec.
        return bool(self._mfa_required or self.login.mfa_required)

    def _login_form(self, account: Account) -> None:
        if not self.login.url:
            raise AuthError("form login requires login.url")
        token_val = None
        if self.login.csrf_field:
            page = self.client.get(self.login.csrf_url or self.login.url)
            self.cookies.update(_last_set_cookies(page))
            token_val = extract_csrf(page.text, self.login.csrf_field)
            if token_val is None:
                raise AuthError(f"CSRF field {self.login.csrf_field!r} not found on login page")
        data = {
            self.login.user_field: account.username or "",
            self.login.pass_field: account.password or "",
            **self.login.extra_fields,
        }
        if self.login.csrf_field and token_val is not None:
            data[self.login.csrf_field] = token_val
        resp = self.client.post(self.login.url, data=data, headers={"Cookie": self.cookie_header()})
        self.cookies.update(_last_set_cookies(resp))
        self._check_mfa(resp)

    def _login_json(self, account: Account) -> None:
        if not self.login.url:
            raise AuthError("json login requires login.url")
        resp = self.client.post(
            self.login.url,
            json={self.login.user_field: account.username, self.login.pass_field: account.password},
        )
        self._check_mfa(resp)
        if resp.status_code >= 400:
            raise AuthError(f"login failed ({resp.status_code})")
        token: object = resp.json()
        for key in (self.login.token_json_path or "token").split("."):
            if not isinstance(token, dict) or key not in token:
                raise AuthError(f"token path {self.login.token_json_path!r} not in login response")
            token = token[key]
        self.bearer = str(token)

    def _check_mfa(self, resp: httpx.Response) -> None:
        if self.login.mfa_status is not None and resp.status_code == self.login.mfa_status:
            raise MfaRequired("login returned the MFA status; hand in a live session instead")
        if self.login.mfa_marker and self.login.mfa_marker in resp.text:
            raise MfaRequired("login response asks for MFA; hand in a live session instead")

    def _verify(self) -> None:
        if not self.login.success_url:
            return
        resp = self.request("GET", self.login.success_url, _allow_reauth=False)
        self._check_mfa(resp)
        if self.login.success_marker and self.login.success_marker not in resp.text:
            raise AuthError("authentication could not be confirmed (success marker absent)")

    def _expired(self, resp: httpx.Response) -> bool:
        if resp.status_code == self.login.expiry_status:
            return True
        if self.login.expiry_marker and self.login.expiry_marker in resp.text:
            return True
        return False
