"""Lightweight HTTP recon: discover endpoints, params, and JS bundles.

Deterministic and cheap (no LLM). Fetches the base page, extracts links /
scripts / form inputs, then scans same-host JS bundles for ``/api`` and ``/rest``
paths and parameter names. Everything here is advisory input for the finder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

_API_PATH_RE = re.compile(r"/(?:api|rest)/[A-Za-z0-9_\-/]+")
_PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_]+)=")


@dataclass
class Recon:
    base_url: str
    endpoints: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    js_bundles: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inputs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "script" and d.get("src"):
            self.scripts.append(d["src"])
        elif tag in ("input", "textarea", "select") and d.get("name"):
            self.inputs.append(d["name"])


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).hostname == urlparse(b).hostname


def extract_from_html(base_url: str, html: str) -> tuple[list[str], list[str], list[str]]:
    p = _Extractor()
    p.feed(html)
    links = [urljoin(base_url, h) for h in p.links]
    scripts = [urljoin(base_url, s) for s in p.scripts]
    return links, scripts, p.inputs


def extract_api_paths(text: str) -> list[str]:
    return sorted({m.group(0) for m in _API_PATH_RE.finditer(text)})


_MAX_REDIRECTS = 5


def _origin(url: str) -> tuple[str, str, int]:
    u = httpx.URL(url)
    return (u.scheme, u.host or "", u.port or (443 if u.scheme == "https" else 80))


def _get_same_origin(client, url: str, rec: Recon):
    """GET *url*, following redirects only while they stay on its own origin.

    Fail closed: an in-scope page that redirects off-host must not make recon
    contact a host outside the authorized target, so we stop and record it
    instead of following.
    """
    origin = _origin(url)
    current = url
    resp = None
    for _ in range(_MAX_REDIRECTS):
        resp = client.get(current)
        if not resp.is_redirect:
            return resp
        location = resp.headers.get("location")
        if not location:
            return resp
        nxt = str(httpx.URL(current).join(location))
        if _origin(nxt) != origin:
            rec.notes.append(f"stopped at off-origin redirect: {current} -> {nxt}")
            return resp
        current = nxt
    rec.notes.append(f"too many redirects from {url}")
    return resp


def recon_http(base_url: str, timeout: float = 15.0, max_js: int = 10, config=None) -> Recon:
    # Paced per host so recon (which runs even in DRY_RUN) never hammers a target.
    from ..net import build_client

    rec = Recon(base_url=base_url)
    # follow_redirects=False: redirects are vetted per hop against the origin.
    with build_client(config, timeout=timeout, follow_redirects=False) as client:
        try:
            resp = _get_same_origin(client, base_url, rec)
        except Exception as exc:  # noqa: BLE001 - recon failure is non-fatal
            rec.notes.append(f"base fetch failed: {exc}")
            return rec
        links, scripts, inputs = extract_from_html(base_url, resp.text)
        rec.params.extend(inputs)
        same_host_scripts = [s for s in scripts if _same_host(base_url, s)]
        rec.js_bundles = (same_host_scripts or scripts)[:max_js]
        rec.endpoints.extend(sorted({x for x in links if _same_host(base_url, x)}))
        for link in links:
            rec.params.extend(m.group(1) for m in _PARAM_RE.finditer(link))
        api: set[str] = set()
        for js in rec.js_bundles:
            try:
                api.update(
                    urljoin(base_url, p)
                    for p in extract_api_paths(_get_same_origin(client, js, rec).text)
                )
            except Exception:  # noqa: BLE001 - skip a bad bundle
                continue
        rec.endpoints.extend(sorted(api))
    rec.endpoints = sorted(set(rec.endpoints))
    rec.params = sorted(set(rec.params))
    return rec
