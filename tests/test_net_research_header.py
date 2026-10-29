"""The research attribution header must ride on every outbound request.

When a researcher handle is configured (BB_H1_USERNAME), every request that
leaves through the shared paced client -- recon, session logins, proof replays --
carries ``X-HackerOne-Research: <handle>`` so the program can attribute all
harness traffic. With no handle set (local sandboxes) no header is added.
"""

from __future__ import annotations

import httpx

from bugbounty.config import Config
from bugbounty.net.pacing import build_client


def _record(seen: list[dict[str, str]]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.headers))
        return httpx.Response(200, text="ok")

    return httpx.MockTransport(handler)


def test_header_on_every_request_when_handle_configured(monkeypatch):
    monkeypatch.setenv("BB_H1_USERNAME", "research_handle")
    cfg = Config()
    assert cfg.research_attribution() == ("X-HackerOne-Research", "research_handle")
    seen: list[dict[str, str]] = []
    client = build_client(cfg, inner=_record(seen))
    client.get("https://console.nebius.com/")
    client.post("https://console.nebius.com/api/x", json={"a": 1})
    assert [h.get("x-hackerone-research") for h in seen] == [
        "research_handle",
        "research_handle",
    ]


def test_header_value_survives_user_supplied_headers(monkeypatch):
    monkeypatch.setenv("BB_H1_USERNAME", "research_handle")
    seen: list[dict[str, str]] = []
    client = build_client(Config(), inner=_record(seen))
    client.get("https://console.nebius.com/", headers={"X-HackerOne-Research": "spoofed"})
    assert seen[0]["x-hackerone-research"] == "research_handle"


def test_header_name_is_overridable(monkeypatch):
    monkeypatch.setenv("BB_H1_USERNAME", "research_handle")
    monkeypatch.setenv("BB_RESEARCH_HEADER", "X-Custom-Research")
    seen: list[dict[str, str]] = []
    client = build_client(Config(), inner=_record(seen))
    client.get("https://console.nebius.com/")
    assert seen[0].get("x-custom-research") == "research_handle"


def test_no_header_without_a_handle(monkeypatch):
    monkeypatch.delenv("BB_H1_USERNAME", raising=False)
    assert Config().research_attribution() is None
    seen: list[dict[str, str]] = []
    client = build_client(Config(), inner=_record(seen))
    client.get("http://localhost:3000/")
    assert "x-hackerone-research" not in seen[0]
