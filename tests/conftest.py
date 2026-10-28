"""Shared pytest fixtures.

``browser_ready`` resolves a launchable Chromium for the ``browser``-marked
integration tests (the bundled one, a ``BB_CHROMIUM_EXECUTABLE`` override, or
the environment's provisioned build) and skips cleanly when none can launch --
so these tests run wherever a browser exists and are a no-op in a browserless CI.
"""

from __future__ import annotations

import os

import pytest

_PROVISIONED = [
    "/opt/pw-browsers/chromium",
    "/opt/pw-browsers/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell",
]
_SKIP = object()


def _resolve_browser():
    """A working executable path, None if the default launch works, or _SKIP."""
    from playwright.sync_api import sync_playwright

    tried: list = []
    for exe in [os.environ.get("BB_CHROMIUM_EXECUTABLE"), None, *_PROVISIONED]:
        if exe in tried:
            continue
        tried.append(exe)
        try:
            with sync_playwright() as p:
                kw: dict = {"headless": True}
                if exe:
                    kw["executable_path"] = exe
                browser = p.chromium.launch(**kw)
                browser.close()
            return exe
        except Exception:
            continue
    return _SKIP


@pytest.fixture(scope="session")
def browser_ready():
    resolved = _resolve_browser()
    if resolved is _SKIP:
        pytest.skip("no launchable Chromium in this environment")
    if isinstance(resolved, str):
        os.environ["BB_CHROMIUM_EXECUTABLE"] = resolved
    yield
