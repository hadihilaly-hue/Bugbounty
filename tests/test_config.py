import pytest

from bugbounty.config import Config, load_config


def test_dry_run_default_true():
    assert Config().dry_run is True


def test_active_payloads_gated():
    # Global dry-run on -> never allowed.
    assert Config(dry_run=True).active_payloads_allowed(target_dry_run=False) is False
    # Global off but target still dry -> blocked.
    assert Config(dry_run=False).active_payloads_allowed(target_dry_run=True) is False
    # Both cleared -> allowed.
    assert Config(dry_run=False).active_payloads_allowed(target_dry_run=False) is True
    # Kill switch overrides everything.
    assert (
        Config(dry_run=False, kill_switch=True).active_payloads_allowed(target_dry_run=False)
        is False
    )


def test_blank_dry_run_keeps_safe_default(monkeypatch):
    """A blank DRY_RUN must not read as False and enable live payloads."""
    monkeypatch.setenv("DRY_RUN", "")
    assert load_config().dry_run is True


def test_unparseable_dry_run_raises_instead_of_failing_open(monkeypatch):
    """A typo'd DRY_RUN must fail loudly, never silently disable dry-run."""
    monkeypatch.setenv("DRY_RUN", "flase")
    with pytest.raises(ValueError):
        load_config()


def test_budget_caps_read_env_at_instantiation(monkeypatch):
    """Caps must not be frozen at import time -- the spend cap is safety-critical."""
    monkeypatch.setenv("BB_MAX_USD", "111")
    monkeypatch.setenv("BB_MAX_REQUESTS", "7")
    cfg = load_config()
    assert cfg.budget.max_usd == 111.0
    assert cfg.budget.max_requests == 7
