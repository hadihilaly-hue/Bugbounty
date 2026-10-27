from bugbounty.config import Config


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
