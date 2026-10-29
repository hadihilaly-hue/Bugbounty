"""Finder model config + a key-gated live sanity call.

The finder's model name is a config value (env BB_ANTHROPIC_MODEL) with a current
default, so it can't silently rot to a retired model again. The live test is
skipped unless ANTHROPIC_API_KEY is present; when it is, it proves the finder can
make one real call on the configured model and account for its token spend.
"""

from __future__ import annotations

import os

import pytest

from bugbounty.finder.anthropic_client import DEFAULT_MODEL, AnthropicReasoner


def test_model_is_configurable_with_a_current_default():
    assert DEFAULT_MODEL == "claude-sonnet-5-5"  # current, not a retired model
    assert AnthropicReasoner().model == "claude-sonnet-5-5"
    assert AnthropicReasoner(model="some-other-model").model == "some-other-model"


def test_max_tokens_is_env_overridable(monkeypatch):
    assert AnthropicReasoner().max_tokens == 4096
    monkeypatch.setenv("BB_ANTHROPIC_MAX_TOKENS", "256")
    assert AnthropicReasoner().max_tokens == 256
    assert AnthropicReasoner(max_tokens=32).max_tokens == 32  # explicit wins


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="no ANTHROPIC_API_KEY; live finder call skipped",
)
def test_finder_makes_one_successful_live_call():
    reasoner = AnthropicReasoner(max_tokens=16)
    assert reasoner.available()
    out = reasoner.complete(
        system="You are a terse test endpoint.",
        user="Reply with the single word: pong",
    )
    assert out.text.strip(), "live call returned no text"
    assert out.input_tokens > 0 and out.output_tokens > 0
    assert out.usd >= 0.0
