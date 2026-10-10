"""Configuration and settings tests."""

import pytest

from gryphos.config import ConfigError, Settings, get_settings


def test_default_scope_preserved(monkeypatch):
    monkeypatch.delenv("GRYPHOS_ALLOWED_TARGETS", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
    s = get_settings()
    assert s.allowed_targets == ("127.0.0.1/32",)


def test_missing_api_key_not_configured(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    s = get_settings()
    assert not s.api_key_configured
    with pytest.raises(ConfigError):
        s.require_api_key()


def test_placeholder_key_not_configured(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "replace_me")
    s = get_settings()
    assert not s.api_key_configured


def test_invalid_numeric_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("GRYPHOS_COMMAND_TIMEOUT", "not-a-number")
    s = get_settings()
    assert s.command_timeout == 45


def test_numeric_clamped_to_bounds(monkeypatch):
    monkeypatch.setenv("GRYPHOS_MAX_AGENT_STEPS", "9999")
    s = get_settings()
    assert s.max_agent_steps == 20
    monkeypatch.setenv("GRYPHOS_MAX_AGENT_STEPS", "0")
    s = get_settings()
    assert s.max_agent_steps == 1


def test_safe_summary_never_contains_key():
    s = Settings(api_key="sk-or-v1-supersecretvalue", default_model="m",
                 allowed_targets=("127.0.0.1/32",), command_timeout=45,
                 max_output_chars=1000, max_agent_steps=6)
    summary = str(s.safe_summary())
    assert "supersecretvalue" not in summary
    assert "sk-or-v1" not in summary
    assert "set (redacted)" in summary


def test_custom_base_and_timeouts(monkeypatch):
    monkeypatch.setenv("GRYPHOS_API_BASE", "https://example.invalid/api/v1")
    monkeypatch.setenv("GRYPHOS_TIME_BUDGET_SECONDS", "120")
    s = get_settings()
    assert s.api_base == "https://example.invalid/api/v1"
    assert s.time_budget_seconds == 120
