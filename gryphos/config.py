"""Configuration for Gryphos.

Reads environment variables and `.env` (without modifying them). All numeric
values are validated with safe bounds; invalid values fall back to defaults
with a warning rather than crashing. API keys are never printed by this module.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

log = logging.getLogger("gryphos.config")

DEFAULT_API_BASE = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "openrouter/free"
DEFAULT_SCOPE = "127.0.0.1/32"

# name -> (default, lower bound, upper bound)
_INT_SETTINGS: dict[str, tuple[int, int, int]] = {
    "GRYPHOS_COMMAND_TIMEOUT": (45, 5, 300),
    "GRYPHOS_MAX_OUTPUT_CHARS": (12000, 1000, 100000),
    "GRYPHOS_MAX_AGENT_STEPS": (6, 1, 20),
    "GRYPHOS_REQUEST_TIMEOUT": (60, 5, 300),
    "GRYPHOS_MAX_RETRIES": (1, 0, 5),
    "GRYPHOS_TIME_BUDGET_SECONDS": (600, 30, 3600),
    "GRYPHOS_MODEL_CACHE_TTL": (300, 0, 86400),
    "GRYPHOS_MAX_APPROVAL_LEVEL": (3, 0, 4),
    "GRYPHOS_CTF_MAX_STEPS": (20, 1, 100),
}


class ConfigError(ValueError):
    """Raised when required configuration is missing or unusable."""


def _int_env(name: str) -> int:
    default, lo, hi = _INT_SETTINGS[name]
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        log.warning("Ignoring invalid %s=%r; using default %s", name, raw, default)
        return default
    if value < lo or value > hi:
        clamped = max(lo, min(hi, value))
        log.warning("Clamping %s=%s to allowed range [%s, %s] -> %s", name, value, lo, hi, clamped)
        return clamped
    return value


def _bool_env(name: str, default: bool = False) -> bool:
    """Parse a truthy/falsey env flag; unset uses `default`, unknown is `default`."""
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    log.warning("Ignoring invalid %s=%r; treating as %s", name, raw, default)
    return default


@dataclass(frozen=True)
class Settings:
    api_key: str
    default_model: str
    allowed_targets: tuple[str, ...]
    command_timeout: int
    max_output_chars: int
    max_agent_steps: int
    api_base: str = DEFAULT_API_BASE
    request_timeout: int = 60
    max_retries: int = 1
    time_budget_seconds: int = 600
    model_cache_ttl: int = 300
    max_approval_level: int = 3
    reports_dir: Path = field(default_factory=lambda: Path("reports"))
    log_dir: Path = field(default_factory=lambda: Path("logs"))
    ctf_challenges_dir: Path = field(default_factory=lambda: Path("challenges"))
    ctf_max_steps: int = 20
    ctf_remote_verify: bool = False
    ctf_web_enabled: bool = True
    ctf_net_enabled: bool = True

    @property
    def api_key_configured(self) -> bool:
        return bool(self.api_key) and self.api_key != "replace_me"

    def require_api_key(self) -> str:
        if not self.api_key_configured:
            raise ConfigError(
                "OPENROUTER_API_KEY is not configured. Copy .env.example to .env "
                "and set your key from https://openrouter.ai/settings/keys."
            )
        return self.api_key

    def safe_summary(self) -> dict[str, object]:
        """Configuration summary safe for display and logging (no secret)."""
        key_note = "set (redacted)" if self.api_key_configured else "NOT SET"
        return {
            "api_base": self.api_base,
            "api_key": key_note,
            "default_model": self.default_model,
            "allowed_targets": list(self.allowed_targets),
            "command_timeout": self.command_timeout,
            "max_output_chars": self.max_output_chars,
            "max_agent_steps": self.max_agent_steps,
            "request_timeout": self.request_timeout,
            "max_retries": self.max_retries,
            "time_budget_seconds": self.time_budget_seconds,
            "model_cache_ttl": self.model_cache_ttl,
            "max_approval_level": self.max_approval_level,
            "reports_dir": str(self.reports_dir),
            "ctf_challenges_dir": str(self.ctf_challenges_dir),
            "ctf_max_steps": self.ctf_max_steps,
            "ctf_remote_verify": self.ctf_remote_verify,
            "ctf_web_enabled": self.ctf_web_enabled,
            "ctf_net_enabled": self.ctf_net_enabled,
        }


def get_settings() -> Settings:
    load_dotenv()

    raw_scope = os.getenv("GRYPHOS_ALLOWED_TARGETS", DEFAULT_SCOPE)
    targets = tuple(x.strip() for x in raw_scope.split(",") if x.strip())
    if not targets:
        log.warning("GRYPHOS_ALLOWED_TARGETS is empty; defaulting to %s", DEFAULT_SCOPE)
        targets = (DEFAULT_SCOPE,)

    api_base = os.getenv("GRYPHOS_API_BASE", DEFAULT_API_BASE).strip() or DEFAULT_API_BASE

    return Settings(
        api_key=os.getenv("OPENROUTER_API_KEY", ""),
        default_model=os.getenv("GRYPHOS_DEFAULT_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        allowed_targets=targets,
        command_timeout=_int_env("GRYPHOS_COMMAND_TIMEOUT"),
        max_output_chars=_int_env("GRYPHOS_MAX_OUTPUT_CHARS"),
        max_agent_steps=_int_env("GRYPHOS_MAX_AGENT_STEPS"),
        api_base=api_base,
        request_timeout=_int_env("GRYPHOS_REQUEST_TIMEOUT"),
        max_retries=_int_env("GRYPHOS_MAX_RETRIES"),
        time_budget_seconds=_int_env("GRYPHOS_TIME_BUDGET_SECONDS"),
        model_cache_ttl=_int_env("GRYPHOS_MODEL_CACHE_TTL"),
        max_approval_level=_int_env("GRYPHOS_MAX_APPROVAL_LEVEL"),
        ctf_challenges_dir=Path(
            os.getenv("GRYPHOS_CTF_CHALLENGES_DIR", "challenges").strip() or "challenges"
        ),
        ctf_max_steps=_int_env("GRYPHOS_CTF_MAX_STEPS"),
        ctf_remote_verify=_bool_env("GRYPHOS_CTF_REMOTE_VERIFY"),
        ctf_web_enabled=_bool_env("GRYPHOS_CTF_WEB_ENABLED", default=True),
        ctf_net_enabled=_bool_env("GRYPHOS_CTF_NET_ENABLED", default=True),
    )
