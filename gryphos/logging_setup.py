"""Logging setup with secret redaction.

Diagnostic logs go to `logs/gryphos.log` (gitignored). A filter redacts API keys
and authorization headers so secrets never reach disk or the console.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

_REDACTED = "***REDACTED***"

_PATTERNS: tuple[re.Pattern[str], ...] = (
    # OpenRouter-style keys
    re.compile(r"sk-or-v1-[A-Za-z0-9]{8,}"),
    # Generic bearer tokens / authorization headers
    re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?)(?:bearer\s+)?\S+"),
    re.compile(r"(?i)(api[_-]?key[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9_\-]{8,})"),
)


def redact(text: str) -> str:
    """Replace known secret patterns in *text* with a redaction marker."""
    out = text
    for pattern in _PATTERNS:
        if pattern.groups:
            out = pattern.sub(lambda m: m.group(1) + _REDACTED, out)
        else:
            out = pattern.sub(_REDACTED, out)
    return out


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def setup_logging(log_dir: Path, level: int = logging.INFO) -> logging.Logger:
    """Configure the `gryphos` logger to write to a redacted file log."""
    logger = logging.getLogger("gryphos")
    logger.setLevel(level)
    if any(getattr(h, "_gryphos_file", False) for h in logger.handlers):
        return logger

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_dir / "gryphos.log", encoding="utf-8")
    except OSError:
        logger.addHandler(logging.NullHandler())
        return logger

    handler._gryphos_file = True  # type: ignore[attr-defined]
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    handler.addFilter(RedactionFilter())
    logger.addHandler(handler)

    console_filter = RedactionFilter()
    for h in logger.handlers:
        h.addFilter(console_filter)
    return logger
