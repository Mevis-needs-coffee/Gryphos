"""Flag detection and verification.

Detection scans untrusted output for flag-shaped strings. Verification decides
whether a candidate can be trusted, and the verdict always names the verifier so
nothing is silently treated as confirmed:

- `HeuristicFlagVerifier` (default, offline) accepts a candidate only when it
  matches the challenge's declared format (or a conservative default format) and
  passes length/charset bounds. It is explicitly *format conformance*, never
  independent confirmation.
- `HttpFlagVerifier` (opt-in) submits to a configured CTFd-style endpoint. It is
  only ever constructed when a submit config exists AND remote verification is
  explicitly enabled.

A candidate is only "verified" when a verifier accepts it. Detection alone is
never success.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

import requests

from .models import FlagCandidate, utc_now_iso

# Conservative default: common flag wrappers only. Deliberately narrow to avoid
# flooding the solver with false positives from unrelated brace-delimited text.
_DEFAULT_FLAG_RE = re.compile(
    r"(?:flag|ctf|key|picoCTF|HTB|DUCTF|CSR)\{[^}\n\r]{1,200}\}",
    re.IGNORECASE,
)
_MAX_CANDIDATES = 20
_MAX_FLAG_LEN = 512
_MIN_FLAG_LEN = 4

_HTTP_SUBMIT_TIMEOUT = 15


class FlagFormat:
    """A compiled flag-format matcher for one challenge."""

    def __init__(self, pattern: str | None = None):
        self.pattern_text = pattern or ""
        try:
            self.regex = re.compile(pattern) if pattern else _DEFAULT_FLAG_RE
        except re.error as exc:  # a bad operator-supplied pattern is a config error
            raise ValueError(f"Invalid flag_format regex {pattern!r}: {exc}") from exc
        self.explicit = bool(pattern)

    @classmethod
    def for_challenge(cls, challenge) -> FlagFormat:
        return cls(getattr(challenge, "flag_format", None))

    def matches(self, value: str) -> bool:
        text = (value or "").strip()
        if not (_MIN_FLAG_LEN <= len(text) <= _MAX_FLAG_LEN):
            return False
        if any(ch in text for ch in "\r\n\t"):
            return False
        if not text.isprintable():
            return False
        return bool(self.regex.fullmatch(text))

    def find(self, text: str, limit: int = _MAX_CANDIDATES) -> list[str]:
        """Return unique flag-shaped substrings, in first-seen order."""
        found: list[str] = []
        for match in self.regex.finditer(text or ""):
            value = match.group(0).strip()
            if value and value not in found:
                found.append(value)
            if len(found) >= limit:
                break
        return found

    @property
    def description(self) -> str:
        return self.pattern_text or _DEFAULT_FLAG_RE.pattern


@dataclass
class FlagVerdict:
    value: str
    status: str  # one of gryphos.ctf.models.FLAG_STATUSES
    verifier: str
    detail: str = ""
    conclusive: bool = False  # True only when a challenge endpoint accepted it
    at: str = ""

    def __post_init__(self) -> None:
        if not self.at:
            self.at = utc_now_iso()

    def to_candidate(self, source: str = "", confidence: str = "medium") -> FlagCandidate:
        return FlagCandidate(
            value=self.value,
            source=source,
            confidence=confidence,
            status=self.status,
            verifier=self.verifier,
            detail=self.detail,
            detected_at=self.at,
        )


def detect_flags(text: str, fmt: FlagFormat | None = None) -> list[str]:
    """Scan untrusted text for flag-shaped candidates."""
    return (fmt or FlagFormat()).find(text or "")


class HeuristicFlagVerifier:
    """Offline, format-conformance verifier (default)."""

    name = "heuristic-format"

    def __init__(self, fmt: FlagFormat | None = None):
        self.fmt = fmt or FlagFormat()

    def verify(self, candidate: str) -> FlagVerdict:
        value = (candidate or "").strip()
        if not value:
            return FlagVerdict(value, "format_invalid", self.name, "empty candidate")
        if not self.fmt.matches(value):
            return FlagVerdict(
                value,
                "format_invalid",
                self.name,
                "does not match the expected flag format",
            )
        return FlagVerdict(
            value,
            "verified",
            self.name,
            "matches the expected flag format (format conformance, not "
            "independently confirmed by a challenge endpoint)",
            conclusive=False,
        )


class HttpFlagVerifier:
    """Opt-in CTFd-style verifier. Gated by explicit configuration."""

    name = "http-submit"

    def __init__(
        self,
        url: str,
        token: str = "",
        field: str = "flag",
        timeout: int = _HTTP_SUBMIT_TIMEOUT,
        http_post: Callable[[str, dict, dict, int], object] | None = None,
    ):
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            raise ValueError("Flag submit URL must be an absolute http(s) URL.")
        self.url = url
        self.token = token
        self.field = field or "flag"
        self.timeout = timeout
        self._post = http_post or _default_post

    def verify(self, candidate: str) -> FlagVerdict:
        value = (candidate or "").strip()
        if not value:
            return FlagVerdict(value, "format_invalid", self.name, "empty candidate")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = self._post(self.url, {self.field: value}, headers, self.timeout)
        except Exception as exc:  # noqa: BLE001 - a submission failure is reported, never hidden
            return FlagVerdict(
                value, "unverified", self.name, f"submission failed: {type(exc).__name__}"
            )
        return self._interpret(value, response)

    def _interpret(self, value: str, response: object) -> FlagVerdict:
        status_code = getattr(response, "status_code", None)
        try:
            body = str(getattr(response, "text", "") or "")
        except Exception:  # noqa: BLE001 - defensive: a broken response body is just "no body"
            body = ""
        lowered = body.lower()
        accepted = status_code == 200 and (
            '"success": true' in lowered
            or '"success":true' in lowered
            or "correct" in lowered
            or "accepted" in lowered
            or "congrat" in lowered
        )
        if accepted:
            return FlagVerdict(value, "verified", self.name, "accepted by the submit endpoint", conclusive=True)
        if status_code in (200, 400, 403, 422) and body:
            return FlagVerdict(value, "incorrect", self.name, "rejected by the submit endpoint", conclusive=True)
        return FlagVerdict(
            value, "unverified", self.name, f"inconclusive response (HTTP {status_code})"
        )


def _default_post(url: str, payload: dict, headers: dict, timeout: int):
    return requests.post(url, json=payload, headers=headers, timeout=timeout)


def verify_flag(
    candidate: str,
    fmt: FlagFormat | None = None,
    submit: dict | None = None,
    allow_remote: bool = False,
    http_post: Callable | None = None,
) -> FlagVerdict:
    """Verify a candidate, preferring the remote verifier only when permitted."""
    if allow_remote and submit and submit.get("url"):
        try:
            verifier = HttpFlagVerifier(
                url=str(submit["url"]),
                token=str(submit.get("token", "")),
                field=str(submit.get("field", "flag")),
                http_post=http_post,
            )
        except ValueError as exc:
            return FlagVerdict(candidate, "unverified", "http-submit", str(exc))
        return verifier.verify(candidate)
    return HeuristicFlagVerifier(fmt).verify(candidate)
