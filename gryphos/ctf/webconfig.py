"""Authorized web-challenge origin configuration.

A web challenge must explicitly declare the one origin the solver is allowed to
touch. This module parses and validates that declaration; it performs **no**
network activity and makes no policy decision about reachability (that is
`webscope.py`). Keeping the parser dependency-free means the challenge model can
embed a `WebConfig` without importing the runtime scope machinery.

The `web` block in `challenge.json` looks like:

    {"origin": "http://127.0.0.1:8080", "lab": true}

`lab` must be set explicitly by the operator to authorize loopback, private, and
other reserved destinations (e.g. a local Docker target). Without it only public
addresses are reachable. Cross-origin redirects are disabled unless the operator
opts in, and every size/time/rate bound has a hard ceiling so a challenge cannot
raise its own limits beyond safety.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_MAX_REQUESTS = 40
CEILING_MAX_REQUESTS = 500
DEFAULT_MAX_BODY_BYTES = 256 * 1024
CEILING_MAX_BODY_BYTES = 4 * 1024 * 1024
DEFAULT_MIN_INTERVAL_MS = 0
CEILING_MIN_INTERVAL_MS = 5000

_SECURE_SCHEMES = {"http", "https"}
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


class WebConfigError(ValueError):
    """Raised when the declared web mission origin or bounds are invalid."""


def _clamp_int(value: object, default: int, lo: int, hi: int, field: str) -> int:
    if value is None:
        return default
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise WebConfigError(f"{field} must be an integer.") from exc
    if number < lo:
        raise WebConfigError(f"{field} must be >= {lo}.")
    return min(number, hi)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class WebConfig:
    """A validated, immutable authorized web origin and its safety bounds."""

    scheme: str
    host: str
    port: int
    lab: bool = False
    allow_cross_origin_redirects: bool = False
    max_requests: int = DEFAULT_MAX_REQUESTS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    min_interval_ms: int = DEFAULT_MIN_INTERVAL_MS

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def host_is_ip(self) -> bool:
        return _is_ip_literal(self.host)

    @classmethod
    def from_dict(cls, data: object) -> WebConfig:
        if not isinstance(data, dict):
            raise WebConfigError("web must be a JSON object with an 'origin'.")
        origin = str(data.get("origin", "")).strip()
        if not origin:
            raise WebConfigError(
                "web.origin is required: set the authorized challenge origin, "
                "e.g. \"http://127.0.0.1:8080\"."
            )
        if any(ch in origin for ch in "\r\n\t "):
            raise WebConfigError("web.origin must not contain whitespace or control characters.")
        parts = urlsplit(origin)
        scheme = parts.scheme.lower()
        if scheme not in _SECURE_SCHEMES:
            raise WebConfigError("web.origin scheme must be http or https.")
        if not parts.netloc or parts.username or parts.password:
            raise WebConfigError("web.origin must be a plain scheme://host[:port] with no credentials.")
        if parts.query or parts.fragment:
            raise WebConfigError("web.origin must not include a query string or fragment.")
        if parts.path not in ("", "/"):
            raise WebConfigError("web.origin must not include a path; put paths in the tools.")
        host = (parts.hostname or "").strip()
        if not host:
            raise WebConfigError("web.origin must contain a host.")
        if not _is_ip_literal(host) and not _HOSTNAME_RE.match(host):
            raise WebConfigError(f"web.origin host {host!r} is not a valid IP or hostname.")
        try:
            port = parts.port
        except ValueError as exc:
            raise WebConfigError("web.origin port is invalid.") from exc
        if port is None:
            port = 443 if scheme == "https" else 80
        if not (1 <= port <= 65535):
            raise WebConfigError("web.origin port must be between 1 and 65535.")

        lab = bool(data.get("lab", False))
        cross = bool(data.get("allow_cross_origin_redirects", False))
        max_requests = _clamp_int(
            data.get("max_requests"), DEFAULT_MAX_REQUESTS, 1, CEILING_MAX_REQUESTS, "web.max_requests"
        )
        max_body = _clamp_int(
            data.get("max_body_bytes"), DEFAULT_MAX_BODY_BYTES, 1024, CEILING_MAX_BODY_BYTES,
            "web.max_body_bytes",
        )
        interval = _clamp_int(
            data.get("min_interval_ms"), DEFAULT_MIN_INTERVAL_MS, 0, CEILING_MIN_INTERVAL_MS,
            "web.min_interval_ms",
        )
        return cls(
            scheme=scheme,
            host=host,
            port=port,
            lab=lab,
            allow_cross_origin_redirects=cross,
            max_requests=max_requests,
            max_body_bytes=max_body,
            min_interval_ms=interval,
        )

    def to_dict(self) -> dict:
        return {
            "origin": self.origin,
            "lab": self.lab,
            "allow_cross_origin_redirects": self.allow_cross_origin_redirects,
            "max_requests": self.max_requests,
            "max_body_bytes": self.max_body_bytes,
            "min_interval_ms": self.min_interval_ms,
        }

    def describe(self) -> str:
        mode = "lab (private/loopback authorized)" if self.lab else "public-only"
        cross = "on" if self.allow_cross_origin_redirects else "off"
        return (
            f"origin={self.origin} ({mode}); cross-origin redirects {cross}; "
            f"max {self.max_requests} requests, {self.max_body_bytes} bytes/response"
        )
