"""Authorized network-target configuration for a CTF challenge (Phase 4).

A network challenge declares the one host the solver is allowed to touch. This
module parses and validates that declaration; it performs **no** network activity
and makes no reachability decision (that is `netscope.py`). A `TargetConfig` is
what the operator authorized — nothing else is reachable.

The `target` block in `challenge.json` looks like:

    {"host": "10.10.5.12", "lab": true, "ports": "1-1024"}

`lab` must be set explicitly by the operator to authorize loopback, private, and
other reserved destinations (TryHackMe machines are reached over a private VPN
range, so `lab: true` is expected there). Without it, only public addresses are
reachable. Every port/connection/time/rate bound has a hard ceiling so a challenge
cannot raise its own limits beyond safety.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

DEFAULT_PORTS = "1-1024"
CEILING_MAX_PORTS = 4096
DEFAULT_MAX_CONNECTIONS = 200
CEILING_MAX_CONNECTIONS = 2000
DEFAULT_CONNECT_TIMEOUT_MS = 1500
CEILING_CONNECT_TIMEOUT_MS = 5000
FLOOR_CONNECT_TIMEOUT_MS = 100
DEFAULT_MIN_INTERVAL_MS = 0
CEILING_MIN_INTERVAL_MS = 5000

# A small, ordered set of commonly-open service ports, used when the caller asks
# for a quick "top ports" scan instead of a range.
TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 2049, 2082, 2083, 2181, 3000, 3306, 3389, 4443, 5000,
    5432, 5900, 5985, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 11211, 27017,
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


class TargetConfigError(ValueError):
    """Raised when the declared network target or bounds are invalid."""


def _clamp_int(value: object, default: int, lo: int, hi: int, field: str) -> int:
    if value is None:
        return default
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise TargetConfigError(f"{field} must be an integer.") from exc
    if number < lo:
        raise TargetConfigError(f"{field} must be >= {lo}.")
    return min(number, hi)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip())
        return True
    except ValueError:
        return False


def parse_port_spec(spec: object, max_ports: int) -> list[int]:
    """Parse a port spec ("80", "1-1024", "22,80,443") into a bounded port list.

    Raises `TargetConfigError` on malformed input or when the requested set
    exceeds `max_ports`.
    """
    text = str(spec or "").strip()
    if not text:
        raise TargetConfigError("A port spec is required (e.g. \"80\", \"1-1024\", \"22,80,443\").")
    ports: set[int] = set()
    for raw_chunk in text.split(","):
        chunk = raw_chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_text, _, hi_text = chunk.partition("-")
            try:
                lo, hi = int(lo_text), int(hi_text)
            except ValueError as exc:
                raise TargetConfigError(f"Invalid port range {chunk!r}.") from exc
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or lo > hi:
                raise TargetConfigError(f"Invalid port range {chunk!r}.")
            ports.update(range(lo, hi + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise TargetConfigError(f"Invalid port {chunk!r}.") from exc
            if not (1 <= port <= 65535):
                raise TargetConfigError(f"Port {chunk!r} must be between 1 and 65535.")
            ports.add(port)
        if len(ports) > max_ports:
            break
    if not ports:
        raise TargetConfigError("Port spec contained no usable ports.")
    if len(ports) > max_ports:
        raise TargetConfigError(
            f"Port spec selects {len(ports)} ports, above the configured maximum of {max_ports}."
        )
    return sorted(ports)


@dataclass(frozen=True)
class TargetConfig:
    """A validated, immutable authorized network target and its safety bounds."""

    host: str
    lab: bool = False
    ports: str = DEFAULT_PORTS
    max_ports: int = 1024
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    connect_timeout_ms: int = DEFAULT_CONNECT_TIMEOUT_MS
    min_interval_ms: int = DEFAULT_MIN_INTERVAL_MS

    @property
    def host_is_ip(self) -> bool:
        return is_ip_literal(self.host)

    @classmethod
    def from_dict(cls, data: object) -> TargetConfig:
        if not isinstance(data, dict):
            raise TargetConfigError("target must be a JSON object with a 'host'.")
        if isinstance(data.get("origin"), str) and "host" not in data:
            raise TargetConfigError(
                "target.host is required; for web challenges use the 'web' block instead."
            )
        host = str(data.get("host", "")).strip()
        if not host:
            raise TargetConfigError(
                "target.host is required: set the authorized target IP/hostname, "
                "e.g. \"10.10.5.12\"."
            )
        if any(ch in host for ch in "\r\n\t /"):
            raise TargetConfigError("target.host must not contain whitespace, spaces, or slashes.")
        if not is_ip_literal(host) and not _HOSTNAME_RE.match(host):
            raise TargetConfigError(f"target.host {host!r} is not a valid IP or hostname.")

        lab = bool(data.get("lab", False))
        ports = str(data.get("ports", DEFAULT_PORTS)).strip() or DEFAULT_PORTS
        max_ports = _clamp_int(data.get("max_ports"), 1024, 1, CEILING_MAX_PORTS, "target.max_ports")
        # Validate the declared port spec against the declared maximum now.
        parse_port_spec(ports, max_ports)
        max_connections = _clamp_int(
            data.get("max_connections"), DEFAULT_MAX_CONNECTIONS, 1, CEILING_MAX_CONNECTIONS,
            "target.max_connections",
        )
        timeout = _clamp_int(
            data.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS,
            FLOOR_CONNECT_TIMEOUT_MS, CEILING_CONNECT_TIMEOUT_MS, "target.connect_timeout_ms",
        )
        interval = _clamp_int(
            data.get("min_interval_ms"), DEFAULT_MIN_INTERVAL_MS, 0, CEILING_MIN_INTERVAL_MS,
            "target.min_interval_ms",
        )
        return cls(
            host=host,
            lab=lab,
            ports=ports,
            max_ports=max_ports,
            max_connections=max_connections,
            connect_timeout_ms=timeout,
            min_interval_ms=interval,
        )

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "lab": self.lab,
            "ports": self.ports,
            "max_ports": self.max_ports,
            "max_connections": self.max_connections,
            "connect_timeout_ms": self.connect_timeout_ms,
            "min_interval_ms": self.min_interval_ms,
        }

    def describe(self) -> str:
        mode = "lab (private/loopback authorized)" if self.lab else "public-only"
        return (
            f"host={self.host} ({mode}); ports '{self.ports}' (max {self.max_ports}); "
            f"max {self.max_connections} connections, {self.connect_timeout_ms} ms timeout"
        )
