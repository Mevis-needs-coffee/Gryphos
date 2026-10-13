"""Runtime scope enforcement for an authorized web CTF challenge (Phase 3).

`WebConfig` (see `webconfig.py`) records what the operator explicitly authorized;
`WebScope` turns it into an execution-time boundary. Every request the solver can
make must pass through here, so the model can never widen its own reach:

- the destination scheme/host/port must match the configured origin, or (only
  when the operator opted in) a cross-origin redirect destination;
- the host is resolved on every request and **every** resolved address must pass
  the IP policy, defeating DNS rebinding to a blocked address;
- cloud-metadata and link-local ranges are blocked unconditionally, even in lab
  mode, and private/loopback/reserved ranges require the explicit `lab: true`
  opt-in, so a public challenge cannot pivot into a private network;
- paths are normalized and validated (no CR/LF, no `//host` or `scheme://`).

`WebScope` performs no I/O beyond DNS resolution; the HTTP client lives in
`webclient.py` and always consults this object first.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from ..scope import classify_ip
from .webconfig import WebConfig

MAX_PATH_LEN = 2048

# Address categories that are never reachable, even with `lab: true`.
_ALWAYS_BLOCKED = frozenset({
    "unspecified",
    "cloud_metadata (link-local)",
    "link-local",
    "multicast/reserved",
    "reserved (future use)",
})
# Address categories reachable only when the operator sets `lab: true`.
_LAB_ONLY = frozenset({
    "private",
    "loopback",
    "CGNAT (shared)",
    "reserved/testing",
    "documentation (TEST-NET)",
})


class WebScopeError(ValueError):
    """Raised when a web request or redirect violates the authorized scope."""


@dataclass(frozen=True)
class WebTarget:
    """A fully validated, in-scope request destination."""

    scheme: str
    host: str  # the origin hostname/literal used for the Host header and TLS SNI
    port: int
    path: str

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}{self.path}"


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class WebScope:
    """The fixed, operator-authorized boundary for one web challenge."""

    def __init__(self, config: WebConfig):
        self.config = config
        self.origin_scheme = config.scheme
        self.origin_host = config.host
        self.origin_port = config.port
        # Fail fast: the configured origin itself must satisfy the IP policy.
        self.resolve_destination(self.origin_host)

    # -- properties -------------------------------------------------------

    @property
    def origin(self) -> str:
        return self.config.origin

    @property
    def max_requests(self) -> int:
        return self.config.max_requests

    @property
    def max_body_bytes(self) -> int:
        return self.config.max_body_bytes

    @property
    def min_interval_ms(self) -> int:
        return self.config.min_interval_ms

    @property
    def lab(self) -> bool:
        return self.config.lab

    def describe(self) -> str:
        return self.config.describe()

    # -- IP policy --------------------------------------------------------

    def _address_error(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        categories = classify_ip(address)
        blocked = [c for c in categories if c in _ALWAYS_BLOCKED]
        if blocked:
            return f"address {address} is a blocked range ({', '.join(blocked)})"
        if not self.lab:
            private = [c for c in categories if c in _LAB_ONLY]
            if private:
                return (
                    f"address {address} is {', '.join(private)}; set \"lab\": true on the "
                    "web mission to authorize private/loopback/reserved lab targets"
                )
        return None

    def resolve_destination(self, host: str) -> list[str]:
        """Resolve `host` and verify every address satisfies the IP policy.

        Returns the list of validated IP strings. Raises WebScopeError if the
        host is malformed, does not resolve, or any resolved address is blocked
        (which is the DNS-rebinding guard).
        """
        text = (host or "").strip()
        if not text:
            raise WebScopeError("Destination host is empty.")
        if _is_ip_literal(text):
            addresses = [str(ipaddress.ip_address(text))]
        else:
            try:
                infos = socket.getaddrinfo(text, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror as exc:
                raise WebScopeError(f"Could not resolve host {text!r}: {exc}") from exc
            addresses = []
            for info in infos:
                candidate = str(info[4][0])
                if candidate not in addresses:
                    addresses.append(candidate)
            if not addresses:
                raise WebScopeError(f"Host {text!r} did not resolve to any address.")
        for candidate in addresses:
            address = ipaddress.ip_address(candidate)
            problem = self._address_error(address)
            if problem:
                raise WebScopeError(f"Refused destination {text!r}: {problem}.")
        return addresses

    # -- endpoint / path policy ------------------------------------------

    def _same_origin(self, scheme: str, host: str, port: int) -> bool:
        return (
            scheme == self.origin_scheme
            and host.lower() == self.origin_host.lower()
            and port == self.origin_port
        )

    def _check_endpoint(self, scheme: str, host: str, port: int, *, cross_origin: bool) -> None:
        scheme = (scheme or "").lower()
        if scheme not in {"http", "https"}:
            raise WebScopeError("Destination scheme must be http or https.")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise WebScopeError("Destination port must be between 1 and 65535.")
        if self._same_origin(scheme, host, port):
            return
        if not cross_origin or not self.config.allow_cross_origin_redirects:
            raise WebScopeError(
                "Refused cross-origin destination "
                f"{scheme}://{host}:{port}: only the authorized origin {self.origin} is "
                "allowed (set allow_cross_origin_redirects to permit redirects)."
            )
        # Cross-origin is permitted, but the new host is still fully validated.
        self.resolve_destination(host)

    @staticmethod
    def _check_path(path: object) -> str:
        text = path if isinstance(path, str) else ""
        text = text.strip()
        if not text:
            text = "/"
        if "://" in text or text.startswith("//"):
            raise WebScopeError("Path must be relative to the authorized origin, not an absolute URL.")
        if any(ch in text for ch in "\r\n\t "):
            raise WebScopeError("Path contains illegal whitespace or control characters.")
        if not text.startswith("/"):
            text = "/" + text
        if len(text) > MAX_PATH_LEN:
            raise WebScopeError("Path is too long.")
        return text

    def authorize_request(
        self,
        path: str,
        *,
        scheme: str | None = None,
        host: str | None = None,
        port: int | None = None,
    ) -> WebTarget:
        """Validate a direct request (defaults to the configured origin)."""
        target_scheme = (scheme or self.origin_scheme).lower()
        target_host = host or self.origin_host
        target_port = self.origin_port if port is None else port
        self._check_endpoint(target_scheme, target_host, target_port, cross_origin=False)
        return WebTarget(target_scheme, target_host, target_port, self._check_path(path))

    def authorize_redirect(self, location: str, current: WebTarget) -> WebTarget:
        """Validate one redirect destination (cross-origin only if opted in)."""
        from urllib.parse import urljoin, urlsplit

        location = (location or "").strip()
        if not location:
            raise WebScopeError("Redirect Location header is empty.")
        if any(ch in location for ch in "\r\n\t "):
            raise WebScopeError("Redirect Location contains illegal characters.")
        joined = urljoin(current.url, location)
        parts = urlsplit(joined)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise WebScopeError("Redirect scheme must be http or https.")
        if parts.username or parts.password:
            raise WebScopeError("Redirect Location must not contain credentials.")
        host = parts.hostname or ""
        if not host:
            raise WebScopeError("Redirect Location has no host.")
        try:
            port = parts.port
        except ValueError as exc:
            raise WebScopeError("Redirect Location port is invalid.") from exc
        if port is None:
            port = 443 if scheme == "https" else 80
        cross_origin = not self._same_origin(scheme, host, port)
        self._check_endpoint(scheme, host, port, cross_origin=cross_origin)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return WebTarget(scheme, host, port, self._check_path(path))
