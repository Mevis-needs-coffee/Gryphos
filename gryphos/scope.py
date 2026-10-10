"""Target scope enforcement.

Scope is a security boundary enforced in application code immediately before
any tool executes. Only literal IPv4/IPv6 addresses are accepted as targets;
hostnames, URLs, CIDR ranges, and ambiguous forms are rejected. Scope entries
themselves may be IPs or CIDR networks. IPv4 and IPv6 are never mixed: a
target is only in scope if a network of the same IP version contains it.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Raised when a target or scope entry is invalid or out of scope."""


def parse_scope(scope_items: tuple[str, ...]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in scope_items:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ScopeError(
                f"Invalid GRYPHOS_ALLOWED_TARGETS entry {item!r}: {exc}"
            ) from exc
    if not networks:
        raise ScopeError(
            "No authorized targets configured. Set GRYPHOS_ALLOWED_TARGETS in .env."
        )
    return networks


def normalize_ip(target: str) -> tuple[str, int]:
    """Parse a single literal IP address.

    Returns (normalized_string, version). Rejects hostnames, URLs, CIDR
    ranges, and ambiguous forms (e.g. '127.1'). IPv4-mapped IPv6 addresses
    are rejected to avoid v4/v6 scope confusion.
    """
    text = (target or "").strip()
    if not text:
        raise ScopeError("Target is empty. Provide one literal IP address.")
    if any(ch in text for ch in "/[]"):
        # '[::1]' bracket form and any CIDR are rejected for single-IP tools.
        raise ScopeError(
            "Target must be a single literal IP address without brackets or CIDR suffix."
        )
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ScopeError(
            "For safety, target must be one literal IPv4/IPv6 address — "
            "not a hostname, URL, range, or abbreviated form."
        ) from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise ScopeError(
            "IPv4-mapped IPv6 addresses are not accepted; use the IPv4 address directly."
        )
    return str(address), address.version


_RESERVED_NETS: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = [
    ("unspecified", ipaddress.ip_network("0.0.0.0/8")),
    ("loopback", ipaddress.ip_network("127.0.0.0/8")),
    ("loopback", ipaddress.ip_network("::1/128")),
    ("cloud_metadata (link-local)", ipaddress.ip_network("169.254.169.254/32")),
    ("link-local", ipaddress.ip_network("169.254.0.0/16")),
    ("link-local", ipaddress.ip_network("fe80::/10")),
    ("private", ipaddress.ip_network("10.0.0.0/8")),
    ("private", ipaddress.ip_network("172.16.0.0/12")),
    ("private", ipaddress.ip_network("192.168.0.0/16")),
    ("private", ipaddress.ip_network("fc00::/7")),
    ("CGNAT (shared)", ipaddress.ip_network("100.64.0.0/10")),
    ("reserved/testing", ipaddress.ip_network("192.0.0.0/24")),
    ("reserved/testing", ipaddress.ip_network("198.18.0.0/15")),
    ("documentation (TEST-NET)", ipaddress.ip_network("192.0.2.0/24")),
    ("documentation (TEST-NET)", ipaddress.ip_network("198.51.100.0/24")),
    ("documentation (TEST-NET)", ipaddress.ip_network("203.0.113.0/24")),
    ("multicast/reserved", ipaddress.ip_network("224.0.0.0/4")),
    ("multicast/reserved", ipaddress.ip_network("ff00::/8")),
    ("reserved (future use)", ipaddress.ip_network("240.0.0.0/4")),
]


def classify_ip(network: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[str]:
    """Classify an address into reserved/private/link-local/metadata categories.

    Used for diagnostics and for policy messaging. Being 'private' or
    'link-local' is NOT a block by itself: an address is only reachable when
    the configured scope explicitly permits it. This function only names the
    category for clear errors and reporting.
    """
    categories: list[str] = []
    for label, net in _RESERVED_NETS:
        if (
            net.version == network.version
            and network in net
            and label not in categories
        ):
            categories.append(label)
    return categories


def validate_target(target: str, scope_items: tuple[str, ...]) -> str:
    """Validate one literal target IP against the configured scope.

    Returns the normalized IP string, or raises ScopeError.
    """
    normalized, version = normalize_ip(target)
    address = ipaddress.ip_address(normalized)
    networks = parse_scope(scope_items)
    for net in networks:
        if net.version == version and address in net:
            return normalized
    categories = classify_ip(address)
    hint = ""
    if categories:
        hint = f" It is classified as: {', '.join(categories)}."
    raise ScopeError(
        f"{normalized} is outside the configured authorized scope. "
        f"To target it, add it to GRYPHOS_ALLOWED_TARGETS explicitly.{hint} "
        f"Allowed scope: {', '.join(scope_items)}"
    )


def authorize_url(url: str, scope_items: tuple[str, ...]) -> dict[str, object]:
    """Authorize an HTTP(S) URL for a network tool.

    Policy: the URL must be absolute, use http or https, and its host must be
    a *literal IP address* inside the configured scope. Hostnames are rejected
    (no DNS resolution), which removes DNS-rebinding and redirect-to-name
    bypasses entirely. Returns a dict with normalized parts.
    """
    text = (url or "").strip()
    if not text or any(ch in text for ch in "\r\n\t "):
        raise ScopeError("URL is empty or contains illegal whitespace/control characters.")
    parts = urlsplit(text)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ScopeError("URL scheme must be http or https.")
    if not parts.netloc or parts.username or parts.password:
        raise ScopeError("URL must have a plain host[:port] with no credentials.")
    try:
        port = parts.port
    except ValueError as exc:
        raise ScopeError("URL port is invalid.") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ScopeError("URL port must be between 1 and 65535.")
    host = parts.hostname or ""
    try:
        normalized, _version = normalize_ip(host)
    except ScopeError as exc:
        raise ScopeError(
            "URL host must be a literal IP address inside the authorized scope "
            "(hostnames are not permitted)."
        ) from exc
    validate_target(normalized, scope_items)
    default_port = 443 if parts.scheme.lower() == "https" else 80
    effective_port = port if port is not None else default_port
    path = parts.path or "/"
    if len(path) > 2048:
        raise ScopeError("URL path is too long.")
    return {
        "scheme": parts.scheme.lower(),
        "host": normalized,
        "port": effective_port,
        "path": path,
        "url": f"{parts.scheme.lower()}://{normalized}:{effective_port}{path}",
    }


def validate_port(port: object) -> int:
    """Validate a TCP port number."""
    try:
        value = int(port)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ScopeError("Port must be an integer between 1 and 65535.") from exc
    if not (1 <= value <= 65535):
        raise ScopeError("Port must be between 1 and 65535.")
    return value


def validate_path(path: object) -> str:
    """Validate an HTTP request path (must start with '/', no CR/LF)."""
    text = path if isinstance(path, str) else ""
    if not text.startswith("/"):
        raise ScopeError("HTTP path must start with '/'.")
    if any(ch in text for ch in "\r\n\t "):
        raise ScopeError("HTTP path contains illegal characters.")
    if len(text) > 2048:
        raise ScopeError("HTTP path is too long.")
    return text
