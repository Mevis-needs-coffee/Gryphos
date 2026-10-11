"""Target scope enforcement.

Scope is a security boundary enforced in application code immediately before
any tool executes. Only literal IPv4/IPv6 addresses are accepted as targets;
hostnames, URLs, CIDR ranges, and ambiguous forms are rejected. Scope entries
themselves may be IPs or CIDR networks. IPv4 and IPv6 are never mixed: a
target is only in scope if a network of the same IP version contains it.

Scope changes are guarded: narrowing the effective scope to a subset of the
configured baseline is allowed silently, but *expansion* beyond the baseline
always requires an explicit, out-of-band operator action (a confirmation
token), so scope can never be widened accidentally or by model output.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

# A scope change beyond the configured baseline only proceeds when the operator
# supplies this exact token. It is never derived from model output.
EXPAND_SCOPE_CONFIRMATION = "EXPAND-SCOPE"


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


# --- resolved-IP / connection peer validation ------------------------------

def resolve_and_validate(
    host: str,
    scope_items: tuple[str, ...],
    allow_hostnames: bool = False,
) -> str:
    """Resolve a destination host to ONE in-scope IP address.

    Literal IPs are validated directly. Hostnames are rejected outright unless
    ``allow_hostnames`` is set. When hostnames are permitted, *every* address
    the name resolves to must be inside the scope; otherwise the destination is
    refused. This is the DNS-rebinding guard: a name that resolves to a mix of
    in-scope and out-of-scope addresses can never be reached.
    """
    text = (host or "").strip()
    try:
        literal, _version = normalize_ip(text)
    except ScopeError:
        literal = None
    if literal is not None:
        return validate_target(literal, scope_items)
    if not allow_hostnames:
        raise ScopeError(
            "Destination must be a literal IP address inside the authorized scope "
            "(hostnames are not permitted)."
        )
    if not text or any(ch in text for ch in "/:@ \t\r\n[]"):
        raise ScopeError("Hostname is malformed.")
    try:
        infos = socket.getaddrinfo(text, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"Could not resolve hostname {text!r}: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        candidate = info[4][0]
        try:
            normalized, _version = normalize_ip(str(candidate))
        except ScopeError:
            continue
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise ScopeError(f"Hostname {text!r} did not resolve to any usable IP address.")
    # Every resolved address must be in scope (blocks rebinding to a mixed set).
    for address in addresses:
        validate_target(address, scope_items)
    return addresses[0]


def validate_connected_peer(peer: str, scope_items: tuple[str, ...]) -> str:
    """Validate the address we actually connected to against scope.

    Applied after ``connect`` so the real peer — not just the requested
    destination — is re-checked against the scope boundary.
    """
    try:
        normalized, _version = normalize_ip(str(peer))
    except ScopeError as exc:
        raise ScopeError(
            f"Connected peer address {peer!r} is not a usable literal IP."
        ) from exc
    return validate_target(normalized, scope_items)


# --- scope change guard -----------------------------------------------------

def scope_networks(
    scope_items: tuple[str, ...],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return parse_scope(scope_items)


def is_subset(inner: tuple[str, ...], outer: tuple[str, ...]) -> bool:
    """True when every network in `inner` is contained within some `outer` net."""
    inner_nets = parse_scope(inner)
    outer_nets = parse_scope(outer)
    return all(
        any(
            net.version == other.version and net.subnet_of(other)
            for other in outer_nets
        )
        for net in inner_nets
    )


def describe_change(baseline: tuple[str, ...], candidate: tuple[str, ...]) -> str:
    """Classify a scope change as 'same', 'narrow', or 'expand'."""
    if tuple(candidate) == tuple(baseline):
        return "same"
    if is_subset(candidate, baseline):
        return "narrow"
    return "expand"


@dataclass
class ScopeManager:
    """Holds the configured (baseline) scope and the effective scope.

    The effective scope may only be narrowed silently. Any change that adds
    coverage beyond the baseline is an *expansion* and requires the explicit
    ``EXPAND_SCOPE_CONFIRMATION`` token. The model has no path to this object.
    """

    baseline: tuple[str, ...]
    effective: tuple[str, ...] = ()
    changes: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        parse_scope(self.baseline)
        if not self.effective:
            self.effective = tuple(self.baseline)
        else:
            parse_scope(self.effective)
            if not is_subset(self.effective, self.baseline):
                raise ScopeError("Effective scope must be within the baseline scope.")

    def classify(self, candidate: tuple[str, ...]) -> str:
        items = tuple(str(x).strip() for x in candidate if str(x).strip())
        parse_scope(items)
        return describe_change(self.baseline, items)

    def change(
        self, candidate: tuple[str, ...], confirmation: str = ""
    ) -> dict:
        """Apply a scope change, guarding against accidental expansion.

        Narrowing (or resetting to baseline) is applied directly. Expansion
        beyond the baseline raises ScopeError unless the exact confirmation
        token is supplied by the operator.
        """
        items = tuple(str(x).strip() for x in candidate if str(x).strip())
        parse_scope(items)
        before = self.effective
        kind = describe_change(self.baseline, items)
        if kind == "expand" and confirmation != EXPAND_SCOPE_CONFIRMATION:
            raise ScopeError(
                "Scope expansion requires an explicit operator confirmation "
                f"(expected token {EXPAND_SCOPE_CONFIRMATION!r}). "
                "The model cannot change scope."
            )
        self.effective = items
        record = {
            "before": list(before),
            "after": list(items),
            "kind": kind,
            "authorization": "explicit" if kind == "expand" else "automatic-narrowing",
            "at": datetime.now(UTC).isoformat(),
        }
        self.changes.append(record)
        return record

    def reset(self) -> dict:
        return self.change(tuple(self.baseline))
