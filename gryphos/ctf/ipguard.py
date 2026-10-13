"""Shared destination IP policy for authorized network scope.

Both the web scope (`webscope.py`) and the network scope (`netscope.py`) must
apply the *same* address policy, so it lives here once. The policy is:

- some address categories are **never** reachable, even in an explicitly
  authorized lab (`ALWAYS_BLOCKED`): the unspecified address, cloud metadata,
  link-local, multicast/reserved, and the reserved-for-future-use range. These
  are the classes used for cloud-metadata SSRF and other pivots, so they are
  blocked unconditionally;
- private, loopback, CGNAT, reserved/testing, and documentation (TEST-NET)
  ranges are reachable **only** when the operator explicitly authorized a lab
  target (`LAB_ONLY`);
- everything else (public addresses) is reachable when a target is authorized.

This module performs DNS resolution and classification only; it makes no policy
decision about *which* host is authorized (that is the scope object's job).
"""

from __future__ import annotations

import ipaddress
import socket

from ..scope import classify_ip

# Address categories that are never reachable, even with an authorized lab target.
ALWAYS_BLOCKED = frozenset({
    "unspecified",
    "cloud_metadata (link-local)",
    "link-local",
    "multicast/reserved",
    "reserved (future use)",
})
# Address categories reachable only when the operator authorizes a lab target.
LAB_ONLY = frozenset({
    "private",
    "loopback",
    "CGNAT (shared)",
    "reserved/testing",
    "documentation (TEST-NET)",
})


class AddressPolicyError(ValueError):
    """Raised when a destination host is malformed, unresolvable, or blocked."""


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip())
        return True
    except ValueError:
        return False


def resolve_addresses(host: str) -> list[str]:
    """Resolve `host` to a de-duplicated list of IP strings (literal or DNS).

    Performs no policy check. Raises `AddressPolicyError` if the host is empty,
    malformed, or does not resolve.
    """
    text = (host or "").strip()
    if not text:
        raise AddressPolicyError("Destination host is empty.")
    if is_ip_literal(text):
        return [str(ipaddress.ip_address(text))]
    try:
        infos = socket.getaddrinfo(text, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise AddressPolicyError(f"Could not resolve host {text!r}: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        candidate = str(info[4][0])
        if candidate not in addresses:
            addresses.append(candidate)
    if not addresses:
        raise AddressPolicyError(f"Host {text!r} did not resolve to any address.")
    return addresses


def address_error(address: ipaddress.IPv4Address | ipaddress.IPv6Address, *, lab: bool) -> str | None:
    """Return a human reason if `address` is blocked by policy, else None."""
    categories = classify_ip(address)
    blocked = [c for c in categories if c in ALWAYS_BLOCKED]
    if blocked:
        return f"address {address} is a blocked range ({', '.join(blocked)})"
    if not lab:
        private = [c for c in categories if c in LAB_ONLY]
        if private:
            return (
                f"address {address} is {', '.join(private)}; set \"lab\": true on the "
                "target to authorize private/loopback/reserved lab targets"
            )
    return None


def check_host(host: str, *, lab: bool) -> list[str]:
    """Resolve `host` and verify **every** resolved address satisfies the policy.

    Returns the validated IP strings. This is the DNS-rebinding guard: a host that
    resolves to any blocked address is rejected outright.
    """
    addresses = resolve_addresses(host)
    for candidate in addresses:
        problem = address_error(ipaddress.ip_address(candidate), lab=lab)
        if problem:
            raise AddressPolicyError(f"Refused destination {host!r}: {problem}.")
    return addresses
