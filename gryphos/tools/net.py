"""Shared, bounded network helpers for active tools.

All HTTP traffic flows through here so that timeouts, response draining, and
destination authorization behave identically across tools. Redirects are never
followed automatically; each hop is re-authorized against the configured
scope, and reserved classes (loopback, link-local, private, cloud metadata)
are only reachable when the scope explicitly permits them.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl

import requests

from ..scope import ScopeError, authorize_url, validate_target

USER_AGENT = "Gryphos/1.0 (authorized security assessment; +local)"


def authorized_destination(
    scheme: str,
    host: str,
    port: int,
    scope_items: tuple[str, ...],
) -> tuple[str, int]:
    """Validate (host, port) against scope; returns the normalized pair."""
    host = validate_target(str(host), scope_items)
    port = int(port)
    if not (1 <= port <= 65535):
        raise ScopeError("Port must be between 1 and 65535.")
    return host, port


def bounded_http_request(
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    timeout: int,
) -> requests.Response:
    """One HTTP request with fixed args; NO automatic redirect following."""
    url = f"{scheme}://{host}:{port}{path}"
    return requests.request(
        method,
        url,
        timeout=timeout,
        allow_redirects=False,
        headers={"User-Agent": USER_AGENT},
        stream=True,
    )


def drain_and_close(response: requests.Response, limit: int) -> str:
    """Read at most `limit` body bytes, then close the connection."""
    try:
        body = response.raw.read(limit if limit > 0 else 1, decode_content=True)
    except Exception:  # noqa: BLE001 - best-effort bounded read from any transport
        body = b""
    finally:
        response.close()
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return body[:limit]


def authorize_redirect(location: str, current: dict, scope_items: tuple[str, ...]) -> dict:
    """Authorize one redirect destination (no DNS, no blind following)."""
    base = f"{current['scheme']}://{current['host']}:{current['port']}{current['path']}"
    target = requests.compat.urljoin(base, location)
    return authorize_url(target, scope_items)


def tls_context() -> ssl.SSLContext:
    """A default, certificate-verifying TLS context. Verification is never disabled."""
    return ssl.create_default_context()


def tls_connect(
    host: str, port: int, connect_name: str, timeout: int,
) -> tuple[ssl.SSLSocket, dict]:
    """Open and wrap a TLS socket with full verification.

    Returns (socket, parsed_peer_cert). Raises ssl.CertificateError on
    hostname/chain failures and OSError on connection failures.
    """
    context = tls_context()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        tls = context.wrap_socket(sock, server_hostname=connect_name)
    except (OSError, ValueError):
        sock.close()
        raise
    return tls, tls.getpeercert() or {}


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None
