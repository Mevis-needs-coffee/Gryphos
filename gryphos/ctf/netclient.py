"""Bounded, scope-pinned TCP client for the network CTF tools (Phase 4).

All network connections flow through `NetClient` so the connection budget, rate
limit, per-connect timeout, and destination/port authorization behave identically
across tools. The client never opens a socket without first asking `NetScope` to
authorize the host and port, and it connects to the **validated IP** (resolved and
policy-checked up front) rather than re-resolving mid-scan.

Safety properties enforced here:
- every destination host resolves to addresses that all pass the IP policy; the
  scan then connects only to those validated addresses (DNS-rebinding guard);
- a per-run connection budget and optional min-interval rate limit bound the
  total activity; a wall-clock deadline bounds the whole scan;
- a bounded worker pool caps concurrency; per-connect timeout caps each attempt;
- transport errors are recorded as data, never raised, so the solver sees them;
- banner bytes are read with a hard cap and sanitized before display.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass

from .netscope import NetScope, NetScopeError

DEFAULT_MAX_WORKERS = 64
MAX_MAX_WORKERS = 128
MAX_BANNER_BYTES = 2048
DEFAULT_READ_TIMEOUT_MS = 1200

# Well-known port → likely service name (a hint, never authoritative).
SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2181: "zookeeper",
    3000: "http-alt", 3306: "mysql", 3389: "rdp", 4443: "https-alt", 5000: "http-alt",
    5432: "postgres", 5900: "vnc", 5985: "winrm", 6379: "redis", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}


class NetClientError(RuntimeError):
    """Raised for client misuse or exhausted bounds (never for transport errors)."""


@dataclass
class PortResult:
    port: int
    state: str  # open | closed | filtered | error
    host: str = ""
    resolved_ip: str = ""
    service: str = ""
    banner: str = ""
    elapsed_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "host": self.host,
            "resolved_ip": self.resolved_ip,
            "service": self.service,
            "banner": self.banner,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }


def _sanitize_banner(data: bytes) -> str:
    """Keep printable ASCII, collapse control characters, cap length."""
    text = data.decode("utf-8", errors="replace")
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(cleaned.split())[:400]


def service_hint(port: int, banner: str = "") -> str:
    """Best-effort service name from the port and any banner text."""
    low = (banner or "").lower()
    if "ssh-" in low:
        return "ssh"
    if low.startswith("http") or "server:" in low:
        return "http"
    if "smtp" in low or "esmtp" in low:
        return "smtp"
    if "ftp" in low:
        return "ftp"
    if "mysql" in low:
        return "mysql"
    if "redis" in low:
        return "redis"
    return SERVICE_NAMES.get(port, "")


class NetClient:
    """A single-run, bounded TCP client bound to one `NetScope`."""

    def __init__(
        self,
        scope: NetScope,
        *,
        max_workers: int = DEFAULT_MAX_WORKERS,
        read_timeout_ms: int = DEFAULT_READ_TIMEOUT_MS,
    ):
        self.scope = scope
        self.max_workers = max(1, min(int(max_workers), MAX_MAX_WORKERS))
        self.read_timeout_ms = max(100, int(read_timeout_ms))
        self._count = 0
        self._last_ts = 0.0
        self._lock = threading.Lock()

    @property
    def connection_count(self) -> int:
        return self._count

    @property
    def remaining(self) -> int:
        return max(0, self.scope.max_connections - self._count)

    # -- core operations --------------------------------------------------

    def connect_probe(self, port: int, *, grab_banner: bool = True, resolved_ip: str | None = None) -> PortResult:
        """Attempt one TCP connection to `port` and optionally read a banner."""
        port = self.scope.authorize_port(port)
        host = self.scope.target_host
        started = time.monotonic()
        if resolved_ip is None:
            addresses = self.scope.resolve_destination(host)
            resolved_ip = addresses[0]
        self._throttle()
        self._spend()
        timeout = self.scope.connect_timeout_ms / 1000.0
        result = PortResult(port=port, state="closed", host=host, resolved_ip=resolved_ip)
        try:
            with socket.create_connection((resolved_ip, port), timeout=timeout) as sock:
                result.state = "open"
                result.service = SERVICE_NAMES.get(port, "")
                if grab_banner:
                    result.banner = self._grab_banner(sock)
                    result.service = service_hint(port, result.banner) or result.service
        except TimeoutError:
            result.state = "filtered"
            result.error = "timeout"
        except ConnectionRefusedError:
            result.state = "closed"
        except OSError as exc:
            result.state = "error"
            result.error = f"{type(exc).__name__}: {exc}"
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        return result

    def scan(
        self,
        ports: list[int],
        *,
        grab_banner: bool = True,
        deadline_seconds: float = 60.0,
    ) -> dict:
        """Concurrent bounded connect scan; returns open ports and the full map."""
        host = self.scope.target_host
        addresses = self.scope.resolve_destination(host)
        resolved_ip = addresses[0]
        allowed = [self.scope.authorize_port(p) for p in ports]
        results: dict[int, PortResult] = {}
        if self.remaining <= 0:
            raise NetClientError(
                f"Connection budget exhausted ({self.scope.max_connections} connections)."
            )
        submitted = allowed[: self.remaining]
        deadline = time.monotonic() + max(1.0, float(deadline_seconds))
        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures = {}
        try:
            for port in submitted:
                futures[executor.submit(self.connect_probe, port, grab_banner=grab_banner,
                                        resolved_ip=resolved_ip)] = port
            for future in futures:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    result = future.result(timeout=remaining)
                except FuturesTimeout:
                    break
                except Exception as exc:  # noqa: BLE001 - a failing worker must not abort the scan
                    result = PortResult(port=futures[future], state="error",
                                        host=host, resolved_ip=resolved_ip,
                                        error=f"{type(exc).__name__}: {exc}")
                results[result.port] = result
        finally:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
        open_ports = [r for r in sorted(results.values(), key=lambda r: r.port) if r.state == "open"]
        return {"host": host, "results": results, "open_ports": open_ports, "resolved_ip": resolved_ip}

    # -- internals --------------------------------------------------------

    def _grab_banner(self, sock: socket.socket) -> str:
        try:
            sock.settimeout(self.read_timeout_ms / 1000.0)
            data = sock.recv(MAX_BANNER_BYTES)
        except OSError:
            return ""
        return _sanitize_banner(data)

    def _throttle(self) -> None:
        interval = self.scope.min_interval_ms / 1000.0
        if interval <= 0:
            return
        with self._lock:
            wait = interval - (time.monotonic() - self._last_ts)
            if wait > 0:
                time.sleep(wait)
            self._last_ts = time.monotonic()

    def _spend(self) -> None:
        with self._lock:
            if self._count >= self.scope.max_connections:
                raise NetClientError(
                    f"Connection budget exhausted ({self.scope.max_connections} connections). "
                    "Stop and reason about the results gathered so far."
                )
            self._count += 1
            self._last_ts = time.monotonic()


def resolve_target_ips(scope: NetScope) -> list[str]:
    """Resolve and policy-check the scope's target (used for reporting)."""
    try:
        return scope.resolve_destination(scope.target_host)
    except NetScopeError:
        return []


__all__ = [
    "MAX_BANNER_BYTES",
    "SERVICE_NAMES",
    "NetClient",
    "NetClientError",
    "PortResult",
    "resolve_target_ips",
    "service_hint",
]
