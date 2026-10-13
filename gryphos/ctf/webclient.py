"""Bounded, scope-pinned HTTP client for the web CTF tools (Phase 3).

All web traffic flows through `WebClient` so timeouts, response-size limits,
request budgets, rate limiting, redirect handling, and credential redaction
behave identically across tools. The client never issues a request without first
asking `WebScope` to authorize it, and it connects to the *validated* IP while
keeping the original host for the Host header and TLS SNI — so a resolved
destination can never silently differ from the one that was checked.

Safety properties enforced here:
- methods are restricted to GET/HEAD/POST/OPTIONS (never PUT/PATCH/DELETE/etc.);
- per-run request budget (`WebConfig.max_requests`) and optional min-interval
  rate limit; identical requests are served from an in-run cache unless a
  deliberate comparison asks otherwise;
- every response body is read with a hard byte cap and reported truncated;
- transport errors are returned as data, never raised, so the solver records them;
- cookies, authorization headers, and sensitive query/body values are redacted
  before anything reaches evidence, the model, or a report.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import ssl
import time
from dataclasses import dataclass, field, replace
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..logging_setup import redact
from .webscope import WebScope, WebScopeError, WebTarget

USER_AGENT = "Gryphos-CTF/1.0 (authorized CTF challenge solver)"
DEFAULT_TIMEOUT = 15
MAX_RETRIES = 1
MAX_HEADERS = 100
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS"})
RETRYABLE_STATUSES = frozenset({502, 503, 504})

REDACTED = "***REDACTED***"

# Header names whose values are always redacted before storage/display.
SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-auth-token",
    "x-api-key",
    "x-csrf-token",
    "x-xsrf-token",
})
# Query/form parameter names whose values are redacted.
SENSITIVE_PARAMS = frozenset({
    "token", "access_token", "id_token", "refresh_token", "auth", "authorization",
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "key", "session",
    "sessionid", "sid", "csrf", "csrf_token", "signature", "sig",
})


class WebClientError(RuntimeError):
    """Raised for client misuse or exhausted bounds (never for transport errors)."""


@dataclass
class WebResponse:
    method: str
    url: str
    status: int = 0
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    body_length: int = 0
    body_truncated: bool = False
    content_type: str = ""
    resolved_ip: str = ""
    elapsed_ms: int = 0
    redirect: str | None = None
    reused: bool = False
    attempts: int = 1
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def header_map(self) -> dict[str, str]:
        """Last-wins mapping (duplicates e.g. Set-Cookie are joined for display)."""
        out: dict[str, str] = {}
        for key, value in self.headers:
            lowered = key.lower()
            out[lowered] = f"{out[lowered]}, {value}" if lowered in out else value
        return out

    def to_dict(self, *, redacted: bool = True) -> dict:
        headers = redact_headers(self.headers) if redacted else list(self.headers)
        body = redact(self.body) if redacted else self.body
        return {
            "method": self.method,
            "url": redact_url(self.url) if redacted else self.url,
            "status": self.status,
            "reason": self.reason,
            "content_type": self.content_type,
            "headers": [{"name": k, "value": v} for k, v in headers],
            "body": body,
            "body_length": self.body_length,
            "body_truncated": self.body_truncated,
            "resolved_ip": self.resolved_ip,
            "elapsed_ms": self.elapsed_ms,
            "redirect": redact_url(self.redirect) if (redacted and self.redirect) else self.redirect,
            "reused": self.reused,
            "attempts": self.attempts,
            "error": self.error,
        }


# --- redaction helpers ------------------------------------------------------

def _redact_set_cookie(value: str) -> str:
    parts = value.split(";")
    out = []
    for index, part in enumerate(parts):
        segment = part.strip()
        if index == 0 and "=" in segment:
            name = segment.split("=", 1)[0]
            out.append(f"{name}={REDACTED}")
        else:
            out.append(segment)
    return "; ".join(out)


def redact_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key, value in headers:
        lowered = key.lower()
        if lowered == "set-cookie":
            out.append((key, _redact_set_cookie(value)))
        elif lowered in SENSITIVE_HEADERS:
            out.append((key, REDACTED))
        else:
            out.append((key, redact(value)))
    return out


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    redacted = [(k, REDACTED if k.lower() in SENSITIVE_PARAMS else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted), parts.fragment))


def redact_body(text: str, max_chars: int | None = None) -> str:
    out = redact(text)
    if max_chars is not None and len(out) > max_chars:
        out = out[:max_chars]
    return out


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection pinned to a pre-validated IP (no hidden re-resolution)."""

    def __init__(self, host: str, port: int, resolved_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._resolved_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a validated IP, with SNI + cert verification."""

    def __init__(
        self, host: str, port: int, resolved_ip: str, timeout: float, context: ssl.SSLContext
    ):
        super().__init__(host, port, timeout=timeout, context=context)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._resolved_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def tls_context() -> ssl.SSLContext:
    """A verifying TLS context. Certificate verification is never disabled."""
    return ssl.create_default_context()


@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None


def _domain_match(host: str, domain: str) -> bool:
    host = (host or "").lower()
    domain = (domain or "").lower().lstrip(".")
    return domain == "" or host == domain or host.endswith("." + domain)


def parse_set_cookie(value: str, default_domain: str) -> Cookie | None:
    parts = [p.strip() for p in (value or "").split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, _, cookie_value = parts[0].partition("=")
    name = name.strip()
    if not name:
        return None
    cookie = Cookie(name=name, value=cookie_value.strip(), domain=default_domain)
    for part in parts[1:]:
        key, _, attr = part.partition("=")
        key = key.strip().lower()
        attr = attr.strip()
        if key == "domain" and attr:
            cookie.domain = attr.lstrip(".").lower()
        elif key == "path" and attr:
            cookie.path = attr
        elif key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.http_only = True
        elif key == "samesite" and attr:
            cookie.same_site = attr
    return cookie


class WebClient:
    """A single-run, bounded HTTP client bound to one `WebScope`."""

    def __init__(self, scope: WebScope, *, timeout: int = DEFAULT_TIMEOUT, user_agent: str = USER_AGENT):
        self.scope = scope
        self.timeout = max(1, min(int(timeout), 60))
        self.user_agent = user_agent
        self._count = 0
        self._last_ts = 0.0
        self._cache: dict[str, WebResponse] = {}
        self._cookies: list[Cookie] = []

    @property
    def request_count(self) -> int:
        return self._count

    @property
    def remaining(self) -> int:
        return max(0, self.scope.max_requests - self._count)

    # -- cookies ----------------------------------------------------------

    def store_cookies(self, headers: list[tuple[str, str]], host: str) -> list[Cookie]:
        stored: list[Cookie] = []
        for key, value in headers:
            if key.lower() != "set-cookie":
                continue
            cookie = parse_set_cookie(value, host)
            if cookie is None:
                continue
            self._cookies = [
                c for c in self._cookies
                if not (c.name == cookie.name and c.domain == cookie.domain and c.path == cookie.path)
            ]
            self._cookies.append(cookie)
            stored.append(cookie)
        return stored

    def clear_cookies(self) -> None:
        self._cookies = []

    def cookie_header(self, target: WebTarget) -> str | None:
        pairs = [
            f"{c.name}={c.value}"
            for c in self._cookies
            if _domain_match(target.host, c.domain)
            and target.path.startswith(c.path)
            and (not c.secure or target.scheme == "https")
        ]
        return "; ".join(pairs) if pairs else None

    def cookies_snapshot(self) -> list[dict]:
        return [
            {
                "name": c.name,
                "domain": c.domain,
                "path": c.path,
                "secure": c.secure,
                "http_only": c.http_only,
                "same_site": c.same_site,
            }
            for c in self._cookies
        ]

    # -- public API -------------------------------------------------------

    def request(
        self,
        method: str,
        target: WebTarget,
        *,
        headers: dict | None = None,
        body: bytes | None = None,
        allow_repeat: bool = False,
        max_body: int | None = None,
    ) -> WebResponse:
        method = str(method or "").upper()
        if method not in ALLOWED_METHODS:
            raise WebClientError(
                f"HTTP method {method!r} is not allowed; only GET, HEAD, POST, OPTIONS."
            )
        if method in {"GET", "HEAD"} and body:
            raise WebClientError(f"{method} requests must not carry a body.")
        limit = self.scope.max_body_bytes if max_body is None else min(int(max_body), self.scope.max_body_bytes)

        key = self._fingerprint(method, target, headers, body)
        if not allow_repeat and key in self._cache:
            return replace(self._cache[key], reused=True)
        if self._count >= self.scope.max_requests:
            raise WebClientError(
                f"Request budget exhausted ({self.scope.max_requests} requests). "
                "Stop and reason about the evidence gathered so far."
            )
        self._throttle()
        self._count += 1
        self._last_ts = time.monotonic()
        response = self._send_with_retries(method, target, headers, body, limit)
        self._cache[key] = response
        return response

    def request_with_redirects(
        self,
        method: str,
        target: WebTarget,
        *,
        headers: dict | None = None,
        body: bytes | None = None,
        max_hops: int = 5,
        allow_repeat: bool = False,
        max_body: int | None = None,
    ) -> list[WebResponse]:
        """Follow up to `max_hops` redirects, re-authorizing each destination."""
        chain: list[WebResponse] = []
        current = target
        hops = max(1, min(int(max_hops), 10))
        for _ in range(hops + 1):
            response = self.request(
                method, current, headers=headers, body=body,
                allow_repeat=allow_repeat, max_body=max_body,
            )
            chain.append(response)
            if (
                response.ok
                and response.status in REDIRECT_STATUSES
                and response.redirect
                and method in {"GET", "HEAD"}
            ):
                try:
                    current = self.scope.authorize_redirect(response.redirect, current)
                except WebScopeError as exc:
                    response.error = f"redirect blocked: {exc}"
                    break
                continue
            break
        return chain

    # -- internals --------------------------------------------------------

    def _throttle(self) -> None:
        interval = self.scope.min_interval_ms / 1000.0
        if interval <= 0:
            return
        wait = interval - (time.monotonic() - self._last_ts)
        if wait > 0:
            time.sleep(wait)

    def _fingerprint(self, method: str, target: WebTarget, headers: dict | None, body: bytes | None) -> str:
        canonical = json.dumps(
            {
                "m": method,
                "u": target.url,
                "h": sorted((str(k).lower(), str(v)) for k, v in (headers or {}).items()),
                "b": (body or b"").hex(),
                "c": self._cookie_fingerprint(),
            },
            sort_keys=True,
        )
        return canonical

    def _cookie_fingerprint(self) -> str:
        return ";".join(sorted(f"{c.name}={c.value}@{c.domain}{c.path}" for c in self._cookies))

    def _send_with_retries(
        self, method: str, target: WebTarget, headers: dict | None, body: bytes | None, limit: int
    ) -> WebResponse:
        last: WebResponse | None = None
        for attempt in range(1, MAX_RETRIES + 2):
            response = self._send_once(method, target, headers, body, limit)
            response.attempts = attempt
            last = response
            # Retry only idempotent requests failing transiently.
            retry = method in {"GET", "HEAD"} and self._retryable(response) and attempt <= MAX_RETRIES
            if not retry:
                return response
            self._throttle()
        return last or WebResponse(method=method, url=target.url, error="no response")

    @staticmethod
    def _retryable(response: WebResponse) -> bool:
        if response.error is not None:
            return True
        return response.status in RETRYABLE_STATUSES

    def _send_once(
        self, method: str, target: WebTarget, headers: dict | None, body: bytes | None, limit: int
    ) -> WebResponse:
        started = time.monotonic()
        try:
            addresses = self.scope.resolve_destination(target.host)
        except WebScopeError as exc:
            raise WebClientError(str(exc)) from exc
        resolved_ip = addresses[0]
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        for key, value in (headers or {}).items():
            request_headers[str(key)] = str(value)
        if body is not None and "Content-Type" not in request_headers:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if not any(k.lower() == "cookie" for k in request_headers):
            jar_cookie = self.cookie_header(target)
            if jar_cookie:
                request_headers["Cookie"] = jar_cookie
        connection = self._connection(target, resolved_ip)
        try:
            connection.request(method, target.path, body=body, headers=request_headers)
            raw = connection.getresponse()
            status = int(raw.status)
            reason = str(raw.reason or "")
            raw_headers = [(str(k), str(v)) for k, v in raw.getheaders()[:MAX_HEADERS]]
            data = raw.read(limit + 1)
            truncated = len(data) > limit
            data = data[:limit] if truncated else data
        except TimeoutError:
            return self._error(method, target, resolved_ip, started, "timeout")
        except ssl.SSLError as exc:
            return self._error(method, target, resolved_ip, started, f"tls error: {exc}")
        except (http.client.HTTPException, OSError) as exc:
            return self._error(method, target, resolved_ip, started, f"{type(exc).__name__}: {exc}")
        finally:
            with contextlib.suppress(OSError):
                connection.close()

        header_map = {k.lower(): v for k, v in raw_headers}
        content_type = header_map.get("content-type", "").split(";")[0].strip()
        redirect = header_map.get("location")
        self.store_cookies(raw_headers, target.host)
        elapsed = int((time.monotonic() - started) * 1000)
        return WebResponse(
            method=method,
            url=target.url,
            status=status,
            reason=reason,
            headers=raw_headers,
            body=data.decode("utf-8", errors="replace"),
            body_length=len(data),
            body_truncated=truncated,
            content_type=content_type,
            resolved_ip=resolved_ip,
            elapsed_ms=elapsed,
            redirect=redirect,
        )

    def _connection(self, target: WebTarget, resolved_ip: str):
        if target.scheme == "https":
            return _PinnedHTTPSConnection(target.host, target.port, resolved_ip, self.timeout, tls_context())
        return _PinnedHTTPConnection(target.host, target.port, resolved_ip, self.timeout)

    def _error(
        self, method: str, target: WebTarget, resolved_ip: str, started: float, message: str
    ) -> WebResponse:
        return WebResponse(
            method=method,
            url=target.url,
            resolved_ip=resolved_ip,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            error=message,
        )
