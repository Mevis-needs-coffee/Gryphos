"""A tiny, fully-offline mock HTTP server for web-tool tests.

No public target is ever contacted: the server binds 127.0.0.1 on an ephemeral
port and serves routes registered per test. It records every request so tests can
assert on method/path/headers/body and on request counts.
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


@dataclass
class Route:
    status: int = 200
    body: bytes = b""
    headers: list[tuple[str, str]] = field(default_factory=list)
    content_type: str = "text/html; charset=utf-8"
    delay: float = 0.0
    sequence: list[tuple[int, bytes]] | None = None  # cycle (status, body) for retry tests


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence the default stderr logging
        return

    def _dispatch(self, method: str) -> None:
        server: MockWebServer = self.server  # type: ignore[assignment]
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 65536)) if length else b""
        server.requests.append({
            "method": method,
            "path": self.path,
            "route": parts.path,
            "query": parts.query,
            "headers": dict(self.headers.items()),
            "body": body,
        })
        route = server.routes.get(parts.path)
        if callable(route):
            route = route(server, self)  # type: ignore[misc]
        if route is None:
            route = Route(status=404, body=b"not found", content_type="text/plain")
        if route.delay:
            time.sleep(route.delay)
        status, payload = route.status, route.body
        if route.sequence:
            index = server.hits.get(parts.path, 0)
            server.hits[parts.path] = index + 1
            status, payload = route.sequence[min(index, len(route.sequence) - 1)]
        self.send_response(status)
        if route.content_type:
            self.send_header("Content-Type", route.content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in route.headers:
            self.send_header(key, value)
        self.end_headers()
        if method != "HEAD" and payload:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(payload)
        self.close_connection = True

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_POST(self):
        self._dispatch("POST")

    def do_OPTIONS(self):
        self._dispatch("OPTIONS")


class MockWebServer:
    def __init__(self) -> None:
        self.routes: dict[str, Route | object] = {}
        self.requests: list[dict] = []
        self.hits: dict[str, int] = {}
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.routes = self.routes  # type: ignore[attr-defined]
        self._httpd.requests = self.requests  # type: ignore[attr-defined]
        self._httpd.hits = self.hits  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def add(self, path: str, route: Route) -> None:
        self.routes[path] = route

    def html(self, path: str, body: str, status: int = 200) -> None:
        self.add(path, Route(status=status, body=body.encode(), content_type="text/html; charset=utf-8"))

    def json(self, path: str, obj: object, status: int = 200) -> None:
        self.add(path, Route(
            status=status,
            body=json.dumps(obj).encode(),
            content_type="application/json",
        ))

    def redirect(self, path: str, location: str, status: int = 302) -> None:
        self.add(path, Route(status=status, body=b"", headers=[("Location", location)]))

    def __enter__(self) -> MockWebServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def echo_route(server, handler):  # pragma: no cover - used via add(callable)
    payload = json.dumps({"path": handler.path}).encode()
    return Route(status=200, body=payload, content_type="application/json")
