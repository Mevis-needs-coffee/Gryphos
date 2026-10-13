"""A tiny, fully-offline mock TCP server for network-tool tests.

No public target is ever contacted: the server binds 127.0.0.1 on an ephemeral
(or requested) port and records every accepted connection so tests can assert on
which ports were actually reached.
"""

from __future__ import annotations

import contextlib
import socket
import threading


class MockTcpServer:
    def __init__(self) -> None:
        self._listeners: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._ports: list[int] = []
        self._stop = threading.Event()
        self.connections: list[int] = []

    def listen(self, banner: bytes = b"", port: int = 0) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(16)
        srv.settimeout(0.2)
        actual = srv.getsockname()[1]
        thread = threading.Thread(target=self._serve, args=(srv, banner), daemon=True)
        thread.start()
        self._listeners.append(srv)
        self._threads.append(thread)
        self._ports.append(actual)
        return actual

    @property
    def ports(self) -> list[int]:
        return list(self._ports)

    def _serve(self, srv: socket.socket, banner: bytes) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections.append(srv.getsockname()[1])
            with contextlib.suppress(OSError):
                if banner:
                    conn.sendall(banner)
            with contextlib.suppress(OSError):
                conn.close()

    def __enter__(self) -> MockTcpServer:
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        for srv in self._listeners:
            with contextlib.suppress(OSError):
                srv.close()
        for thread in self._threads:
            thread.join(timeout=2)
