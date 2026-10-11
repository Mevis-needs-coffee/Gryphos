"""Tool 12 — tcp_banner: Level 3, single-connection service banner read.

The most intrusive tool Gryphos ships by default. It opens exactly one TCP
connection to a literal in-scope IP and reads whatever the service volunteers
without being prompted (no payload is ever sent), under a tight timeout and
output bound. The connected peer address is re-validated against scope after
the connect. Requires explicit operator approval (Level 3).
"""

from __future__ import annotations

import contextlib
import socket
from datetime import UTC, datetime

from ..scope import validate_connected_peer, validate_port, validate_target
from .base import ToolResult, ToolSpec, duration_since

MAX_READ_BYTES = 2048


def _run_tcp_banner(
    target: str,
    port: int,
    scope_items: tuple[str, ...],
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    safe_target = validate_target(target, scope_items)
    safe_port = validate_port(port)
    read_timeout = max(1, min(timeout, 10))
    read_limit = max(1, min(max_output_chars, MAX_READ_BYTES))
    display = f"TCP banner read {safe_target}:{safe_port} (single connect, no payload)"
    started = datetime.now(UTC)

    try:
        sock = socket.create_connection((safe_target, safe_port), timeout=read_timeout)
        try:
            peer = str(sock.getpeername()[0])
        except OSError:
            peer = safe_target
        try:
            validate_connected_peer(peer, scope_items)
        except Exception:
            sock.close()
            raise
        sock.settimeout(read_timeout)
        try:
            raw = sock.recv(read_limit + 1)
        except TimeoutError:
            raw = b""
        finally:
            with contextlib.suppress(OSError):
                sock.close()
    except Exception as exc:  # noqa: BLE001 - single defensive boundary for socket I/O
        return ToolResult(
            tool="tcp_banner", target=safe_target, display=display, returncode=None,
            output=(
                f"TCP connect/banner read failed: {type(exc).__name__}"
                + (f": {exc}" if str(exc) else "")
            ),
            network_active=True, activity="active",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data={"port": safe_port},
            error=type(exc).__name__,
        )

    truncated = len(raw) > read_limit
    body = raw[:read_limit].decode("utf-8", errors="replace")
    banner = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "." for ch in body)
    if not banner:
        output = f"No unprompted banner received from {safe_target}:{safe_port} within {read_timeout}s."
    else:
        output = banner
    return ToolResult(
        tool="tcp_banner", target=safe_target, display=display, returncode=0,
        output=output[:max_output_chars], network_active=True, activity="active",
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={
            "port": safe_port,
            "peer": peer,
            "banner": banner,
            "bytes_read": len(raw),
            "truncated": truncated,
            "payload_sent": False,
        },
    )


def show_tcp_banner_action(args: dict) -> str:
    return (
        f"TCP banner read {args.get('target', '?')}:{args.get('port', '?')} "
        "(single connect, no payload)"
    )


def tcp_banner_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="tcp_banner",
        description=(
            "Open exactly one TCP connection to a literal in-scope IP:port and "
            "read the service's unprompted banner (no payload is sent). Tighter "
            "timeout and output bounds than a scan. Useful to confirm a service "
            "that a prior check identified. The connected peer is re-validated "
            "against scope."
        ),
        purpose="Confirm a listening service identity by reading its banner on an authorized host.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Literal in-scope IP"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            },
            "required": ["target", "port"],
            "additionalProperties": False,
        },
        risk="medium",
        side_effects=(
            "Opens one TCP connection to the target and reads an unprompted "
            "banner; sends no payload."
        ),
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 10),
        max_output_chars=min(out_limit, MAX_READ_BYTES),
        activity="active",
        approval_level=3,
        scope_requirements=(
            "Literal IP inside GRYPHOS_ALLOWED_TARGETS; the connected peer address "
            "is re-validated against scope after connecting."
        ),
        result_schema={"type": "object", "properties": {
            "port": {"type": "integer"},
            "peer": {"type": "string"},
            "banner": {"type": "string"},
            "bytes_read": {"type": "integer"},
            "truncated": {"type": "boolean"},
            "payload_sent": {"type": "boolean"},
        }},
        show=show_tcp_banner_action,
        execute=lambda args, scope_items, evidence=None: _run_tcp_banner(
            str(args.get("target", "")),
            validate_port(args.get("port", 0)),
            scope_items,
            min(timeout, 10),
            out_limit,
        ),
    )
