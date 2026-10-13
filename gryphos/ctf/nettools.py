"""Authorized network CTF tools (Phase 4).

Every tool here is built around a shared `NetScope` + `NetClient`, so all
connections obey the operator-authorized target, the declared port range, the
connection budget, and the rate/time bounds configured for the challenge. Tools
never act on a host other than the one the operator declared.

- `net_portscan`  — bounded TCP connect scan; reports open/closed/filtered ports.
- `net_service_probe` — banner grab and service hints on specific (or discovered) ports.
- `net_http_probe` — bounded HTTP(S) request(s) to the target and its redacted response.
- `net_clues` — offline (no network) prioritization of the network evidence so far.
"""

from __future__ import annotations

import contextlib
import time
from datetime import UTC, datetime

from ..tools.base import ToolError, ToolResult, ToolSpec, duration_since
from .flag import FlagFormat
from .netclient import NetClient, NetClientError, PortResult
from .netconfig import TOP_PORTS
from .netscope import NetScope, NetScopeError
from .sandbox import attach_flags
from .webclient import (
    MAX_HEADERS,
    WebResponse,
    _PinnedHTTPConnection,
    _PinnedHTTPSConnection,
    tls_context,
)
from .webtools import attach_flags_from

MAX_HTTP_PATHS = 12
MAX_HTTP_BODY = 262144
MAX_LIST_ITEMS = 60
NET_HTTP_USER_AGENT = "Gryphos-CTF/1.0 (authorized network challenge solver)"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


# --- helpers ----------------------------------------------------------------

def _http_scheme(port: int, requested: object = None) -> str:
    if requested in ("http", "https"):
        return str(requested)
    return "https" if port in {443, 8443, 4443} else "http"


def _authorize_ports(scope: NetScope, raw: object, evidence: list[dict] | None) -> list[int]:
    """Resolve a requested port spec, or fall back to ports discovered earlier."""
    if raw:
        try:
            return scope.authorize_ports(raw)
        except NetScopeError as exc:
            raise ToolError(str(exc)) from exc
    discovered = _discovered_ports(evidence or [])
    if discovered:
        return discovered
    try:
        return scope.authorize_ports(scope.default_ports)
    except NetScopeError as exc:
        raise ToolError(str(exc)) from exc


def _discovered_ports(evidence: list[dict]) -> list[int]:
    ports: list[int] = []
    for item in evidence:
        if item.get("kind") != "tool_result":
            continue
        data = item.get("data") or {}
        if not isinstance(data, dict):
            continue
        for entry in data.get("open_ports") or []:
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("port"), int)
                and entry["port"] not in ports
            ):
                ports.append(entry["port"])
        for entry in data.get("services") or []:
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("port"), int)
                and entry["port"] not in ports
            ):
                ports.append(entry["port"])
    return sorted(ports)[:MAX_LIST_ITEMS]


def _render_scan(payload: dict, out_limit: int) -> str:
    results: dict[int, PortResult] = payload["results"]
    open_ports: list[PortResult] = payload["open_ports"]
    counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
    for result in results.values():
        counts[result.state] = counts.get(result.state, 0) + 1
    lines = [
        f"TCP connect scan of {payload['host']} ({payload['resolved_ip']}), "
        f"{len(results)} port(s) probed.",
        f"Summary: {counts['open']} open, {counts['closed']} closed, "
        f"{counts['filtered']} filtered, {counts['error']} error.",
        "",
    ]
    if open_ports:
        lines.append("Open ports:")
        for result in open_ports:
            svc = f" {result.service}" if result.service else ""
            line = f"  {result.port}/tcp open{svc} ({result.elapsed_ms} ms)"
            if result.banner:
                line += f"  banner: {result.banner}"
            lines.append(line)
    else:
        lines.append("No open ports found in the scanned range.")
    errored = [r for r in results.values() if r.state == "error"]
    if errored:
        lines.append("")
        lines.append("Errors:")
        lines.extend(f"  {r.port}: {r.error}" for r in errored[:20])
    return "\n".join(lines)[:out_limit]


def net_portscan_spec(
    scope: NetScope, client: NetClient, fmt: FlagFormat, timeout: int, out_limit: int
) -> ToolSpec:
    def _run(args, scope_items, evidence=None) -> ToolResult:
        started = datetime.now(UTC)
        top = bool(args.get("top"))
        banner = bool(args.get("banner", True))
        raw_ports = args.get("ports")
        if top and not raw_ports:
            ports = list(TOP_PORTS)[: scope.max_ports]
        else:
            ports = _authorize_ports(scope, raw_ports, evidence)
        try:
            payload = client.scan(ports, grab_banner=banner, deadline_seconds=min(timeout, 60))
        except (NetClientError, NetScopeError) as exc:
            raise ToolError(str(exc)) from exc
        open_ports = payload["open_ports"]
        output = _render_scan(payload, out_limit)
        data = {
            "host": scope.target_host,
            "resolved_ip": payload["resolved_ip"],
            "scanned": len(payload["results"]),
            "ports": ports,
            "open_ports": [r.to_dict() for r in open_ports],
            "results": [r.to_dict() for r in sorted(payload["results"].values(), key=lambda r: r.port)],
            "used_connections": client.connection_count,
            "remaining_connections": client.remaining,
        }
        result = ToolResult(
            tool="net_portscan",
            target=scope.target_host,
            display=(
                f"net_portscan({scope.target_host}, "
                + ("top-ports" if top and not raw_ports else f"ports={raw_ports or scope.default_ports}")
                + ")"
            ),
            returncode=0,
            output=output,
            network_active=True,
            activity="active",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=data,
        )
        return attach_flags_from(result, fmt, [r.banner for r in payload["results"].values()])

    return ToolSpec(
        name="net_portscan",
        description=(
            "TCP connect scan of the operator-authorized target: probe a port range (or a "
            "quick set of common ports with top=true) and report which ports are open, "
            "closed, or filtered. Optionally reads a service banner from each open port. "
            "Bounded by the declared port maximum, connection budget, and a wall-clock "
            "deadline. Only the authorized target is ever contacted."
        ),
        purpose="Discover which services are reachable on the target.",
        input_schema={
            "type": "object",
            "properties": {
                "ports": {
                    "type": "string",
                    "description": (
                        "Port spec, e.g. \"1-1024\", \"22,80,443\", or \"1-65535\" (bounded "
                        f"to the configured max of {scope.max_ports}). Defaults to the "
                        "challenge's declared range."
                    ),
                },
                "top": {
                    "type": "boolean",
                    "description": "Scan a built-in set of common ports instead of `ports` (default false).",
                },
                "banner": {
                    "type": "boolean",
                    "description": "Read a short banner from each open port (default true).",
                },
            },
            "additionalProperties": False,
        },
        risk="medium",
        side_effects="Opens bounded TCP connections to the authorized target only; changes no state.",
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 60),
        max_output_chars=out_limit,
        activity="active",
        approval_level=2,
        scope_requirements="Single authorized target; bounded by port max, connection budget, and rate.",
        result_schema={
            "type": "object",
            "properties": {"open_ports": {"type": "array"}, "scanned": {"type": "integer"}},
        },
        show=lambda args: (
            f"net_portscan({scope.target_host}, "
            + ("top" if args.get("top") else f"ports={args.get('ports') or scope.default_ports}")
            + ")"
        ),
        execute=_run,
    )


def net_service_probe_spec(
    scope: NetScope, client: NetClient, fmt: FlagFormat, timeout: int, out_limit: int
) -> ToolSpec:
    def _run(args, scope_items, evidence=None) -> ToolResult:
        started = datetime.now(UTC)
        raw_ports = args.get("ports")
        ports = _authorize_ports(scope, raw_ports, evidence)
        services: list[PortResult] = []
        for port in ports[:MAX_LIST_ITEMS]:
            try:
                services.append(client.connect_probe(port, grab_banner=True))
            except (NetClientError, NetScopeError) as exc:
                raise ToolError(str(exc)) from exc
        lines = [
            f"Service probe of {scope.target_host}: {len(services)} port(s).",
            "",
        ]
        for result in services:
            svc = result.service or "unknown"
            line = f"  {result.port}/tcp {result.state} — {svc} ({result.elapsed_ms} ms)"
            lines.append(line)
            if result.banner:
                lines.append(f"      banner: {result.banner}")
            if result.error:
                lines.append(f"      error: {result.error}")
        data = {
            "host": scope.target_host,
            "services": [r.to_dict() for r in services],
            "used_connections": client.connection_count,
            "remaining_connections": client.remaining,
        }
        result = ToolResult(
            tool="net_service_probe",
            target=scope.target_host,
            display=f"net_service_probe({scope.target_host}, ports={raw_ports or 'discovered'})",
            returncode=0,
            output="\n".join(lines)[:out_limit],
            network_active=True,
            activity="active",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=data,
        )
        return attach_flags_from(result, fmt, [r.banner for r in services])

    return ToolSpec(
        name="net_service_probe",
        description=(
            "Connect to specific ports on the authorized target and read a short banner to "
            "fingerprint the service and version. Defaults to the ports already found open. "
            "Useful for confirming what a discovered port actually speaks."
        ),
        purpose="Fingerprint the services on discovered ports.",
        input_schema={
            "type": "object",
            "properties": {
                "ports": {
                    "type": "string",
                    "description": "Port spec to probe; defaults to the ports discovered so far.",
                },
            },
            "additionalProperties": False,
        },
        risk="medium",
        side_effects="Opens bounded TCP connections to the authorized target only; changes no state.",
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 45),
        max_output_chars=out_limit,
        activity="active",
        approval_level=2,
        scope_requirements="Single authorized target; bounded by connection budget and rate.",
        result_schema={
            "type": "object",
            "properties": {"services": {"type": "array"}},
        },
        show=lambda args: f"net_service_probe({scope.target_host}, ports={args.get('ports') or 'discovered'})",
        execute=_run,
    )


def _http_once(
    scheme: str, host: str, ip: str, port: int, method: str, path: str, timeout: int, limit: int
) -> WebResponse:
    started = time.monotonic()
    request_headers = {
        "User-Agent": NET_HTTP_USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    connection = (
        _PinnedHTTPSConnection(host, port, ip, timeout, tls_context())
        if scheme == "https"
        else _PinnedHTTPConnection(host, port, ip, timeout)
    )
    try:
        connection.request(method, path, headers=request_headers)
        raw = connection.getresponse()
        status = int(raw.status)
        raw_headers = [(str(k), str(v)) for k, v in raw.getheaders()[:MAX_HEADERS]]
        data = raw.read(limit + 1)
        truncated = len(data) > limit
        data = data[:limit] if truncated else data
    except TimeoutError:
        return WebResponse(method=method, url=f"{scheme}://{host}:{port}{path}",
                           resolved_ip=ip, error="timeout")
    except OSError as exc:
        return WebResponse(method=method, url=f"{scheme}://{host}:{port}{path}",
                           resolved_ip=ip, error=f"{type(exc).__name__}: {exc}")
    finally:
        with contextlib.suppress(OSError):
            connection.close()
    header_map = {k.lower(): v for k, v in raw_headers}
    return WebResponse(
        method=method,
        url=f"{scheme}://{host}:{port}{path}",
        status=status,
        reason=str(raw.reason or ""),
        headers=raw_headers,
        body=data.decode("utf-8", errors="replace"),
        body_length=len(data),
        body_truncated=truncated,
        content_type=header_map.get("content-type", "").split(";")[0].strip(),
        resolved_ip=ip,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        redirect=header_map.get("location"),
    )


def net_http_probe_spec(
    scope: NetScope, client: NetClient, fmt: FlagFormat, timeout: int, out_limit: int
) -> ToolSpec:
    def _run(args, scope_items, evidence=None) -> ToolResult:
        started = datetime.now(UTC)
        port = scope.authorize_port(int(args.get("port") or 80))
        scheme = _http_scheme(port, args.get("scheme"))
        method = str(args.get("method") or "GET").upper()
        if method not in {"GET", "HEAD"}:
            raise ToolError("Only GET and HEAD are allowed for HTTP probing.")
        raw_paths = args.get("paths")
        if isinstance(raw_paths, list) and raw_paths:
            paths = [str(p) for p in raw_paths][:MAX_HTTP_PATHS]
        else:
            paths = [str(args.get("path") or "/")]
        try:
            ip = scope.resolve_destination(scope.target_host)[0]
        except NetScopeError as exc:
            raise ToolError(str(exc)) from exc
        responses: list[WebResponse] = []
        for raw_path in paths:
            path = raw_path if raw_path.startswith("/") else "/" + raw_path
            responses.append(
                _http_once(scheme, scope.target_host, ip, port, method, path, timeout, MAX_HTTP_BODY)
            )
        lines = [f"HTTP probe {method} {scope.target_host}:{port} ({len(responses)} path(s))", ""]
        for response in responses:
            item = response.to_dict(redacted=True)
            status = f"{item['status']} {item['reason']}".strip()
            lines.append(
                f"[{item['url']}] -> {status or '(no response)'} "
                f"({item['content_type'] or '?'}, {item['body_length']}B)"
            )
            if item["error"]:
                lines.append(f"    error: {item['error']}")
            if item["redirect"]:
                lines.append(f"    location: {item['redirect']}")
            for header in item["headers"][:MAX_HEADERS]:
                lines.append(f"    {header['name']}: {header['value']}")
            if item["body"]:
                lines.append("    body:")
                lines.append("    " + item["body"][:1500].replace("\n", "\n    "))
            lines.append("")
        data = {
            "host": scope.target_host,
            "port": port,
            "scheme": scheme,
            "method": method,
            "responses": [r.to_dict(redacted=True) for r in responses],
            "final_status": responses[-1].status if responses else 0,
            "final_error": responses[-1].error if responses else None,
        }
        result = ToolResult(
            tool="net_http_probe",
            target=f"{scheme}://{scope.target_host}:{port}",
            display=f"net_http_probe({method} {scope.target_host}:{port}, paths={len(paths)})",
            returncode=responses[-1].status if responses and responses[-1].ok else None,
            output="\n".join(lines)[:out_limit],
            network_active=True,
            activity="active",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=data,
            error=responses[-1].error if responses else None,
        )
        return attach_flags_from(result, fmt, [r.body for r in responses])

    return ToolSpec(
        name="net_http_probe",
        description=(
            "Send bounded GET/HEAD requests to an HTTP(S) service on the authorized target "
            "and show the redacted status, headers, and body. Provide several `paths` to "
            "check common endpoints in one step. Cookies/tokens in the response are redacted. "
            "Only the authorized target is contacted."
        ),
        purpose="Inspect an HTTP(S) service discovered on the target.",
        input_schema={
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1, "maximum": 65535,
                         "description": "Target port (default 80)."},
                "scheme": {"type": "string", "enum": ["http", "https"],
                           "description": "Defaults to https on 443/8443/4443 else http."},
                "method": {"type": "string", "enum": ["GET", "HEAD"], "description": "Default GET."},
                "path": {"type": "string", "description": "Single path to request (default /)."},
                "paths": {"type": "array", "items": {"type": "string"},
                          "description": f"Up to {MAX_HTTP_PATHS} paths to request in one step."},
            },
            "additionalProperties": False,
        },
        risk="medium",
        side_effects="Issues bounded GET/HEAD requests to the authorized target only.",
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 45),
        max_output_chars=out_limit,
        activity="active",
        approval_level=2,
        scope_requirements="Single authorized target; bounded by path count and response size.",
        result_schema={
            "type": "object",
            "properties": {"responses": {"type": "array"}, "port": {"type": "integer"}},
        },
        show=lambda args: (
            f"net_http_probe({args.get('method', 'GET')} {scope.target_host}:{args.get('port', 80)})"
        ),
        execute=_run,
    )


# --- offline clue synthesis -------------------------------------------------

_NET_KEYWORDS = (
    ("flag", 5),
    ("admin", 4),
    ("root", 3),
    ("anonymous", 3),
    ("default", 3),
    ("backup", 3),
    ("config", 2),
    ("secret", 3),
    ("password", 2),
    ("passwd", 2),
    ("token", 2),
    ("private", 2),
    ("internal", 2),
    ("debug", 3),
    ("upload", 2),
    ("login", 1),
    ("smtp", 2),
    ("ftp", 2),
    ("ssh", 2),
    ("mysql", 2),
    ("redis", 2),
    ("mongodb", 2),
    ("nfs", 3),
    ("smb", 3),
    ("version", 2),
    ("beta", 2),
    ("test", 1),
    ("dev", 2),
)


def _score_net_text(text: str) -> tuple[int, list[str]]:
    low = (text or "").lower()
    matched = [kw for kw, _ in _NET_KEYWORDS if kw in low]
    score = sum(weight for kw, weight in _NET_KEYWORDS if kw in low)
    return score, matched


def _add_net_clue(clues: dict, kind: str, value: str, source: str) -> None:
    value = (value or "").strip()
    if not value:
        return
    key = (kind, value)
    if key in clues:
        return
    score, matched = _score_net_text(value)
    reason = f"matched: {', '.join(matched)}" if matched else "observed"
    clues[key] = {"kind": kind, "value": value, "priority": score, "source": source, "reason": reason}


def collect_net_clues(evidence: list[dict]) -> tuple[dict, dict]:
    clues: dict[tuple[str, str], dict] = {}
    meta: dict = {"open_ports": [], "services": [], "http_paths": [], "banner_hints": []}
    for item in evidence or []:
        if item.get("kind") != "tool_result":
            continue
        tool = str(item.get("tool") or "")
        if not tool.startswith("net_"):
            continue
        data = item.get("data") or {}
        if not isinstance(data, dict):
            continue
        source = str(item.get("command") or tool)
        for entry in data.get("open_ports") or []:
            if not isinstance(entry, dict):
                continue
            port = entry.get("port")
            service = str(entry.get("service") or "")
            if isinstance(port, int):
                label = f"{port}/{service}" if service else str(port)
                if label not in meta["open_ports"]:
                    meta["open_ports"].append(label)
                _add_net_clue(clues, "port", label, source)
                if entry.get("banner"):
                    banner = str(entry["banner"])
                    meta["banner_hints"].append(banner)
                    _add_net_clue(clues, "banner", banner, source)
        for entry in data.get("services") or []:
            if not isinstance(entry, dict):
                continue
            port = entry.get("port")
            service = str(entry.get("service") or "")
            if isinstance(port, int):
                label = f"{port}/{service}" if service else str(port)
                if label not in meta["services"]:
                    meta["services"].append(label)
                _add_net_clue(clues, "service", label, source)
            if entry.get("banner"):
                banner = str(entry["banner"])
                meta["banner_hints"].append(banner)
                _add_net_clue(clues, "banner", banner, source)
        for response in data.get("responses") or []:
            if not isinstance(response, dict):
                continue
            url = str(response.get("url") or "")
            if url:
                meta["http_paths"].append(url)
                _add_net_clue(clues, "endpoint", url, source)
    return clues, meta


def net_clues_spec(fmt: FlagFormat, out_limit: int) -> ToolSpec:
    def _run(args, scope_items, evidence=None) -> ToolResult:
        started = datetime.now(UTC)
        max_items = int(args.get("max_items") or 20)
        focus = str(args.get("focus") or "").strip().lower()
        clues, meta = collect_net_clues(list(evidence or []))
        entries = list(clues.values())
        if focus:
            for entry in entries:
                if focus in entry["value"].lower():
                    entry["priority"] += 1
                    entry["reason"] += f"; matches focus '{focus}'"
        entries.sort(key=lambda e: (-e["priority"], e["kind"], e["value"]))
        entries = entries[:max_items]
        lines = [f"Network clue synthesis: {len(entries)} clue(s)", ""]
        if meta["open_ports"]:
            lines.append("Open ports: " + ", ".join(meta["open_ports"]))
        if meta["services"]:
            lines.append("Fingerprinted services: " + ", ".join(meta["services"]))
        lines.append("Prioritized clues (highest first):")
        for index, entry in enumerate(entries, 1):
            lines.append(
                f"  {index}. [{entry['kind']}] {entry['value']} "
                f"(p={entry['priority']}) — {entry['reason']} ({entry['source']})"
            )
        if not entries:
            lines.append("  (no network clues recorded yet)")
        data = {
            "clues": entries,
            "open_ports": meta["open_ports"],
            "services": meta["services"],
            "http_paths": meta["http_paths"],
            "banner_hints": meta["banner_hints"][:MAX_LIST_ITEMS],
        }
        result = ToolResult(
            tool="net_clues",
            target="(evidence)",
            display="net_clues()",
            returncode=0,
            output="\n".join(lines)[:out_limit],
            network_active=False,
            activity="passive",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=data,
        )
        return attach_flags(result, fmt)

    return ToolSpec(
        name="net_clues",
        description=(
            "Offline synthesis (no network) of the network evidence gathered so far: open "
            "ports, fingerprinted services, banners, and probed HTTP endpoints. Clues are "
            "prioritized by security-relevant keywords so the next step targets the most "
            "promising lead."
        ),
        purpose="Prioritize the next network step from evidence rather than guessing.",
        input_schema={
            "type": "object",
            "properties": {
                "focus": {"type": "string", "description": "Optional keyword to bias ranking."},
                "max_items": {"type": "integer", "minimum": 1, "maximum": 40,
                              "description": "Maximum clues to report (default 20)."},
            },
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: reads evidence already collected; makes no connections.",
        network_active=False,
        approval_policy="none",
        timeout=10,
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="None: local synthesis of recorded evidence.",
        result_schema={"type": "object", "properties": {"clues": {"type": "array"}}},
        show=lambda args: f"net_clues(focus={args.get('focus')!r})" if args.get("focus") else "net_clues()",
        execute=_run,
    )
