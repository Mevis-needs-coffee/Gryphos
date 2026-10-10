"""Tool 2 — HTTP inspection: status, headers, and redirect-chain analysis.

Every destination (including every redirect hop) is validated as a literal
in-scope IP before any connection is made. Redirects are never followed
automatically; off-scope, hostname, reserved, and metadata destinations are
blocked with a scope-policy message.
"""

from __future__ import annotations

from datetime import UTC, datetime

import requests

from ..scope import ScopeError, validate_path, validate_port, validate_target
from .base import ToolResult, ToolSpec, duration_since
from .net import (
    authorize_redirect,
    bounded_http_request,
    drain_and_close,
)

HARDENING_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
INTERESTING_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "content-type",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "set-cookie",
    "www-authenticate",
    "location",
    "x-generator",
    "x-backend-server",
    "x-runtime",
    "x-served-by",
)


def _scheme_of(value: str) -> str:
    if str(value).lower() == "https":
        return "https"
    if str(value).lower() == "http":
        return "http"
    raise ScopeError("scheme must be 'http' or 'https'.")


def _safe_header(key_lower: str, value: str) -> str:
    """Sanitize header values that could carry credentials before they reach
    output, evidence, or the model context (e.g. Set-Cookie)."""
    text = str(value)
    if key_lower != "set-cookie" or "=" not in text:
        return text
    parts = text.split(";")
    left = parts[0].strip()
    if "=" in left:
        name = left.split("=", 1)[0]
        parts[0] = f"{name}=<redacted>"
    return ";".join(parts)[:200]


def _run_http_headers(
    target: str,
    port: int,
    scheme: str,
    scope_items: tuple[str, ...],
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    safe_target = validate_target(target, scope_items)
    safe_port = validate_port(port)
    safe_scheme = _scheme_of(scheme)
    display = f"HTTP HEAD {safe_scheme}://{safe_target}:{safe_port}/ (headers only, no redirects)"
    started = datetime.now(UTC)
    try:
        response = bounded_http_request("HEAD", safe_scheme, safe_target, safe_port, "/", timeout)
        headers = {
            k: _safe_header(k.lower(), v)
            for k, v in response.headers.items()
            if k.lower() in INTERESTING_HEADERS
        }
        _ = drain_and_close(response, 0)
    except requests.RequestException as exc:
        return ToolResult(
            tool="http_headers", target=safe_target, display=display, returncode=None,
            output=f"Request failed: {type(exc).__name__}", network_active=True,
            started_at=started.isoformat(), error=type(exc).__name__,
        )
    status = response.status_code
    reason = getattr(response, "reason", "") or ""
    tech = [
        v for k, v in headers.items()
        if k.lower() in {"server", "x-powered-by", "x-aspnet-version", "x-generator"}
        if v
    ]
    missing = [h for h in HARDENING_HEADERS if h not in {k.lower() for k in headers}]
    lines = [f"HTTP {status} {reason}".strip()]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if missing:
        lines.append("")
        lines.append("Missing hardening headers: " + ", ".join(missing))
    return ToolResult(
        tool="http_headers", target=safe_target, display=display,
        returncode=0, output="\n".join(lines)[:max_output_chars], network_active=True,
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={
            "status_code": status,
            "port": safe_port,
            "headers": headers,
            "technology_hints": tech,
            "missing_hardening_headers": missing,
        },
    )


def _run_http_redirects(
    target: str,
    port: int,
    scheme: str,
    path: str,
    scope_items: tuple[str, ...],
    timeout: int,
    max_output_chars: int,
    max_hops: int = 5,
) -> ToolResult:
    safe_target = validate_target(target, scope_items)
    safe_port = validate_port(port)
    safe_path = validate_path(path)
    safe_scheme = _scheme_of(scheme)
    display = (
        f"HTTP GET {safe_scheme}://{safe_target}:{safe_port}{safe_path} "
        f"(manual redirect tracing, max {max_hops} hops, every hop validated)"
    )
    started = datetime.now(UTC)
    hops: list[dict] = []
    validated: list[dict] = []
    blocked = None
    current = {"scheme": safe_scheme, "host": safe_target, "port": safe_port, "path": safe_path}
    for _hop in range(max_hops + 1):
        try:
            response = bounded_http_request(
                "GET", current["scheme"], current["host"], current["port"], current["path"], timeout,
            )
        except requests.RequestException as exc:
            hops.append({**current, "error": type(exc).__name__})
            break
        status = response.status_code
        location = response.headers.get("Location")
        _ = drain_and_close(response, 0)
        hop_record = {**current, "status": status}
        hops.append(hop_record)
        if status in (301, 302, 303, 307, 308) and location:
            hop_record["location"] = location
            try:
                nxt = authorize_redirect(location, current, scope_items)
            except ScopeError as exc:
                blocked = f"Redirect target blocked by scope policy: {exc}"
                break
            current = {
                "scheme": str(nxt["scheme"]), "host": str(nxt["host"]),
                "port": int(nxt["port"]), "path": str(nxt["path"]),
            }
            validated.append(current)
            continue
        break

    lines = []
    for index, hop in enumerate(hops, 1):
        status = hop.get("status", hop.get("error", "?"))
        lines.append(f"{index}. {hop['scheme']}://{hop['host']}:{hop['port']}{hop['path']} -> {status}")
        if hop.get("location"):
            lines.append(f"   Location: {hop['location']}")
    if blocked:
        lines.append(blocked)
    elif len(hops) > 1:
        lines.append("Chain terminated within scope after re-authorizing every hop.")
    return ToolResult(
        tool="http_redirects", target=safe_target, display=display, returncode=0,
        output="\n".join(lines)[:max_output_chars], network_active=True,
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={
            "hops": hops,
            "port": safe_port,
            "validated_destinations": validated,
            "blocked": blocked,
            "policy": "every redirect hop must be a literal IP inside GRYPHOS_ALLOWED_TARGETS",
        },
    )


def show_http_headers_action(args: dict) -> str:
    scheme = args.get("scheme", "http")
    port = args.get("port", 80)
    return f"HTTP HEAD {scheme}://{args.get('target', '?')}:{port}/ (headers only, no redirects)"


def show_http_redirects_action(args: dict) -> str:
    scheme = args.get("scheme", "http")
    port = args.get("port", 80)
    path = args.get("path", "/")
    return f"HTTP GET {scheme}://{args.get('target', '?')}:{port}{path} (manual redirect tracing)"


def http_headers_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="http_headers",
        description=(
            "Send one HTTP HEAD request to an in-scope literal IP and report "
            "response status, security-relevant headers, technology hints, and "
            "missing hardening headers. No redirect following."
        ),
        purpose="Inspect HTTP response headers for exposure and hardening gaps.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Literal in-scope IP"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "scheme": {"type": "string", "enum": ["http", "https"]},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk="low",
        side_effects="One HTTP HEAD request to the target.",
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="active",
        scope_requirements=(
            "Literal in-scope IP only; reserved/private/metadata destinations "
            "require explicit scope entry."
        ),
        result_schema={"type": "object", "properties": {
            "status_code": {"type": "integer"},
            "headers": {"type": "object"},
            "technology_hints": {"type": "array"},
            "missing_hardening_headers": {"type": "array"},
        }},
        show=show_http_headers_action,
        execute=lambda args, scope_items, evidence=None: _run_http_headers(
            str(args.get("target", "")),
            validate_port(args.get("port", 80)),
            str(args.get("scheme", "http")),
            scope_items,
            min(timeout, 30),
            out_limit,
        ),
    )


def http_redirects_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="http_redirects",
        description=(
            "GET an in-scope literal-IP URL without following redirects "
            "automatically; traces up to 5 redirect hops. Every hop destination "
            "must itself be a literal in-scope IP or the chain is blocked."
        ),
        purpose="Map HTTP redirect chains and detect off-scope redirect targets.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Literal in-scope IP"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "scheme": {"type": "string", "enum": ["http", "https"]},
                "path": {"type": "string", "description": "Request path starting with '/'"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk="low",
        side_effects="Up to 6 bounded HTTP GET requests along a validated redirect chain.",
        network_active=True,
        approval_policy="explicit",
        timeout=timeout,
        max_output_chars=out_limit,
        activity="active",
        scope_requirements=(
            "Initial host and every redirect hop must be a literal IP inside "
            "GRYPHOS_ALLOWED_TARGETS; no DNS resolution and no blind following."
        ),
        result_schema={"type": "object", "properties": {
            "hops": {"type": "array"},
            "validated_destinations": {"type": "array"},
            "blocked": {"type": ["string", "null"]},
            "policy": {"type": "string"},
        }},
        show=show_http_redirects_action,
        execute=lambda args, scope_items, evidence=None: _run_http_redirects(
            str(args.get("target", "")),
            validate_port(args.get("port", 80)),
            str(args.get("scheme", "http")),
            str(args.get("path", "/")),
            scope_items,
            timeout,
            out_limit,
        ),
    )
