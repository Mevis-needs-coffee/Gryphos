"""Authorized web CTF tools (Phase 3).

Every tool here is built around a shared `WebScope` + `WebClient`, so all web
traffic obeys the operator-authorized origin, bounded request budget, body-size
cap, and rate limit configured for the challenge. Tools never see raw
credentials: cookies and tokens are redacted before they reach evidence, the
model, or a report.

`web_fetch` retrieves a single same-origin resource (optionally following
same-origin redirects) and renders status, redacted headers, and a bounded body.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

from ..tools.base import ToolError, ToolResult, ToolSpec, duration_since
from .flag import FlagFormat
from .sandbox import attach_flags
from .webclient import WebClient, WebClientError, WebResponse
from .webscope import WebScope, WebScopeError, WebTarget

MAX_REDIRECT_HOPS = 5


def _same_origin_path(raw: object, scope: WebScope) -> str:
    """Normalize a path or same-origin URL to a bounded request path."""
    text = str(raw or "").strip()
    if not text:
        raise ToolError("A request path is required (e.g. / or /login).")
    if "://" in text:
        parts = urlsplit(text)
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError as exc:
            raise ToolError(f"Refused: invalid port in {text!r}.") from exc
        if port is None:
            port = 443 if scheme == "https" else 80
        if parts.username or parts.password:
            raise ToolError("Refused: URLs with embedded credentials are not allowed.")
        if not (
            scheme == scope.origin_scheme
            and host == scope.origin_host.lower()
            and port == scope.origin_port
        ):
            raise ToolError(f"Refused: {text!r} is not on the authorized origin {scope.origin}.")
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return path
    return text


def _authorize(scope: WebScope, raw: object) -> WebTarget:
    path = _same_origin_path(raw, scope)
    try:
        return scope.authorize_request(path)
    except WebScopeError as exc:
        raise ToolError(str(exc)) from exc


def render_responses(responses: list[WebResponse], out_limit: int) -> str:
    """Render a request/redirect chain with all sensitive values redacted."""
    lines: list[str] = []
    for index, response in enumerate(responses):
        item = response.to_dict(redacted=True)
        status = f"{item['status']} {item['reason']}".strip()
        lines.append(f"[{index}] {item['method']} {item['url']} -> {status or '(no response)'}")
        if item["error"]:
            lines.append(f"    error: {item['error']}")
        if item["redirect"]:
            lines.append(f"    location: {item['redirect']}")
    final = responses[-1].to_dict(redacted=True)
    lines.append("")
    lines.append(
        f"Final: {final['status']} {final['reason']}".rstrip()
        + f" ({final['content_type'] or 'unknown content-type'}, {final['body_length']} bytes"
        + (", truncated" if final["body_truncated"] else "")
        + f", {final['elapsed_ms']} ms)"
    )
    if final["resolved_ip"]:
        lines.append(f"Resolved to: {final['resolved_ip']}")
    if final["reused"]:
        lines.append("(served from this run's cache; no new network request was made)")
    if final["headers"]:
        lines.append("Headers (redacted):")
        lines.extend(f"  {h['name']}: {h['value']}" for h in final["headers"])
    if final["body"]:
        lines.append("")
        lines.append("Body (redacted):")
        lines.append(final["body"])
    return "\n".join(lines)[:out_limit]


def web_fetch_spec(
    scope: WebScope, client: WebClient, fmt: FlagFormat, timeout: int, out_limit: int
) -> ToolSpec:
    def _run(args, scope_items, evidence=None) -> ToolResult:
        started = datetime.now(UTC)
        method = str(args.get("method") or "GET").upper()
        follow = bool(args.get("follow_redirects", False))
        max_body = args.get("max_body")
        target = _authorize(scope, args.get("path", ""))
        try:
            if follow:
                responses = client.request_with_redirects(
                    method, target, max_hops=MAX_REDIRECT_HOPS, max_body=max_body
                )
            else:
                responses = [client.request(method, target, max_body=max_body)]
        except WebClientError as exc:
            raise ToolError(str(exc)) from exc
        final = responses[-1]
        output = render_responses(responses, out_limit)
        data = {
            "request_url": target.url,
            "method": method,
            "responses": [r.to_dict(redacted=True) for r in responses],
            "final_status": final.status,
            "final_error": final.error,
            "used_requests": client.request_count,
            "remaining_requests": client.remaining,
        }
        result = ToolResult(
            tool="web_fetch",
            target=target.url,
            display=f"web_fetch({method} {target.path})",
            returncode=final.status if final.ok else None,
            output=output,
            network_active=True,
            activity="active",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=data,
            error=final.error,
        )
        return attach_flags(result, fmt)

    return ToolSpec(
        name="web_fetch",
        description=(
            "Fetch one resource from the authorized challenge origin and show its status, "
            "headers, and body. Only GET/HEAD are allowed; a same-origin redirect chain can "
            "be followed. Cookies, tokens, and credentials in the response are redacted. "
            "Never contacts any origin other than the one the operator authorized."
        ),
        purpose="Retrieve and inspect a specific page, endpoint, or asset on the challenge.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path on the authorized origin, e.g. / or /login or /api/items?id=1.",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "HEAD"],
                    "description": "HTTP method (default GET). HEAD fetches headers only.",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "Follow same-origin redirects (default false).",
                },
                "max_body": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": scope.max_body_bytes,
                    "description": f"Maximum response bytes to read (default {scope.max_body_bytes}).",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk="medium",
        side_effects=(
            "Issues bounded GET/HEAD requests to the operator-authorized challenge origin only."
        ),
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="active",
        approval_level=2,
        scope_requirements=(
            "Confined to the authorized web origin; bounded by request budget, size, and rate."
        ),
        result_schema={
            "type": "object",
            "properties": {
                "request_url": {"type": "string"},
                "final_status": {"type": "integer"},
                "responses": {"type": "array"},
            },
        },
        show=lambda args: f"web_fetch({args.get('method', 'GET')} {args.get('path')!r})",
        execute=_run,
    )
