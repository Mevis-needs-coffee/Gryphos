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

import html as html_mod
import re
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

from ..tools.base import ToolError, ToolResult, ToolSpec, duration_since
from .flag import FlagFormat
from .sandbox import attach_flags, find_flags
from .webclient import WebClient, WebClientError, WebResponse
from .webscope import WebScope, WebScopeError, WebTarget

MAX_REDIRECT_HOPS = 5
MAX_CRAWL_PAGES = 25
MAX_CRAWL_DEPTH = 3
MAX_LIST_ITEMS = 60

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_META_RE = re.compile(r"<meta\s+([^>]+?)/?>", re.I | re.S)
_ATTR_RE = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s\"'>]+)")
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_FIELD_RE = re.compile(r"<(?:input|textarea|select|button)\b([^>]*)>", re.I | re.S)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_ENDPOINT_RE = re.compile(r"[\"'`](/[A-Za-z0-9_\-./?=&%]{1,120})[\"'`]")
_LINK_PATTERNS = (
    ("a", re.compile(r"<a\b[^>]*?\bhref\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I | re.S)),
    ("link", re.compile(r"<link\b[^>]*?\bhref\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I | re.S)),
    ("script", re.compile(r"<script\b[^>]*?\bsrc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I | re.S)),
    ("img", re.compile(r"<img\b[^>]*?\bsrc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I | re.S)),
    ("form", re.compile(r"<form\b[^>]*?\baction\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I | re.S)),
)
_SKIP_PREFIXES = ("mailto:", "javascript:", "data:", "tel:", "blob:")


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return html_mod.unescape(value)


def _attr(blob: str, name: str) -> str | None:
    for match in _ATTR_RE.finditer(blob):
        if match.group(1).lower() == name.lower():
            return _unquote(match.group(2))
    return None


def _extract_links(html: str, base: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for kind, pattern in _LINK_PATTERNS:
        for match in pattern.finditer(html):
            href = _unquote(match.group(1))
            if not href or href.startswith("#") or href.lower().startswith(_SKIP_PREFIXES):
                continue
            found.append((urljoin(base, href), kind))
    return found


def _extract_title(html: str) -> str:
    match = _TITLE_RE.search(html)
    return _unquote(match.group(1)) if match else ""


def _extract_meta(html: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for attrs in _META_RE.findall(html):
        name = _attr(attrs, "name") or _attr(attrs, "property") or _attr(attrs, "http-equiv")
        content = _attr(attrs, "content")
        if name and content:
            out[name] = content
    return out


def _extract_forms(html: str, base: str) -> list[dict]:
    forms: list[dict] = []
    for attrs, inner in _FORM_RE.findall(html):
        action = _attr(attrs, "action") or ""
        method = (_attr(attrs, "method") or "get").lower()
        fields: list[dict] = []
        for field_attrs in _FIELD_RE.findall(inner):
            name = _attr(field_attrs, "name")
            if not name:
                continue
            fields.append({"name": name, "type": (_attr(field_attrs, "type") or "text").lower()})
        forms.append({
            "action": urljoin(base, action) if action else base,
            "method": method,
            "fields": fields[:MAX_LIST_ITEMS],
        })
    return forms


def _extract_comments(html: str) -> list[str]:
    comments = [c.strip() for c in _COMMENT_RE.findall(html)]
    return [c for c in comments if c][:MAX_LIST_ITEMS]


def _extract_endpoints(html: str, inline_js: str) -> list[str]:
    found: list[str] = []
    for match in _ENDPOINT_RE.finditer(html + "\n" + inline_js):
        path = match.group(1)
        if path not in found and not path.startswith(("//", "/>")):
            found.append(path)
    return found[:MAX_LIST_ITEMS]



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


def _merge_flags(result: ToolResult, fmt: FlagFormat, found: list[str]) -> ToolResult:
    if found:
        result.data.setdefault("flags", found)
        result.output = (
            result.output.rstrip()
            + "\n\nFlag-shaped strings detected: "
            + ", ".join(found)
        )
    return result


def attach_flags_from(result: ToolResult, fmt: FlagFormat, texts: list[str]) -> ToolResult:
    """Surface flag-shaped strings found in any of `texts` (e.g. fetched bodies)."""
    found: list[str] = []
    for text in texts:
        for value in find_flags(text or "", fmt):
            if value not in found:
                found.append(value)
    return _merge_flags(result, fmt, found)


def _classify_links(
    scope: WebScope, current: WebTarget, html: str
) -> tuple[list[dict], list[str]]:
    """Return (same-origin links, offsite link targets) for a page."""
    same: list[dict] = []
    offsite: list[str] = []
    seen: set[str] = set()
    for href, kind in _extract_links(html, current.url):
        try:
            target = scope.authorize_redirect(href, current)
        except WebScopeError:
            if href not in offsite:
                offsite.append(href)
            continue
        if target.url in seen:
            continue
        seen.add(target.url)
        same.append({"url": target.url, "path": target.path, "kind": kind})
    return same, offsite[:MAX_LIST_ITEMS]


def web_crawl_spec(
    scope: WebScope, client: WebClient, fmt: FlagFormat, timeout: int, out_limit: int
) -> ToolSpec:
    def _run(args, scope_items, evidence=None) -> ToolResult:
        started = datetime.now(UTC)
        start = _authorize(scope, args.get("path") or "/")
        max_pages = int(args.get("max_pages") or 8)
        depth = int(args.get("depth") or 2)
        visited: dict[str, int] = {start.path: 0}
        queue: list[tuple[WebTarget, int]] = [(start, 0)]
        pages: list[dict] = []
        offsite: list[str] = []
        page_flags: list[str] = []
        stopped: str | None = None
        while queue and len(pages) < max_pages:
            if client.remaining <= 0:
                stopped = "request budget exhausted"
                break
            target, level = queue.pop(0)
            try:
                response = client.request("GET", target)
            except WebClientError as exc:
                raise ToolError(str(exc)) from exc
            same, off = _classify_links(scope, target, response.body)
            for value in find_flags(response.body, fmt):
                if value not in page_flags:
                    page_flags.append(value)
            for link in off:
                if link not in offsite:
                    offsite.append(link)
            pages.append({
                "url": target.url,
                "path": target.path,
                "depth": level,
                "status": response.status,
                "content_type": response.content_type,
                "title": _extract_title(response.body),
                "same_origin_links": len(same),
                "offsite_links": len(off),
                "body_length": response.body_length,
                "body_truncated": response.body_truncated,
                "error": response.error,
            })
            if level >= depth:
                continue
            for link in same:
                path = urlsplit(link["url"]).path or "/"
                if path not in visited and len(visited) < max_pages * 4:
                    visited[path] = level + 1
                    queue.append((scope.authorize_request(link["path"]), level + 1))

        lines = [
            f"Crawl of {start.url} (max_pages={max_pages}, depth={depth})",
            f"Visited {len(pages)} page(s); {client.remaining} request(s) remaining.",
            "",
        ]
        for page in pages:
            title = f' "{page["title"]}"' if page["title"] else ""
            lines.append(
                f"[d{page['depth']}] {page['status']} {page['path']} "
                f"({page['content_type'] or '?'}){title} "
                f"same-origin-links={page['same_origin_links']} offsite={page['offsite_links']}"
            )
            if page["error"]:
                lines.append(f"    error: {page['error']}")
        if offsite:
            lines.append("")
            lines.append("Offsite references (not fetched):")
            lines.extend(f"  {link}" for link in offsite[:MAX_LIST_ITEMS])
        if stopped:
            lines.append("")
            lines.append(f"Stopped early: {stopped}.")
        data = {
            "start_url": start.url,
            "pages": pages,
            "offsite_references": offsite,
            "stopped": stopped,
            "used_requests": client.request_count,
            "remaining_requests": client.remaining,
        }
        result = ToolResult(
            tool="web_crawl",
            target=start.url,
            display=f"web_crawl({start.path}, max_pages={max_pages}, depth={depth})",
            returncode=0,
            output="\n".join(lines)[:out_limit],
            network_active=True,
            activity="active",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=data,
        )
        return _merge_flags(result, fmt, page_flags)

    return ToolSpec(
        name="web_crawl",
        description=(
            "Breadth-first crawl of same-origin links starting from a path, bounded by "
            "max_pages and depth. Offsite links are listed but never fetched. Each page "
            "reports status, content-type, title, and link counts. Flag-shaped strings "
            "found in crawled pages are surfaced."
        ),
        purpose="Map the reachable same-origin routes and discover where to look next.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Starting path (default /)."},
                "max_pages": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_CRAWL_PAGES,
                    "description": "Maximum pages to fetch (default 8).",
                },
                "depth": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_CRAWL_DEPTH,
                    "description": "Maximum link depth from the start path (default 2).",
                },
            },
            "additionalProperties": False,
        },
        risk="medium",
        side_effects="Issues bounded GET requests to same-origin links only.",
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 45),
        max_output_chars=out_limit,
        activity="active",
        approval_level=2,
        scope_requirements="Same-origin only; bounded by max_pages, depth, and request budget.",
        result_schema={
            "type": "object",
            "properties": {"pages": {"type": "array"}, "start_url": {"type": "string"}},
        },
        show=lambda args: (
            f"web_crawl({args.get('path', '/')!r}, "
            f"max_pages={args.get('max_pages', 8)}, depth={args.get('depth', 2)})"
        ),
        execute=_run,
    )


def web_analyze_spec(
    scope: WebScope, client: WebClient, fmt: FlagFormat, timeout: int, out_limit: int
) -> ToolSpec:
    def _run(args, scope_items, evidence=None) -> ToolResult:
        started = datetime.now(UTC)
        target = _authorize(scope, args.get("path") or "/")
        include_robots = bool(args.get("include_robots", False))
        max_body = args.get("max_body")
        try:
            response = client.request("GET", target, max_body=max_body)
        except WebClientError as exc:
            raise ToolError(str(exc)) from exc
        html = response.body
        same, offsite = _classify_links(scope, target, html)
        inline_scripts = _SCRIPT_BLOCK_RE.findall(html)
        inline_js = "\n".join(inline_scripts)
        forms = _extract_forms(html, target.url)
        meta = _extract_meta(html)
        comments = _extract_comments(html)
        endpoints = _extract_endpoints(html, inline_js)
        external_scripts = [link["url"] for link in same if link["kind"] == "script"]

        extras: list[dict] = []
        if include_robots:
            for extra_path in ("/robots.txt", "/sitemap.xml"):
                if client.remaining <= 0:
                    break
                try:
                    extra_target = scope.authorize_request(extra_path)
                    extra = client.request("GET", extra_target)
                except (WebClientError, WebScopeError):
                    continue
                extras.append({
                    "path": extra_path,
                    "status": extra.status,
                    "body": extra.body if extra.status == 200 else "",
                    "body_truncated": extra.body_truncated,
                })

        lines = [
            f"Analyzed GET {target.url} -> {response.status} {response.reason}".rstrip()
            + f" ({response.content_type or 'unknown content-type'}, {response.body_length} bytes)"
        ]
        if response.error:
            lines.append(f"error: {response.error}")
        if _extract_title(html):
            lines.append(f"Title: {_extract_title(html)}")
        if meta:
            lines.append("Meta:")
            lines.extend(f"  {name}: {value}" for name, value in meta.items())
        lines.append(
            f"Links: {len(same)} same-origin, {len(offsite)} offsite"
        )
        if forms:
            lines.append(f"Forms ({len(forms)}):")
            for form in forms:
                fields = ", ".join(f"{f['name']}({f['type']})" for f in form["fields"]) or "(none)"
                lines.append(f"  - {form['method'].upper()} {form['action']}: {fields}")
        lines.append(
            f"Scripts: {len(external_scripts)} external, {len(inline_scripts)} inline"
        )
        if endpoints:
            lines.append("Referenced endpoints:")
            lines.extend(f"  {path}" for path in endpoints)
        if comments:
            lines.append(f"HTML comments ({len(comments)}):")
            lines.extend(f"  {comment[:200]}" for comment in comments)
        for extra in extras:
            lines.append("")
            lines.append(f"{extra['path']} -> {extra['status']}")
            if extra["body"]:
                lines.append(extra["body"][:1000])

        data = {
            "request_url": target.url,
            "status": response.status,
            "final_error": response.error,
            "title": _extract_title(html),
            "meta": meta,
            "same_origin_links": same,
            "offsite_links": offsite,
            "forms": forms,
            "external_scripts": external_scripts,
            "inline_script_count": len(inline_scripts),
            "endpoints": endpoints,
            "comments": comments,
            "extras": extras,
            "used_requests": client.request_count,
            "remaining_requests": client.remaining,
        }
        result = ToolResult(
            tool="web_analyze",
            target=target.url,
            display=f"web_analyze({target.path})",
            returncode=response.status if response.ok else None,
            output="\n".join(lines)[:out_limit],
            network_active=True,
            activity="active",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=data,
            error=response.error,
        )
        return attach_flags_from(result, fmt, [html, *[extra["body"] for extra in extras]])

    return ToolSpec(
        name="web_analyze",
        description=(
            "Structurally analyze one same-origin page: title, meta tags, forms and their "
            "fields, same-origin vs offsite links, external and inline scripts, referenced "
            "endpoint paths, and HTML comments. Optionally also fetch /robots.txt and "
            "/sitemap.xml. Surfaces flag-shaped strings."
        ),
        purpose="Extract structure, entry points, and clues from a page and its source.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to analyze (default /)."},
                "include_robots": {
                    "type": "boolean",
                    "description": "Also fetch /robots.txt and /sitemap.xml (default false).",
                },
                "max_body": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": scope.max_body_bytes,
                    "description": f"Maximum response bytes to read (default {scope.max_body_bytes}).",
                },
            },
            "additionalProperties": False,
        },
        risk="medium",
        side_effects="Issues bounded GET requests to same-origin pages only.",
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="active",
        approval_level=2,
        scope_requirements="Same-origin only; bounded by request budget, size, and rate.",
        result_schema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "forms": {"type": "array"},
                "endpoints": {"type": "array"},
            },
        },
        show=lambda args: (
            f"web_analyze({args.get('path', '/')!r}"
            + (", robots" if args.get("include_robots") else "")
            + ")"
        ),
        execute=_run,
    )
