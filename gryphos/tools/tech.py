"""Tool 4 — web_tech: bounded web-technology identification.

Identifies technology from response headers and a small, bounded body sniff
(generator meta tags). No crawling, no path enumeration, no aggressive probes.
Optionally consults WhatWeb, when installed, with conservative fixed flags.
All fingerprints are labelled as *inferred*, never confirmed.
"""

from __future__ import annotations

import re
import shutil
from datetime import UTC, datetime

import requests

from ..scope import validate_path, validate_port, validate_target
from .base import ToolResult, ToolSpec, duration_since, resolve_binary, run_process
from .net import bounded_http_request, drain_and_close

BODY_SNIFF_LIMIT = 8192

_TECH_RULES = (
    ("nginx", ("server",)),
    ("apache", ("server",)),
    ("IIS", ("server", "x-powered-by")),
    ("openresty", ("server",)),
    ("caddy", ("server",)),
    ("gunicorn", ("server",)),
    ("uvicorn", ("server",)),
    ("php", ("x-powered-by", "x-generator")),
    ("asp.net", ("x-powered-by", "x-aspnet-version", "x-generator")),
    ("wordpress", ("x-powered-by", "x-generator")),
    ("shinyproxy/huggingface", ("x-served-by",)),
    ("cloudflare", ("server",)),
    ("akamai", ("server",)),
    ("varnish", ("server",)),
    ("traffic server", ("server",)),
)

_META_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


def _infer_from_text(key: str, value: str) -> list[str]:
    key = key.lower()
    text = value.lower()
    names = []
    for name, keys in _TECH_RULES:
        if key in keys and name in text:
            names.append(name)
    return names


def _fingerprint_headers(headers: dict) -> list[dict]:
    found: list[dict] = []
    for key, raw in headers.items():
        for name in _infer_from_text(key, raw):
            if any(t["name"] == name for t in found):
                continue
            found.append({
                "name": name,
                "detected_from": f"{key} header",
                "evidence": raw[:80],
                "confidence": "inferred",
            })
    if "strict-transport-security" in {k.lower() for k in headers}:
        found.append({
            "name": "HSTS configured",
            "detected_from": "strict-transport-security header",
            "evidence": "present",
            "confidence": "inferred",
        })
    return found


def _fingerprint_body(body: str) -> list[dict]:
    match = _META_GENERATOR_RE.search(body or "")
    if not match:
        return []
    return [{
        "name": match.group(1).strip()[:80],
        "detected_from": "<meta name=generator>",
        "evidence": "generator meta tag",
        "confidence": "inferred",
    }]


def _run_whatweb(url: str, timeout: int) -> tuple[bool, str]:
    """Run WhatWeb conservatively if installed; never on the critical path."""
    try:
        binary = resolve_binary("whatweb", "")
    except RuntimeError:
        return False, ""
    proc = run_process(
        [binary, "-a", "1", "--no-redirect", "--max-threads", "1", "--no-errors", url],
        timeout=min(timeout, 30),
        max_output_chars=4000,
    )
    return True, proc.output.strip()


def _run_web_tech(
    target: str,
    port: int,
    scheme: str,
    path: str,
    scope_items: tuple[str, ...],
    timeout: int,
    max_output_chars: int,
    body_limit: int = BODY_SNIFF_LIMIT,
) -> ToolResult:
    safe_target = validate_target(target, scope_items)
    safe_port = validate_port(port)
    safe_scheme = "https" if str(scheme).lower() == "https" else "http"
    safe_path = validate_path(path)
    display = (
        f"HTTP GET {safe_scheme}://{safe_target}:{safe_port}{safe_path} "
        f"(bounded fingerprint, {body_limit} body bytes max, no crawling)"
    )
    started = datetime.now(UTC)
    try:
        response = bounded_http_request("GET", safe_scheme, safe_target, safe_port, safe_path, timeout)
        headers = {k: v for k, v in response.headers.items() if k.lower() in {
            "server", "x-powered-by", "x-aspnet-version", "x-generator",
            "x-served-by", "strict-transport-security", "x-runtime", "x-backend-server",
        }}
        body = drain_and_close(response, body_limit)
        status = response.status_code
    except requests.RequestException as exc:
        return ToolResult(
            tool="web_tech", target=safe_target, display=display, returncode=None,
            output=f"Request failed: {type(exc).__name__}", network_active=True,
            started_at=started.isoformat(), error=type(exc).__name__,
        )

    technologies = _fingerprint_headers(headers) + _fingerprint_body(body)
    whatweb_available = bool(shutil.which("whatweb"))
    whatweb_output = ""
    if whatweb_available:
        whatweb_output = _run_whatweb(
            f"{safe_scheme}://{safe_target}:{safe_port}{safe_path}", timeout,
        )[1]

    lines = [f"HTTP {status} — technology fingerprint (all results are INFERRED):"]
    if technologies:
        for tech in technologies:
            evidence = f": {tech['evidence']}" if tech["evidence"] else ""
            lines.append(
                f"- {tech['name']} (via {tech['detected_from']}{evidence}) [inferred]"
            )
    else:
        lines.append("- No fingerprint indicators found in the bounded scan.")
    if whatweb_output:
        lines.append("")
        lines.append("WhatWeb (inferred):")
        for line in whatweb_output.splitlines()[:15]:
            lines.append(f"  {line[:200]}")
    lines.append(f"- Scanned: {safe_scheme}://{safe_target}:{safe_port}{safe_path} (no crawling, no path enumeration)")

    return ToolResult(
        tool="web_tech", target=safe_target, display=display, returncode=0,
        output="\n".join(lines)[:max_output_chars], network_active=True,
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={
            "status_code": status,
            "port": safe_port,
            "technologies": technologies,
            "body_sniffed_bytes": len(body),
            "crawl_mode": "none",
            "inferred": True,
            "whatweb": {
                "available": whatweb_available,
                "ran": bool(whatweb_output),
                "summary": whatweb_output[:2000] or None,
            },
        },
    )


def show_web_tech_action(args: dict) -> str:
    scheme = args.get("scheme", "http")
    port = args.get("port", 80)
    path = args.get("path", "/")
    return f"HTTP GET {scheme}://{args.get('target', '?')}:{port}{path} (bounded fingerprint, no crawl)"


def web_tech_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="web_tech",
        description=(
            "Identify web technology from response headers and a tiny bounded "
            "body sniff (generator meta tag). No crawling or path enumeration. "
            "All fingerprints are inferred, never confirmed. Optionally runs "
            "WhatWeb if installed, with conservative fixed flags."
        ),
        purpose="Gather bounded, non-invasive technology indicators on an authorized web endpoint.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Literal in-scope IP"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "scheme": {"type": "string", "enum": ["http", "https"]},
                "path": {"type": "string", "description": "Request path starting with '/', default '/'" },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk="low",
        side_effects="One bounded HTTP GET (headers plus up to 8 KiB of body); optional WhatWeb with stealth flags.",
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="active",
        scope_requirements="Literal in-scope IP only; no crawling and no automatic redirects.",
        result_schema={"type": "object", "properties": {
            "status_code": {"type": "integer"},
            "technologies": {"type": "array"},
            "body_sniffed_bytes": {"type": "integer"},
            "crawl_mode": {"type": "string"},
            "inferred": {"type": "boolean"},
        }},
        show=show_web_tech_action,
        execute=lambda args, scope_items, evidence=None: _run_web_tech(
            str(args.get("target", "")),
            validate_port(args.get("port", 80)),
            str(args.get("scheme", "http")),
            str(args.get("path", "/")),
            scope_items,
            min(timeout, 30),
            out_limit,
        ),
    )
