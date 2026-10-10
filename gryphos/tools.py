"""Registry-based security tool framework.

Every executable capability is a registered `ToolSpec` with a fixed
implementation, validated arguments, strict limits, and an explicit approval
policy. The model can only *propose* registered tools by name with arguments;
it can never supply commands, flags, or executable names. Nothing in this
module uses `shell=True`.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import requests

from .scope import (
    ScopeError,
    authorize_url,
    validate_path,
    validate_port,
    validate_target,
)


class ToolError(RuntimeError):
    """Raised for tool validation or execution problems (safe to show users)."""


@dataclass
class ToolResult:
    tool: str
    target: str
    display: str
    returncode: int | None
    output: str
    network_active: bool
    started_at: str = ""
    duration_seconds: float | None = None
    data: dict = field(default_factory=dict)
    error: str | None = None

    def to_evidence(self) -> dict:
        item = {
            "kind": "tool_result",
            "tool": self.tool,
            "target": self.target,
            "command": self.display,
            "returncode": self.returncode,
            "network_active": self.network_active,
            "output": self.output,
        }
        if self.started_at:
            item["started_at"] = self.started_at
        if self.duration_seconds is not None:
            item["duration_seconds"] = round(self.duration_seconds, 3)
        if self.data:
            item["data"] = self.data
        if self.error:
            item["error"] = self.error
        return item


@dataclass
class ToolSpec:
    name: str
    description: str
    purpose: str
    input_schema: dict
    risk: str
    side_effects: str
    network_active: bool
    approval_policy: str  # "explicit" for anything consequential
    timeout: int
    max_output_chars: int
    execute: Callable[..., ToolResult]

    def describe(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "purpose": self.purpose,
            "input_schema": self.input_schema,
            "risk": self.risk,
            "side_effects": self.side_effects,
            "network_active": self.network_active,
            "approval_policy": self.approval_policy,
            "timeout": self.timeout,
            "max_output_chars": self.max_output_chars,
        }


# ---------------------------------------------------------------------------
# nmap_basic — preserved conservative service-discovery scan
# ---------------------------------------------------------------------------

def _run_nmap_basic(
    target: str,
    scope_items: tuple[str, ...],
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    safe_target = validate_target(target, scope_items)
    binary = shutil.which("nmap")
    if not binary:
        raise ToolError("Nmap is not installed. On Kali/Ubuntu: sudo apt install nmap")

    argv = [
        binary,
        "-n",  # no DNS resolution
        "-Pn",  # treat host as online; avoids host-discovery probes
        "-sT",  # TCP connect scan; no raw-socket privileges required
        "-sV",  # service/version detection
        "--top-ports", "100",
        "-T2",  # conservative timing
        "--reason",
        safe_target,
    ]
    display = "nmap -n -Pn -sT -sV --top-ports 100 -T2 --reason " + safe_target
    started = datetime.now(UTC)
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or b""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        return ToolResult(
            tool="nmap_basic",
            target=safe_target,
            display=display,
            returncode=None,
            output=f"Timed out after {timeout}s.\n{partial[:max_output_chars]}".strip(),
            network_active=True,
            started_at=started.isoformat(),
            duration_seconds=(datetime.now(UTC) - started).total_seconds(),
            error=f"timeout after {timeout}s",
        )
    output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
    output = output[:max_output_chars].strip()
    return ToolResult(
        tool="nmap_basic",
        target=safe_target,
        display=display,
        returncode=completed.returncode,
        output=output,
        network_active=True,
        started_at=started.isoformat(),
        duration_seconds=(datetime.now(UTC) - started).total_seconds(),
        data=_parse_nmap_output(output),
    )


def _parse_nmap_output(output: str) -> dict:
    """Deterministically extract open/closed ports from nmap text output."""
    open_ports: list[dict] = []
    closed = 0
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "open":
                port_info = {"port": parts[0]}
                if len(parts) >= 4:
                    port_info["service"] = parts[2]
                    port_info["version"] = " ".join(parts[3:])
                elif len(parts) >= 3:
                    port_info["service"] = parts[2]
                open_ports.append(port_info)
            elif len(parts) >= 2 and parts[1] in {"closed", "filtered"}:
                closed += 1
    return {"open_ports": open_ports, "non_open_count": closed}


# ---------------------------------------------------------------------------
# HTTP tools — literal in-scope IP only; no automatic redirects
# ---------------------------------------------------------------------------

_USER_AGENT = "Gryphos/1.0 (authorized security assessment; +local)"


def _http_request(
    scheme: str, host: str, port: int, path: str, timeout: int, method: str = "GET",
    allow_redirects: bool = False,
) -> requests.Response:
    url = f"{scheme}://{host}:{port}{path}"
    return requests.request(
        method,
        url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        headers={"User-Agent": _USER_AGENT},
        stream=True,
    )


def _drain_and_close(response: requests.Response, limit: int) -> str:
    try:
        body = response.raw.read(limit + 1, decode_content=True)
    except Exception:
        body = b""
    finally:
        response.close()
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return body[:limit]


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
    safe_scheme = "https" if str(scheme).lower() == "https" else "http"
    if str(scheme).lower() not in {"http", "https"}:
        raise ToolError("scheme must be 'http' or 'https'.")
    display = f"HTTP HEAD {safe_scheme}://{safe_target}:{safe_port}/ (headers only)"
    started = datetime.now(UTC)
    try:
        response = _http_request(safe_scheme, safe_target, safe_port, "/", timeout, method="HEAD")
        headers = {k: v for k, v in response.headers.items()}
        _drain_and_close(response, 0)
    except requests.RequestException as exc:
        return ToolResult(
            tool="http_headers", target=safe_target, display=display, returncode=None,
            output=f"Request failed: {type(exc).__name__}", network_active=True,
            started_at=started.isoformat(), error=type(exc).__name__,
        )
    interesting = {
        k: v for k, v in headers.items()
        if k.lower() in {
            "server", "x-powered-by", "x-aspnet-version", "content-type",
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options", "referrer-policy",
            "permissions-policy", "set-cookie", "www-authenticate", "location",
        }
    }
    tech = [
        hints for hints in (
            headers.get("Server"), headers.get("X-Powered-By"), headers.get("X-AspNet-Version"),
        ) if hints
    ]
    lines = [f"HTTP {response.status_code} {response.reason}".strip()]
    lines += [f"{k}: {v}" for k, v in interesting.items()]
    missing = [
        h for h in (
            "strict-transport-security", "content-security-policy", "x-frame-options",
            "x-content-type-options",
        )
        if h not in {k.lower() for k in headers}
    ]
    if missing:
        lines.append("")
        lines.append("Missing hardening headers: " + ", ".join(missing))
    return ToolResult(
        tool="http_headers", target=safe_target, display=display,
        returncode=0, output="\n".join(lines)[:max_output_chars], network_active=True,
        started_at=started.isoformat(),
        duration_seconds=(datetime.now(UTC) - started).total_seconds(),
        data={"status_code": response.status_code, "headers": interesting, "technology_hints": tech,
              "missing_hardening_headers": missing},
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
    safe_scheme = "https" if str(scheme).lower() == "https" else "http"
    display = (
        f"HTTP GET {safe_scheme}://{safe_target}:{safe_port}{safe_path} "
        f"(manual redirect tracing, max {max_hops} hops, off-scope hops blocked)"
    )
    started = datetime.now(UTC)
    hops: list[dict] = []
    current = {"scheme": safe_scheme, "host": safe_target, "port": safe_port, "path": safe_path}
    blocked = None
    for _hop in range(max_hops + 1):
        try:
            response = _http_request(
                current["scheme"], current["host"], current["port"], current["path"],
                timeout, method="GET", allow_redirects=False,
            )
        except requests.RequestException as exc:
            hops.append({**current, "error": type(exc).__name__})
            break
        status = response.status_code
        location = response.headers.get("Location")
        _drain_and_close(response, 0)
        hop_record = {**current, "status": status}
        hops.append(hop_record)
        if status in (301, 302, 303, 307, 308) and location:
            hop_record["location"] = location
            try:
                nxt = authorize_url(
                    requests.compat.urljoin(
                        f"{current['scheme']}://{current['host']}:{current['port']}{current['path']}",
                        location,
                    ),
                    scope_items,
                )
            except ScopeError as exc:
                blocked = f"Redirect target blocked by scope policy: {exc}"
                break
            current = {"scheme": nxt["scheme"], "host": nxt["host"], "port": nxt["port"], "path": nxt["path"]}
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
    return ToolResult(
        tool="http_redirects", target=safe_target, display=display, returncode=0,
        output="\n".join(lines)[:max_output_chars], network_active=True,
        started_at=started.isoformat(),
        duration_seconds=(datetime.now(UTC) - started).total_seconds(),
        data={"hops": hops, "blocked": blocked},
    )


def _run_tls_cert(
    target: str,
    port: int,
    server_hostname: str,
    scope_items: tuple[str, ...],
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    safe_target = validate_target(target, scope_items)
    safe_port = validate_port(port)
    sni = (server_hostname or "").strip()
    if sni and (any(ch in sni for ch in "/:@ \t\r\n") or sni.startswith("[")):
        raise ToolError("server_hostname must be a bare hostname for SNI (no scheme, port, or path).")
    connect_name = sni if sni else safe_target
    display = f"TLS handshake with {safe_target}:{safe_port}" + (f" (SNI: {sni})" if sni else "")
    started = datetime.now(UTC)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((safe_target, safe_port), timeout=timeout) as sock, \
                context.wrap_socket(sock, server_hostname=connect_name) as tls:
            cert = tls.getpeercert()
            cipher = tls.cipher()
            version = tls.version()
    except Exception as exc:
        return ToolResult(
            tool="tls_cert", target=safe_target, display=display, returncode=None,
            output=f"TLS handshake failed: {type(exc).__name__}: {exc}", network_active=True,
            started_at=started.isoformat(), error=type(exc).__name__,
        )
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    sans = [v for kind, v in cert.get("subjectAltName", ()) if kind == "DNS"]
    expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC) if not_after else None
    days_left = (expires_dt - datetime.now(UTC)).days if expires_dt else None
    lines = [
        f"TLS version: {version}",
        f"Cipher: {cipher[0] if cipher else 'unknown'}",
        f"Subject: {subject.get('commonName', '')}",
        f"Issuer: {issuer.get('commonName', '')}",
        f"Valid from: {not_before}",
        f"Valid until: {not_after}" + (f" ({days_left} days left)" if days_left is not None else ""),
        "SANs: " + (", ".join(sans[:20]) if sans else "(none)"),
    ]
    return ToolResult(
        tool="tls_cert", target=safe_target, display=display, returncode=0,
        output="\n".join(lines)[:max_output_chars], network_active=True,
        started_at=started.isoformat(),
        duration_seconds=(datetime.now(UTC) - started).total_seconds(),
        data={
            "subject_cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "not_before": not_before, "not_after": not_after,
            "days_until_expiry": days_left, "sans": sans[:50],
            "tls_version": version,
        },
    )


# ---------------------------------------------------------------------------
# summarize_evidence — passive, no network traffic
# ---------------------------------------------------------------------------

def _run_summarize_evidence(
    evidence: list[dict],
    scope_items: tuple[str, ...],
    max_output_chars: int,
) -> ToolResult:
    """Deterministically summarize recorded tool evidence (no network)."""
    tool_runs = [e for e in evidence if e.get("kind") == "tool_result"]
    errors = [e for e in evidence if e.get("kind") in {"tool_error"} or e.get("error")]
    lines = [f"Tool executions recorded: {len(tool_runs)}"]
    all_open: list[str] = []
    for run in tool_runs:
        name = run.get("tool", "?")
        target = run.get("target", "?")
        rc = run.get("returncode")
        lines.append(f"- {name} on {target}: returncode={rc}")
        data = run.get("data") or {}
        for port in data.get("open_ports", []) or []:
            all_open.append(f"{port.get('port')} ({port.get('service', 'unknown')})")
    if all_open:
        lines.append("Open ports observed: " + ", ".join(all_open))
    else:
        lines.append("No open ports were observed in recorded tool output.")
    if errors:
        lines.append(f"Recorded tool errors: {len(errors)}")
    lines.append(
        "Note: this summary reflects only executed checks; unscanned ports and "
        "services were not tested."
    )
    return ToolResult(
        tool="summarize_evidence",
        target="(session evidence)",
        display="summarize recorded session evidence (passive)",
        returncode=0,
        output="\n".join(lines)[:max_output_chars],
        network_active=False,
        data={"open_ports_observed": all_open, "tool_runs": len(tool_runs), "errors": len(errors)},
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def build_registry(settings) -> dict[str, ToolSpec]:
    """Build the tool registry bound to the given Settings."""
    timeout = settings.command_timeout
    out_limit = settings.max_output_chars

    registry: dict[str, ToolSpec] = {}

    registry["nmap_basic"] = ToolSpec(
        name="nmap_basic",
        description=(
            "Bounded TCP service-discovery scan of the top 100 ports against ONE "
            "literal in-scope IP. Arguments are fixed by the controller; no flags "
            "or commands can be supplied."
        ),
        purpose="Discover listening TCP services and versions on an authorized host.",
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Literal in-scope IPv4/IPv6 address"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        risk="low",
        side_effects="Sends TCP connect probes to the top 100 ports of the target.",
        network_active=True,
        approval_policy="explicit",
        timeout=timeout,
        max_output_chars=out_limit,
        execute=lambda args, scope_items, evidence=None: _run_nmap_basic(
            str(args.get("target", "")), scope_items, timeout, out_limit
        ),
    )

    registry["http_headers"] = ToolSpec(
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
        execute=lambda args, scope_items, evidence=None: _run_http_headers(
            str(args.get("target", "")),
            validate_port(args.get("port", 80)),
            str(args.get("scheme", "http")),
            scope_items,
            min(timeout, 30),
            out_limit,
        ),
    )

    registry["http_redirects"] = ToolSpec(
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
        side_effects="Up to 6 HTTP GET requests along a redirect chain.",
        network_active=True,
        approval_policy="explicit",
        timeout=timeout,
        max_output_chars=out_limit,
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

    registry["tls_cert"] = ToolSpec(
        name="tls_cert",
        description=(
            "Perform a TLS handshake with an in-scope literal IP and report "
            "certificate subject, issuer, validity window, SANs, and negotiated "
            "protocol. Optional server_hostname sets SNI only."
        ),
        purpose="Check TLS certificate properties and expiry on an authorized host.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Literal in-scope IP"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "server_hostname": {"type": "string", "description": "Optional SNI hostname"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk="low",
        side_effects="One TLS handshake with the target.",
        network_active=True,
        approval_policy="explicit",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        execute=lambda args, scope_items, evidence=None: _run_tls_cert(
            str(args.get("target", "")),
            validate_port(args.get("port", 443)),
            str(args.get("server_hostname", "") or ""),
            scope_items,
            min(timeout, 30),
            out_limit,
        ),
    )

    registry["summarize_evidence"] = ToolSpec(
        name="summarize_evidence",
        description=(
            "Passively summarize the tool evidence recorded in this session "
            "(open ports, errors). Sends no network traffic."
        ),
        purpose="Consolidate existing evidence without new network activity.",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None. Reads session evidence only.",
        network_active=False,
        approval_policy="none",
        timeout=10,
        max_output_chars=out_limit,
        execute=lambda args, scope_items, evidence=None: _run_summarize_evidence(
            evidence or [], scope_items, out_limit
        ),
    )

    return registry


def validate_args(spec: ToolSpec, args: dict) -> dict:
    """Validate proposed arguments against the tool's schema.

    Rejects unknown properties and missing required fields. Returns the
    sanitized argument dict.
    """
    if not isinstance(args, dict):
        raise ToolError("Tool arguments must be a JSON object.")
    schema = spec.input_schema
    allowed = set(schema.get("properties", {}))
    if schema.get("additionalProperties") is False:
        unknown = set(args) - allowed
        if unknown:
            raise ToolError(
                f"Unknown argument(s) for {spec.name}: {', '.join(sorted(unknown))}. "
                f"Allowed: {', '.join(sorted(allowed)) or '(none)'}."
            )
    for req in schema.get("required", []):
        if req not in args or args[req] in (None, ""):
            raise ToolError(f"Missing required argument '{req}' for {spec.name}.")
    return {k: args[k] for k in allowed if k in args}
