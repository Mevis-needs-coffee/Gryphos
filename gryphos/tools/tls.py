"""Tool 3 — tls_cert: authorized TLS endpoint certificate inspection.

Uses a default, certificate-verifying TLS context. Verification is NEVER
disabled; hostname/IP verification is performed against the SNI name when one
is supplied. Chain or connection errors are reported explicitly.
"""

from __future__ import annotations

import contextlib
import ssl
from datetime import UTC, datetime

from ..scope import validate_port, validate_target
from .base import ToolError, ToolResult, ToolSpec, duration_since
from .net import tls_connect


def _parse_dn(cert: dict, key: str) -> str:
    return dict(item[0] for item in cert.get(key, ())).get("commonName", "")


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
        raise ToolError(
            "server_hostname must be a bare hostname for SNI (no scheme, port, or path)."
        )
    connect_name = sni if sni else safe_target
    display = f"TLS handshake with {safe_target}:{safe_port}" + (f" (SNI: {sni})" if sni else "")
    started = datetime.now(UTC)

    try:
        tls, cert = tls_connect(safe_target, safe_port, connect_name, timeout, scope_items)
    except ssl.CertificateError as exc:
        return _failure(
            safe_target, display, started,
            f"Certificate verification failed: {exc}", "certificate",
        )
    except (TimeoutError, OSError) as exc:
        return _failure(
            safe_target, display, started,
            f"TLS handshake failed: {type(exc).__name__}: {exc}", "connection",
        )
    except ValueError as exc:
        return _failure(safe_target, display, started, f"TLS failure: {exc}", "protocol")
    except Exception as exc:  # noqa: BLE001 - final defensive boundary for TLS I/O
        return _failure(
            safe_target, display, started,
            f"TLS handshake failed: {type(exc).__name__}", "handshake",
        )

    try:
        cipher = tls.cipher()
        version = tls.version()
    except (OSError, ValueError):
        cipher, version = None, None
    finally:
        with contextlib.suppress(OSError):
            tls.close()

    if not cert:
        return _failure(
            safe_target, display, started,
            "TLS handshake succeeded but no valid certificate could be parsed "
            "(server did not present one, or chain validation did not complete).",
            "no_certificate",
        )

    subject_cn = _parse_dn(cert, "subject")
    issuer_cn = _parse_dn(cert, "issuer")
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    sans = [v for kind, v in cert.get("subjectAltName", ()) if kind == "DNS"]
    expires_dt = None
    if not_after:
        try:
            expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        except ValueError:
            try:
                expires_dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            except ValueError:
                expires_dt = None
    days_left = (expires_dt - datetime.now(UTC)).days if expires_dt else None
    expired = days_left is not None and days_left < 0

    lines = [
        f"TLS version: {version}",
        f"Cipher: {cipher[0] if cipher else 'unknown'}",
        f"Subject: {subject_cn}",
        f"Issuer: {issuer_cn}",
        f"Valid from: {not_before}",
        f"Valid until: {not_after}"
        + (f" ({days_left} days left)" if days_left is not None else ""),
        "Expiry status: "
        + ("EXPIRED" if expired else "valid" if days_left is not None else "unknown"),
        "SANs: " + (", ".join(sans[:20]) if sans else "(none)"),
        "Verification: chain validated; "
        f"{'hostname' if sni else 'IP-SAN'} match verified for {connect_name!r},",
    ]
    return ToolResult(
        tool="tls_cert", target=safe_target, display=display, returncode=0,
        output="\n".join(lines)[:max_output_chars], network_active=True,
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "port": safe_port,
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_left,
            "expired": expired,
            "sans": sans[:50],
            "tls_version": version,
            "cipher": cipher[0] if cipher else None,
            "hostname_verified": True,
            "verification_note": (
                f"chain + {'hostname' if sni else 'IP-SAN'} match verified for {connect_name!r}"
            ),
        },
    )


def _failure(target, display, started, message, kind):
    return ToolResult(
        tool="tls_cert", target=target, display=display, returncode=None,
        output=message, network_active=True,
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={"error": kind},
        error=kind,
    )


def show_tls_action(args: dict) -> str:
    return f"TLS handshake {args.get('target', '?')}:{args.get('port', 443)}"


def tls_cert_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="tls_cert",
        description=(
            "Perform a TLS handshake with an in-scope literal IP and report "
            "certificate subject, issuer, validity window, expiry status, SANs, "
            "chain/verification results, and negotiated protocol. Optional "
            "server_hostname sets SNI only."
        ),
        purpose="Check TLS certificate properties, expiry, and verification on an authorized host.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Literal in-scope IP"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "server_hostname": {
                    "type": "string",
                    "description": "Optional bare SNI hostname (no scheme/port/path)",
                },
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
        activity="active",
        approval_level=2,
        scope_requirements="Literal in-scope IP only; certificate verification is never disabled.",
        result_schema={"type": "object", "properties": {
            "subject_cn": {"type": "string"},
            "issuer_cn": {"type": "string"},
            "days_until_expiry": {"type": ["integer", "null"]},
            "expired": {"type": "boolean"},
            "sans": {"type": "array"},
            "tls_version": {"type": ["string", "null"]},
            "hostname_verified": {"type": "boolean"},
        }},
        show=show_tls_action,
        execute=lambda args, scope_items, evidence=None: _run_tls_cert(
            str(args.get("target", "")),
            validate_port(args.get("port", 443)),
            str(args.get("server_hostname", "") or ""),
            scope_items,
            min(timeout, 30),
            out_limit,
        ),
    )
