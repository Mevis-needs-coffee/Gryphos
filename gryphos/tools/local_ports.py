"""Tool 5 — local_ports: read-only snapshot of locally bound TCP/UDP ports.

Uses `ss -ltunp` (netstat-free; read-only, no root needed for listening
socket listing). Classifies each listener as local-only, wildcard/exposed, or
interface-bound, and notes that process attribution may need privileges.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .base import (
    ProcResult,
    ToolResult,
    ToolSpec,
    duration_since,
    resolve_binary,
    run_process,
)

_LOCAL_LOOPBACK_PREFIXES = ("127.", "::1")


def _classify_local_address(address: str) -> str:
    """Classify a listener as local-only, wildcard/exposed, or interface-bound."""
    clean = address.strip().rstrip(":")
    if clean in {"0.0.0.0", "::", "[::]", "*", ""}:  # noqa: S104 - classification, not binding
        return "wildcard (all interfaces / exposed)"
    if clean.startswith(_LOCAL_LOOPBACK_PREFIXES):
        return "local-only"
    return "interface-bound"


def _run_local_ports(timeout: int, max_output_chars: int) -> ToolResult:
    binary = resolve_binary("ss", "On Debian/Ubuntu: sudo apt install iproute2")
    argv = [binary, "-ltunp"]
    display = "ss -ltunp (read-only, local listeners)"
    started = datetime.now(UTC)
    proc: ProcResult = run_process(argv, timeout, max_output_chars)
    rows: list[dict] = []
    for raw in proc.output.splitlines():
        tokens = raw.split()
        if len(tokens) < 5:
            continue
        if tokens[0] in {"State", "Netid"}:
            continue
        protocol = tokens[0]
        if protocol not in {"tcp", "udp", "tcp6", "udp6"}:
            continue
        local_col = tokens[4]
        if ":" not in local_col and "]:" not in local_col:
            continue
        address, _, port = local_col.rpartition(":")
        rows.append({
            "protocol": protocol,
            "address": address or "*",
            "port": port,
            "state": tokens[1],
            "listener": _classify_local_address(address),
            "process": tokens[6] if len(tokens) > 6 else "",
        })
    counts = {
        "total": len(rows),
        "tcp": sum(1 for r in rows if r["protocol"].startswith("tcp")),
        "udp": sum(1 for r in rows if r["protocol"].startswith("udp")),
        "local_only": sum(1 for r in rows if r["listener"] == "local-only"),
        "exposed_wildcard": sum(1 for r in rows if r["listener"].startswith("wildcard")),
    }
    lines = [f"Local listening sockets: {counts['total']} ",
             f"TCP {counts['tcp']}, UDP {counts['udp']}, "
             f"local-only {counts['local_only']}, wildcard/exposed {counts['exposed_wildcard']}."]
    for row in rows[:80]:
        lines.append(
            f"{row['protocol']} {row['address']}:{row['port']} ({row['state']}) "
            f"-> {row['listener']}" + (f" [{row['process']}]" if row["process"] else "")
        )
    if len(rows) > 80:
        lines.append(f"... and {len(rows) - 80} more (truncated)")
    lines.append("Note: process attribution may require root.")
    return ToolResult(
        tool="local_ports", target="local system", display=display,
        returncode=proc.returncode, output="\n".join(lines)[:max_output_chars],
        network_active=False, activity="passive",
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={"listeners": rows[:500], "counts": counts, "source": "ss"},
        error="timeout" if proc.timed_out else None,
    )


def local_ports_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="local_ports",
        description=(
            "List currently bound TCP/UDP listening sockets on this host with "
            "ss -ltunp. Read-only; classifies listeners as local-only, "
            "interface-bound, or wildcard (exposed). Requires no root for "
            "listener enumeration."
        ),
        purpose="Identify local listening services and whether they are exposed beyond the loopback interface.",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: one read-only process query on this host.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 15),
        max_output_chars=out_limit,
        activity="passive",
        scope_requirements="No network targets; inspects the local host only.",
        result_schema={"type": "object", "properties": {
            "listeners": {"type": "array"},
            "counts": {"type": "object"},
            "source": {"type": "string"},
        }},
        execute=lambda args, scope_items, evidence=None: _run_local_ports(
            min(timeout, 15), out_limit
        ),
    )
