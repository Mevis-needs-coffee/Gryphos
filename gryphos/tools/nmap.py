"""Tool 1 — nmap_basic: bounded TCP service-discovery scan.

Conservative, fixed-argument scan of the top 100 TCP ports against ONE literal
in-scope IP. The controller fixes the argv entirely; the model supplies only
the target. Port range/intensity can never be increased by model output.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..scope import validate_target
from .base import (
    ToolResult,
    ToolSpec,
    duration_since,
    resolve_binary,
    run_process,
)

NMAP_ARGV = ["-n", "-Pn", "-sT", "-sV", "--top-ports", "100", "-T2", "--reason"]
NMAP_DISPLAY = "nmap -n -Pn -sT -sV --top-ports 100 -T2 --reason"


def _run_nmap_basic(
    target: str,
    scope_items: tuple[str, ...],
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    safe_target = validate_target(target, scope_items)
    binary = resolve_binary("nmap", "On Kali/Ubuntu: sudo apt install nmap")
    argv = [binary, *NMAP_ARGV, safe_target]
    display = f"{NMAP_DISPLAY} {safe_target}"
    started = datetime.now(UTC)
    proc = run_process(argv, timeout, max_output_chars)
    return ToolResult(
        tool="nmap_basic",
        target=safe_target,
        display=display,
        returncode=proc.returncode,
        output=proc.output.strip(),
        network_active=True,
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data=_parse_nmap_output(proc.output),
        error="timeout" if proc.timed_out else None,
    )


def _parse_nmap_output(output: str) -> dict:
    """Deterministically extract open/closed ports from nmap text output."""
    open_ports: list[dict] = []
    closed = 0
    filtered = 0
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
            elif len(parts) >= 2 and parts[1] == "closed":
                closed += 1
            elif len(parts) >= 2 and parts[1] == "filtered":
                filtered += 1
    counts = {"open": len(open_ports), "closed": closed, "filtered": filtered}
    return {"open_ports": open_ports, "counts": counts, "port_range": "top 100 TCP"}


def show_nmap_action(args: dict) -> str:
    return f"{NMAP_DISPLAY} {args.get('target', '?')}"


def nmap_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="nmap_basic",
        description=(
            "Bounded TCP service-discovery scan of the top 100 ports against ONE "
            "literal in-scope IP. Arguments are fixed by the controller; no flags, "
            "port ranges, or commands can be supplied. Intensity is never raised."
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
        activity="active",
        approval_level=2,
        scope_requirements=(
            "Literal IP within GRYPHOS_ALLOWED_TARGETS; enforced in code at execution time."
        ),
        result_schema={
            "type": "object",
            "properties": {
                "open_ports": {"type": "array"},
                "counts": {"type": "object"},
                "port_range": {"type": "string"},
            },
        },
        show=show_nmap_action,
        execute=lambda args, scope_items, evidence=None: _run_nmap_basic(
            str(args.get("target", "")), scope_items, timeout, out_limit
        ),
    )
