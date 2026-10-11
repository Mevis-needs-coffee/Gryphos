"""Tool 6 — local_audit: read-only Linux system audit snapshots.

Runs fixed, read-only audit commands and reports their text bounded. No state
is ever changed: no service restarts, no firewall mutations, no package
operations. Lynis is offered as an optional mode only when installed and only
in quick/read-only mode.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime

from .base import ProcResult, ToolResult, ToolSpec, duration_since, run_process

_MODES: dict[str, tuple[str, str]] = {
    "services": (
        "systemctl --no-pager --plain list-units --type=service --state=running",
        "running systemd services (read-only)",
    ),
    "firewall": (
        "nft list ruleset",
        "current nftables ruleset (read-only listing; may require root)",
    ),
    "journal": (
        "journalctl --no-pager --no-hostname -n 200",
        "last 200 journal lines (read-only; may require the adm/systemd-journal group)",
    ),
    "lynis": (
        "lynis audit system --quick --no-colors --quiet",
        "Lynis quick audit (read-only recommendations; requires root; bounded output)",
    ),
}


def _run_local_audit(
    mode: str,
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    if mode not in _MODES:
        from .base import ToolError

        raise ToolError(f"Unknown audit mode {mode!r}. Modes: {', '.join(sorted(_MODES))}")
    argv_line, note = _MODES[mode]
    started = datetime.now(UTC)
    argv = argv_line.split(" ")
    binary = argv[0]
    if not shutil.which(binary):
        from .base import ToolDependencyError

        raise ToolDependencyError(f"{binary} is not installed. {note}")
    # Reports run as the invoking user; privileges are never escalated.
    proc: ProcResult = run_process(argv, timeout, max_output_chars)
    display = f"{argv_line} (read-only)"
    summary = {
        "mode": mode,
        "command": argv[0],
        "read_only": True,
        "privilege_escalation": "never (runs as the current user)",
    }
    lines = [f"{argv_line} (read-only, no changes made)"]
    if proc.timed_out:
        lines.append(f"[timed out after {timeout}s; showing partial output]")
    if proc.returncode == 0:
        lines.append(proc.output.strip()[:max_output_chars])
    else:
        lines.append(
            f"Command exited {proc.returncode}. Output may be empty because it "
            f"requires privileges: {note}\n{proc.output.strip()[:max_output_chars]}"
        )
    return ToolResult(
        tool="local_audit", target="local system", display=display,
        returncode=proc.returncode, output="\n".join(lines)[:max_output_chars],
        network_active=False, activity="passive",
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data=summary,
        error="timeout" if proc.timed_out else None,
    )


def local_audit_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="local_audit",
        description=(
            "Run one read-only Linux audit snapshot. Modes: services (running "
            "systemd services), firewall (current nftables ruleset), journal "
            "(last 200 log lines), lynis (quick Lynis audit if installed). "
            "Nothing is changed and privileges are never elevated."
        ),
        purpose="Gather bounded, read-only system state for local hardening review.",
        input_schema={
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["services", "firewall", "journal", "lynis"],
                    "description": "Which read-only audit to run.",
                },
            },
            "required": ["mode"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: only read-only commands on this host.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="No network targets; inspects the local host only.",
        result_schema={"type": "object", "properties": {
            "mode": {"type": "string"},
            "command": {"type": "string"},
            "read_only": {"type": "boolean"},
        }},
        execute=lambda args, scope_items, evidence=None: _run_local_audit(
            str(args.get("mode", "")), min(timeout, 30), out_limit
        ),
    )
