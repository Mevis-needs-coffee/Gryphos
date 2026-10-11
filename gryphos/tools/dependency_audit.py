"""Tool 8 — dependency_audit: read-only vulnerability audit of dependency files.

Uses pip-audit against a requirements file or a supported lockfile. Exit
codes are classified: 0 = clean, 1 = vulnerabilities found, 2 = audit could
not complete (data unavailable / resolution failure). Auto-upgrade is
deliberately disabled; this tool never modifies manifests or environments.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

from .base import (
    ProcResult,
    ToolError,
    ToolResult,
    ToolSpec,
    duration_since,
    resolve_binary,
    run_process,
)

_LOCKFILE_NAMES = ("poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.lock")


def _classify(manifest: str) -> str:
    basename = os.path.basename(manifest)
    if basename in _LOCKFILE_NAMES:
        return "lockfile"
    if basename.endswith(".txt"):
        return "requirements"
    raise ToolError(
        "Manifest must be a requirements*.txt file or a supported lockfile "
        f"({', '.join(_LOCKFILE_NAMES)})."
    )


def _run_dependency_audit(
    manifest: str,
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    path = os.path.abspath(os.path.expanduser(manifest or ""))
    if not os.path.isfile(path):
        raise ToolError(f"Manifest file not found: {manifest!r}")
    kind = _classify(path)
    binary = resolve_binary("pip-audit", "On Ubuntu: pip install pip-audit")
    argv = [binary, "--json"] + (["-r", path] if kind == "requirements" else [path])
    display = f"pip-audit --json {'-r ' if kind == 'requirements' else ''}{path} (read-only, no upgrades)"
    started = datetime.now(UTC)
    proc: ProcResult = run_process(argv, timeout, max_output_chars=200_000)
    payload: dict = {}
    try:
        payload = json.loads(proc.output) if proc.output else {}
    except (ValueError, TypeError):
        payload = {}

    vulnerable: list[dict] = []
    for dep in payload.get("dependencies", []):
        vulns = dep.get("vulns") or []
        if vulns:
            vulnerable.append({
                "package": dep.get("name"),
                "installed_version": dep.get("version"),
                "vulnerabilities": [
                    {
                        "id": v.get("id"),
                        "fix_version": (v.get("fix_versions") or [None])[0],
                        "severity": v.get("severity"),
                        "description": str(v.get("description", ""))[:200],
                    }
                    for v in vulns
                ],
            })

    data_unavailable = (
        proc.returncode == 2
        or "resolv" in proc.output.lower()
        or "could not" in proc.output.lower()
    )
    if data_unavailable:
        data_unavailable = True

    summary = {
        "manifest": path,
        "kind": kind,
        "dependencies_scanned": len(payload.get("dependencies", [])),
        "vulnerable_packages": len(vulnerable),
        "clean": len(vulnerable) == 0 and not data_unavailable,
        "data_unavailable": data_unavailable,
        "auto_upgrade": "disabled",
    }
    lines = [f"pip-audit on {path} ({kind})"]
    if data_unavailable:
        lines.append(
            "Audit could not fully resolve data (advisory DB or graph resolution "
            "unavailable). This is NOT a clean result — treat coverage as unknown."
        )
    elif not vulnerable:
        lines.append("No known vulnerable dependencies detected.")
    for item in vulnerable:
        lines.append(f"- {item['package']}=={item['installed_version']}")
        for vuln in item["vulnerabilities"][:3]:
            lines.append(
                f"    {vuln['id']} (fix: {vuln['fix_version'] or 'unknown'}"
                + (f", {vuln['severity']}" if vuln.get("severity") else "") + ")"
            )
    lines.append("No fixes were applied; environment and manifests are unchanged.")
    return ToolResult(
        tool="dependency_audit", target=path, display=display,
        returncode=proc.returncode, output="\n".join(lines)[:max_output_chars],
        network_active=False, activity="passive",
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={**summary, "vulnerabilities": vulnerable},
        error="timeout" if proc.timed_out else None,
    )


def dependency_audit_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="dependency_audit",
        description=(
            "Audit a requirements*.txt file or a supported lockfile for known "
            "vulnerabilities using pip-audit. Distinguishes 'clean' from "
            "'data unavailable'. Never upgrades or modifies anything."
        ),
        purpose="Identify known vulnerable dependencies declared in manifests or lockfiles.",
        input_schema={
            "type": "object",
            "properties": {
                "manifest": {
                    "type": "string",
                    "description": (
                        "Absolute path to a requirements*.txt or supported lockfile "
                        "(poetry.lock, Pipfile.lock, uv.lock, pdm.lock)"
                    ),
                },
            },
            "required": ["manifest"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: read-only audit of the manifest; no installs, no upgrades, no network changes to targets.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 120),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="The named local manifest only.",
        result_schema={"type": "object", "properties": {
            "manifest": {"type": "string"},
            "kind": {"type": "string"},
            "vulnerable_packages": {"type": "integer"},
            "clean": {"type": "boolean"},
            "data_unavailable": {"type": "boolean"},
        }},
        execute=lambda args, scope_items, evidence=None: _run_dependency_audit(
            str(args.get("manifest", "")), min(timeout, 120), out_limit
        ),
    )
