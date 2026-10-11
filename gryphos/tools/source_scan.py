"""Tool 7 — source_scan: static analysis of a user-selected Python project.

Runs Bandit with exclusions for vendor/venv/vcs directories. Optionally runs
Semgrep against a *local* rules directory (never the remote registry), so no
network egress happens during analysis. Outputs findings as file:line
references with severity and test name only — source code is never included in
results, evidence, or the model context.
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

_EXCLUDED_DIRS = (
    ".git", ".svn", ".hg", ".venv", "venv", "node_modules",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
)
_SENSITIVE_FILE_NAMES = (".env", "id_rsa", "id_ed25519", "credentials", "secrets", "secret.json")
_VENDOR_EXCLUSION = ",".join(_EXCLUDED_DIRS[:4])


def _resolve_project_dir(project_dir: str) -> str:
    root = os.path.abspath(os.path.expanduser(project_dir or ""))
    if not os.path.isdir(root):
        raise ToolError("project_dir must be an existing directory.")
    return root


def _run_bandit(root: str, timeout: int) -> tuple[int, list[dict]]:
    binary = resolve_binary("bandit", "On Ubuntu: pip install bandit (or use your local venv)")
    proc: ProcResult = run_process(
        [binary, "-r", root, "-f", "json", "-q", "-x", _VENDOR_EXCLUSION],
        timeout=timeout,
        max_output_chars=200_000,
    )
    if proc.returncode not in (0, 1):
        return proc.returncode, []
    try:
        payload = json.loads(proc.output)
    except (ValueError, TypeError):
        return proc.returncode, []
    findings: list[dict] = []
    for item in payload.get("results", []):
        filename = str(item.get("filename", ""))
        basename = os.path.basename(filename)
        if basename in _SENSITIVE_FILE_NAMES or basename.startswith("."):
            continue
        findings.append({
            "tool": "bandit",
            "file": filename,
            "line": item.get("line_number"),
            "test_id": item.get("test_id"),
            "name": item.get("test_name"),
            "severity": item.get("issue_severity"),
            "confidence": item.get("issue_confidence"),
            "issue_text": str(item.get("issue_text", ""))[:300],
            # NOTE: 'code' is deliberately stripped — findings never carry source.
        })
    return 0, findings


def _run_semgrep(root: str, rules_dir: str, timeout: int) -> list[dict]:
    rules = os.path.abspath(os.path.expanduser(rules_dir or ""))
    if not os.path.isdir(rules):
        raise ToolError("semgrep_rules_dir must be an existing local directory.")
    binary = resolve_binary("semgrep", "On Ubuntu: pip install semgrep")
    proc: ProcResult = run_process(
        [binary, "--config", rules, "--json", "-q", root],
        timeout=timeout,
        max_output_chars=200_000,
    )
    findings: list[dict] = []
    try:
        payload = json.loads(proc.output or "{}")
    except (ValueError, TypeError):
        return findings
    for result in payload.get("results", []):
        findings.append({
            "tool": "semgrep",
            "file": result.get("path"),
            "line": result.get("start", {}).get("line"),
            "rule": result.get("check_id"),
            "severity": result.get("extra", {}).get("severity"),
            "name": result.get("extra", {}).get("message", "")[:300],
        })
    findings.sort(key=lambda f: (str(f.get("file") or ""), f.get("line") or 0))
    return findings


def _run_source_scan(
    project_dir: str,
    semgrep_rules_dir: str,
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    root = _resolve_project_dir(project_dir)
    display = f"bandit -r {root}" + (f" + semgrep --config {semgrep_rules_dir}" if semgrep_rules_dir else "")
    started = datetime.now(UTC)
    bandit_findings: list[dict] = []
    semgrep_findings: list[dict] = []
    errors: list[str] = []
    semgrep_ran = bool(semgrep_rules_dir)

    try:
        _rc, bandit_findings = _run_bandit(root, timeout)
    except Exception as exc:  # noqa: BLE001 - report as a safe note, not a crash
        errors.append(f"bandit: {type(exc).__name__}: {exc}")

    if semgrep_ran:
        try:
            semgrep_findings = _run_semgrep(root, semgrep_rules_dir, timeout)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"semgrep: {type(exc).__name__}: {exc}")

    by_tool: dict[str, list[dict]] = {"bandit": bandit_findings, "semgrep": semgrep_findings}
    lines = [
        f"Static analysis of {root}",
        f"Bandit findings: {len(bandit_findings)} (candidate issues, not confirmed)",
        f"Semgrep findings: {len(semgrep_findings)}{' (local rules only, offline)' if semgrep_ran else ' (skipped)'}",
    ]
    if errors:
        lines.append("Notes:")
        lines.extend(f"- {e}" for e in errors)
    for tool in ("bandit", "semgrep"):
        for finding in by_tool[tool][:60]:
            loc = f"{finding['file']}:{finding['line']}"
            sev = finding.get("severity") or "n/a"
            name = finding.get("name") or finding.get("issue_text") or finding.get("rule") or tool
            lines.append(f"- [{tool}] {loc} ({sev}): {name}")
        if len(by_tool[tool]) > 60:
            lines.append(f"- {tool}: ... and {len(by_tool[tool]) - 60} more")
    lines.append(
        "* Findings are candidates to review, not confirmed vulnerabilities. "
        "Source file contents are never included in results or transmitted."
    )
    return ToolResult(
        tool="source_scan", target=root, display=display,
        returncode=0, output="\n".join(lines)[:max_output_chars],
        network_active=False, activity="passive",
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={
            "project_dir": root,
            "findings": {tool: by_tool[tool] for tool in by_tool},
            "counts": {tool: len(by_tool[tool]) for tool in by_tool},
            "source_transmitted": False,
            "semgrep_mode": "local-rules-offline" if semgrep_ran else "disabled",
        },
        error="; ".join(errors) if errors else None,
    )


def source_scan_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="source_scan",
        description=(
            "Run Bandit static analysis over a user-selected local Python "
            "project directory, and optionally Semgrep against a local rules "
            "directory. Reports file:line findings with severity; source code "
            "is never included in results or sent anywhere."
        ),
        purpose="Find candidate security issues in Python source without transmitting source code.",
        input_schema={
            "type": "object",
            "properties": {
                "project_dir": {
                    "type": "string",
                    "description": "Absolute path to the project directory to analyze",
                },
                "semgrep_rules_dir": {
                    "type": "string",
                    "description": "Optional absolute path to a LOCAL semgrep rules directory (offline)",
                },
            },
            "required": ["project_dir"],
            "additionalProperties": False,
        },
        risk="low",
        side_effects="None outside the analyzed directory; runs read-only analyzers locally, no network egress.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 120),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="User-selected project root only; vendored/vcs dirs excluded; no source visible outside.",
        result_schema={"type": "object", "properties": {
            "project_dir": {"type": "string"},
            "findings": {"type": "object"},
            "counts": {"type": "object"},
        }},
        execute=lambda args, scope_items, evidence=None: _run_source_scan(
            str(args.get("project_dir", "")),
            str(args.get("semgrep_rules_dir", "") or ""),
            min(timeout, 120),
            out_limit,
        ),
    )
