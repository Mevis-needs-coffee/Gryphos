"""Tool 9 — secret_detect: local secret scan with hard redaction.

Runs gitleaks with --redact so even the tool's own stdout carries redacted
values. Beyond that, the parser strips Secret, Match, and line-content fields
unconditionally before anything reaches output, evidence, the terminal, the
report, or the model. Only the rule name and file:line locations are reported.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from .base import (
    ProcResult,
    ToolError,
    ToolResult,
    ToolSpec,
    duration_since,
    resolve_binary,
    run_process,
)


def _run_secret_detect(
    project_dir: str,
    timeout: int,
    max_output_chars: int,
) -> ToolResult:
    root = os.path.abspath(os.path.expanduser(project_dir or ""))
    if not os.path.isdir(root):
        raise ToolError(f"project_dir must be an existing directory: {project_dir!r}")
    binary = resolve_binary("gitleaks", "On Ubuntu: download gitleaks from https://github.com/gitleaks/gitleaks/releases")
    report_path = os.path.join(tempfile.mkdtemp(prefix="gryphos-gitleaks-"), "report.json")
    argv = [
        binary, "detect", "--source", root, "--redact", "--no-banner",
        "--exit-code", "0", "--report-format", "json", "--report-path", report_path,
    ]
    display = f"gitleaks detect --source {root} --redact (results: rule + location only)"
    started = datetime.now(UTC)
    proc: ProcResult = run_process(argv, timeout, max_output_chars=50_000)

    findings: list[dict] = []
    report_text = ""
    if os.path.isfile(report_path):
        try:
            report_text = Path(report_path).read_text(errors="replace")[:5_000_000]
        except OSError:
            report_text = ""
    try:
        payload = json.loads(report_text or "[]")
    except (ValueError, TypeError):
        payload = []
    for item in payload if isinstance(payload, list) else []:
        file_path = str(item.get("File", ""))
        rel_path = os.path.relpath(file_path, root) if file_path else ""
        # Redact unconditionally: never carry secret values or raw line text.
        findings.append({
            "rule": item.get("RuleID"),
            "file": rel_path,
            "line": item.get("StartLine"),
            "end_line": item.get("EndLine"),
            "match_preview": "<redacted>",
            "secret_preview": "<redacted>",
        })
    findings.sort(key=lambda f: (str(f.get("file") or ""), int(f.get("line") or 0)))
    counts = {"total": len(findings), "by_rule": {}}
    for finding in findings:
        rule = finding.get("rule") or "unknown"
        counts["by_rule"][rule] = counts["by_rule"].get(rule, 0) + 1

    ran_ok = proc.returncode in (0, 1) or os.path.isfile(report_path)
    lines = [f"Secret scan of {root}: {len(findings)} potential secret(s) found by gitleaks."]
    lines.append("Rule + location only (values are redacted everywhere).")
    for rule, count in sorted(counts["by_rule"].items()):
        lines.append(f"- {rule}: {count}")
    for finding in findings[:40]:
        line = finding["line"]
        end_line = finding.get("end_line")
        span = f"{line}-{end_line}" if end_line and end_line != line else str(line)
        lines.append(f"  {finding['file']}:{span} [{finding['rule']}]")
    if len(findings) > 40:
        lines.append(f"  ... and {len(findings) - 40} more")
    if not ran_ok:
        lines.append(f"Note: gitleaks did not complete normally (exit {proc.returncode}); results may be partial.")
    lines.append("No secret values were stored, transmitted, or displayed.")
    with contextlib.suppress(OSError):
        os.unlink(report_path)
    return ToolResult(
        tool="secret_detect", target=root, display=display,
        returncode=0, output="\n".join(lines)[:max_output_chars],
        network_active=False, activity="passive",
        started_at=started.isoformat(),
        duration_seconds=duration_since(started),
        data={
            "project_dir": root,
            "findings": findings,
            "counts": counts,
            "redacted": True,
            "values_retained": False,
        },
        error="timeout" if proc.timed_out else None,
    )


def secret_detect_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="secret_detect",
        description=(
            "Scan a user-selected local directory for hardcoded secrets with "
            "gitleaks (--redact). Reports only rule + file:line locations. "
            "Secret values and match text are redacted and never retained, "
            "displayed, or sent to the model."
        ),
        purpose="Locate hardcoded credentials without ever exposing their values.",
        input_schema={
            "type": "object",
            "properties": {
                "project_dir": {
                    "type": "string",
                    "description": "Absolute path to a local directory to scan for secrets",
                },
            },
            "required": ["project_dir"],
            "additionalProperties": False,
        },
        risk="low",
        side_effects="None external; runs a read-only local scan and deletes its temporary report.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 120),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements=(
            "The named local directory only. Results are rule + location with "
            "values stripped before leaving the tool."
        ),
        result_schema={"type": "object", "properties": {
            "project_dir": {"type": "string"},
            "findings": {"type": "array"},
            "counts": {"type": "object"},
            "redacted": {"type": "boolean"},
        }},
        execute=lambda args, scope_items, evidence=None: _run_secret_detect(
            str(args.get("project_dir", "")), min(timeout, 120), out_limit
        ),
    )
