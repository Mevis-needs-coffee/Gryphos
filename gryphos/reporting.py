"""Professional assessment reports.

Produces a Markdown report and matching JSON evidence file for each completed
assessment. Confirmed observations (deterministically parsed from tool
output) are presented separately from model-generated interpretations.
Untrusted tool output is fenced safely inside Markdown.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

from .analysis import correlate, detect_contradictions
from .logging_setup import redact
from .session import Session

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _fence(text: str) -> str:
    """Safely fence untrusted content that may itself contain backticks."""
    body = text.replace("\r\n", "\n")
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{body}\n{fence}"


# Characters that restructure Markdown/HTML when placed inline: code spans,
# links, and raw HTML. Emphasis markers and mid-line '#'/'-' cannot restructure
# content, and newlines are neutralized separately (see escape_markdown).
_MD_INLINE_SPECIALS = {"\\", "`", "[", "]", "<", ">"}


def escape_markdown(value: str) -> str:
    """Render an untrusted value as inline Markdown, neutralizing structure.

    Backslashes, backticks, link brackets, and HTML angle brackets are escaped so
    a hostile banner/header/model response cannot inject code spans, clickable
    links, or markup into the report. Newlines become spaces so a value cannot
    forge a list item, heading, or block.
    """
    text = redact(str(value))
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return "".join(
        f"\\{ch}" if ch in _MD_INLINE_SPECIALS else ch
        for ch in text
    )


def escape_code(value: str) -> str:
    """Escape a value destined for a backtick code span."""
    text = redact(str(value))
    text = text.replace("`", "'").replace("\r", " ").replace("\n", " ")
    return text


def _inline_or_fence(value: str) -> list[str]:
    """Render untrusted prose: inline (escaped) or fenced when multi-line."""
    text = redact(str(value))
    if "\n" in text:
        return [_fence(text)]
    return [escape_markdown(text)]


def _describe_port(port: dict) -> str:
    text = str(port.get("port", "?"))
    service = port.get("service")
    if service:
        text += f" ({service}"
        if port.get("version"):
            text += f" {port['version']}"
        text += ")"
    return text


def _describe_hop(hop: dict) -> str:
    status = hop.get("status", hop.get("error", "?"))
    return f"{hop['scheme']}://{hop['host']}:{hop['port']}{hop['path']} ({status})"


def extract_confirmed_observations(session: Session) -> list[dict]:
    """Deterministically derive observations from recorded tool evidence."""
    observations: list[dict] = []
    for run in session.tool_runs:
        tool = run.get("tool", "?")
        target = run.get("target", "?")
        data = run.get("data") or {}
        if tool == "nmap_basic":
            open_ports = data.get("open_ports") or []
            if open_ports:
                listing = ", ".join(_describe_port(p) for p in open_ports)
                observations.append({
                    "source": "nmap_basic",
                    "observation": f"Open TCP ports on {target}: {listing}.",
                    "evidence_ref": run,
                })
            elif run.get("returncode") == 0:
                observations.append({
                    "source": "nmap_basic",
                    "observation": (
                        f"The top 100 TCP ports on {target} were scanned; none were open "
                        f"(closed or filtered). Ports outside this set were not tested."
                    ),
                    "evidence_ref": run,
                })
            elif run.get("error"):
                observations.append({
                    "source": "nmap_basic",
                    "observation": f"Scan of {target} did not complete: {run.get('error')}.",
                    "evidence_ref": run,
                })
        elif tool == "http_headers":
            status = data.get("status_code")
            missing = data.get("missing_hardening_headers") or []
            hints = data.get("technology_hints") or []
            parts = [f"HTTP HEAD to {target} returned status {status}."]
            if missing:
                parts.append("Missing hardening headers: " + ", ".join(missing) + ".")
            if hints:
                parts.append("Technology hints (from response headers): " + "; ".join(hints) + ".")
            observations.append({"source": "http_headers", "observation": " ".join(parts), "evidence_ref": run})
        elif tool == "tls_cert":
            days = data.get("days_until_expiry")
            if data.get("error") or run.get("error"):
                observations.append({
                    "source": "tls_cert",
                    "observation": f"TLS handshake with {target} failed ({run.get('error') or data.get('error')}).",
                    "evidence_ref": run,
                })
            else:
                text = (
                    f"TLS certificate on {target}: subject CN={data.get('subject_cn')!r}, "
                    f"issuer CN={data.get('issuer_cn')!r}, valid until {data.get('not_after')}"
                )
                if days is not None:
                    text += f" ({days} days remaining)"
                text += "."
                observations.append({"source": "tls_cert", "observation": text, "evidence_ref": run})
        elif tool == "http_redirects":
            hops = data.get("hops") or []
            if hops:
                chain = " -> ".join(_describe_hop(h) for h in hops)
                text = f"Redirect chain from {target}: {chain}."
                if data.get("blocked"):
                    text += f" {data['blocked']}"
                observations.append({"source": "http_redirects", "observation": text, "evidence_ref": run})
        elif tool == "summarize_evidence":
            observations.append({
                "source": "summarize_evidence",
                "observation": "Session evidence was summarized (passive, no new traffic).",
                "evidence_ref": run,
            })
        elif tool == "web_tech":
            techs = [t.get("name") for t in (data.get("technologies") or []) if t.get("name")]
            if techs:
                observations.append({
                    "source": "web_tech",
                    "observation": f"Technology indicators on {target} (inferred, not confirmed): "
                                   + ", ".join(techs) + ".",
                    "evidence_ref": run,
                })
        elif tool == "local_ports":
            counts = data.get("counts") or {}
            observations.append({
                "source": "local_ports",
                "observation": (
                    f"Local listening sockets: {counts.get('total', 0)} total, "
                    f"{counts.get('exposed_wildcard', 0)} bound to all interfaces (wildcard)."
                ),
                "evidence_ref": run,
            })
        elif tool == "local_audit":
            observations.append({
                "source": "local_audit",
                "observation": (
                    f"Read-only local audit mode {data.get('mode')!r} executed "
                    f"(return code {run.get('returncode')}); no changes were made."
                ),
                "evidence_ref": run,
            })
        elif tool == "source_scan":
            counts = data.get("counts") or {}
            observations.append({
                "source": "source_scan",
                "observation": (
                    f"Static analysis of {data.get('project_dir')}: "
                    f"{counts.get('bandit', 0)} bandit and {counts.get('semgrep', 0)} "
                    "semgrep candidate finding(s); source was not transmitted."
                ),
                "evidence_ref": run,
            })
        elif tool == "dependency_audit":
            if data.get("data_unavailable"):
                text = (f"Dependency audit of {data.get('manifest')} could not complete "
                        "(data unavailable); coverage is unknown, not 'clean'.")
            elif data.get("vulnerable_packages"):
                text = (f"Dependency audit of {data.get('manifest')} found "
                        f"{data.get('vulnerable_packages')} vulnerable package(s); "
                        "no changes were applied.")
            else:
                text = f"Dependency audit of {data.get('manifest')}: no known vulnerabilities."
            observations.append({"source": "dependency_audit", "observation": text, "evidence_ref": run})
        elif tool == "secret_detect":
            total = (data.get("counts") or {}).get("total", 0)
            observations.append({
                "source": "secret_detect",
                "observation": (
                    f"Secret scan of {data.get('project_dir')} reported {total} "
                    "potential secret(s); values are redacted and were not retained."
                ),
                "evidence_ref": run,
            })
    return observations


def build_report_context(session: Session) -> dict:
    observations = extract_confirmed_observations(session)
    findings = sorted(
        session.findings,
        key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "informational")).lower(), 9),
    )
    tools_executed = sorted({r.get("tool", "?") for r in session.tool_runs})
    approvals = session.approvals
    declined = [a for a in approvals if a.get("decision") == "declined"]
    approved = [a for a in approvals if a.get("decision") == "approved"]
    not_performed = []
    if not session.tool_runs:
        not_performed.append("No tools were executed in this session; conclusions rest on no scan evidence.")
    for name in ("nmap_basic", "http_headers", "tls_cert", "http_redirects"):
        if name not in tools_executed:
            not_performed.append(f"{name} was not executed.")
    return {
        "observations": observations,
        "findings": findings,
        "tools_executed": tools_executed,
        "approvals": approvals,
        "approved": approved,
        "declined": declined,
        "not_performed": not_performed,
        "correlation": correlate(session.tool_runs),
        "contradictions": detect_contradictions(session.tool_runs),
    }


def render_markdown(session: Session, ctx: dict) -> str:
    lines: list[str] = []
    add = lines.append
    add("# Gryphos Assessment Report")
    add("")
    add(f"- **Session ID:** `{escape_code(session.session_id)}`")
    add(f"- **Created:** {escape_markdown(session.created_at)}")
    add(f"- **Completed:** {escape_markdown(session.completed_at or '(in progress)')}")
    add(f"- **Model:** `{escape_code(session.model)}`")
    add(f"- **Objective:** {escape_markdown(session.objective)}")
    add(f"- **Target:** `{escape_code(session.target or '(none)')}`")
    add("")

    add("## 1. Executive summary")
    add("")
    if session.final_assessment:
        lines.extend(_inline_or_fence(session.final_assessment))
        add("")
    else:
        add("_No final assessment was recorded for this session._")
        add("")
    if ctx["findings"]:
        worst = ctx["findings"][0]
        add(
            f"Model-recorded findings: {len(ctx['findings'])} "
            f"(highest severity: {escape_markdown(worst.get('severity', 'informational'))}). "
            "Findings are model interpretations of the evidence below and require "
            "operator verification."
        )
    else:
        add("No structured findings were recorded.")
    add("")

    add("## 2. Assessment metadata")
    add("")
    add(f"- Tools executed: {', '.join(ctx['tools_executed']) if ctx['tools_executed'] else '(none)'}")
    add(f"- Tool executions recorded: {len(session.tool_runs)}")
    add(f"- Agent errors recorded: {len(session.errors)}")
    add("")

    add("## 3. Authorized scope")
    add("")
    for item in session.scope_snapshot:
        add(f"- `{escape_code(item)}`")
    if not session.scope_snapshot:
        add("- (no scope snapshot recorded)")
    add("")
    add("All executed actions were validated against this scope in application code "
        "immediately before execution. The model cannot modify scope.")
    add("")

    add("## 4. Objective and methodology")
    add("")
    add(f"**Objective:** {escape_markdown(session.objective)}")
    add("")
    add("Gryphos proposes registered tools; every network-active action requires "
        "explicit operator approval. Arguments are validated against fixed schemas; "
        "no shell commands are ever constructed from model output.")
    add("")

    add("## 5. Tools executed")
    add("")
    if session.tool_runs:
        for index, run in enumerate(session.tool_runs, 1):
            add(f"### 5.{index} `{escape_code(run.get('tool', '?'))}` on `{escape_code(run.get('target', '?'))}`")
            add("")
            add(f"- Exact action: `{escape_code(run.get('command', ''))}`")
            add(f"- Return code: `{run.get('returncode')}`")
            if run.get("started_at"):
                add(f"- Started: {run['started_at']}")
            if run.get("duration_seconds") is not None:
                add(f"- Duration: {run['duration_seconds']}s")
            add("")
            add(_fence(str(run.get("output", "(no output)"))))
            add("")
    else:
        add("_No tools were executed._")
        add("")

    add("## 6. Approval decisions")
    add("")
    if session.approvals:
        for decision in session.approvals:
            mark = {"approved": "APPROVED", "declined": "DECLINED", "cancelled": "CANCELLED"}.get(
                str(decision.get("decision")), str(decision.get("decision", "?")).upper()
            )
            add(f"- [{mark}] `{escape_code(decision.get('tool', '?'))}` on "
                f"`{escape_code(decision.get('target', '?'))}` at "
                f"{escape_markdown(decision.get('requested_at', '?'))} "
                f"(fingerprint `{escape_code(str(decision.get('fingerprint', '')))[:12]}…`)")
    else:
        add("_No approval requests were made._")
    add("")

    add("## 7. Confirmed observations")
    add("")
    if ctx["observations"]:
        for index, obs in enumerate(ctx["observations"], 1):
            add(f"{index}. **[{escape_code(obs['source'])}]** {escape_markdown(obs['observation'])}")
    else:
        add("_No confirmed observations; no tool evidence was recorded._")
    add("")
    if ctx["correlation"]:
        add("### 7a. Cross-tool correlation")
        add("")
        for group in ctx["correlation"]:
            add(f"- `{escape_code(group['target'])}` — tools: {', '.join(escape_code(t) for t in group['tools'])} "
                f"({group['observation_count']} observation(s))")
            for note in group["notes"]:
                add(f"  - {escape_markdown(note)}")
        add("")
    if ctx["contradictions"]:
        add("### 7b. Cross-tool contradictions")
        add("")
        add("_Conflicting signals between tools are listed here for operator review; "
            "they are not resolved automatically._")
        add("")
        for item in ctx["contradictions"]:
            add(f"- **[{escape_code(item.get('severity', 'medium'))}]** {escape_markdown(item['message'])}")
        add("")

    add("## 8. Findings (model interpretations)")
    add("")
    add("_The findings below are the AI model's interpretations and **unverified "
        "hypotheses**. They are not confirmed vulnerabilities unless an observation "
        "in section 7 explicitly proves the condition. Treat every finding as "
        "requiring operator verification and manual confirmation before action. "
        "Technology labels inferred by `web_tech` are not verified._")
    add("")
    if ctx["findings"]:
        for f in ctx["findings"]:
            add(f"### {escape_markdown(f.get('title', '(untitled)'))}")
            add("")
            add(f"- Severity: **{escape_markdown(f.get('severity', 'informational'))}**")
            add(f"- Confidence: **{escape_markdown(f.get('confidence', 'medium'))}**")
            add("")
            detail = str(f.get("detail") or "").strip()
            if detail:
                lines.extend(_inline_or_fence(detail))
                add("")
    else:
        add("_No findings recorded._")
        add("")

    add("## 9. Recommended remediation")
    add("")
    remedi = [f for f in ctx["findings"] if f.get("remediation")]
    if remedi:
        for f in remedi:
            title = escape_markdown(f.get('title', 'Finding'))
            remediation = str(f.get("remediation") or "")
            if "\n" in redact(remediation):
                add(f"- **{title}:**")
                add("")
                lines.extend(_fence(remediation).splitlines())
            else:
                add(f"- **{title}:** {escape_markdown(remediation)}")
    else:
        add("_No model-supplied remediation guidance was recorded. Follow your "
            "organization's hardening baselines for any exposed services._")
    add("")

    add("## 10. Limitations and untested areas")
    add("")
    for item in ctx["not_performed"]:
        add(f"- {escape_markdown(item)}")
    add("- Only approved, registered checks were performed; this is not a full "
        "vulnerability assessment.")
    add("- An absence of open ports on a bounded probe does NOT mean the system is "
        "secure: services may be listening on ports outside the probed set, the "
        "probe covers only an approved subset, and closed/filtered results can "
        "mask a stateful host firewall.")
    add("- No CVE identifiers, affected-version claims, or external vulnerability "
        "references are asserted. Candidate findings are unverified hypotheses, "
        "not confirmed vulnerabilities.")
    add("- Service versions reported by scanners can be inaccurate; verify manually.")
    add("- No exploitation, credential testing, evasion, or persistence was attempted.")
    add("")

    add("## 11. Errors and incomplete checks")
    add("")
    if session.errors:
        for err in session.errors:
            source = escape_code(err.get('source', '?'))
            message = str(err.get('message', ''))
            if "\n" in redact(message):
                add(f"- [{source}]")
                add("")
                lines.extend(_fence(message).splitlines())
            else:
                add(f"- [{source}] {escape_markdown(message)}")
    else:
        add("_No errors recorded._")
    add("")

    add("## 12. Record")
    add("")
    add(f"- Generated: {datetime.now(UTC).isoformat()}")
    add(f"- Session ID: `{escape_code(session.session_id)}`")
    add(f"- JSON evidence: `{escape_code(session.report_json or '(pending)')}`")
    add("")
    add("> Review and sanitize this report before sharing; scan output may contain "
        "sensitive host information. AI-generated interpretations are hypotheses, "
        "not proof.")
    add("")
    return "\n".join(lines)


def generate_reports(session: Session, directory: Path) -> tuple[Path, Path]:
    """Write `<session_id>.json` evidence and `<session_id>.md` report.

    The JSON payload is the session record itself (with an embedded
    `report_context`), so `SessionStore.save` and this writer produce identical,
    redacted content and neither clobbers the other.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    ctx = build_report_context(session)
    json_path = directory / f"{session.session_id}.json"
    md_path = directory / f"{session.session_id}.md"

    session.report_json = str(json_path)
    session.report_markdown = str(md_path)
    session.report_context = {
        "confirmed_observations": [
            {"source": o["source"], "observation": o["observation"]} for o in ctx["observations"]
        ],
        "tools_executed": ctx["tools_executed"],
        "not_performed": ctx["not_performed"],
        "correlation": ctx["correlation"],
        "contradictions": ctx["contradictions"],
    }

    # `to_dict()` redacts secrets and bounds size; the Markdown is redacted too.
    _atomic_write(json_path, json.dumps(session.to_dict(), indent=2, default=str))
    _atomic_write(md_path, redact(render_markdown(session, ctx)))
    return json_path, md_path
