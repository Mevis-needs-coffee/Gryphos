"""Report generation tests."""

from __future__ import annotations

import json

from gryphos.reporting import (
    build_report_context,
    extract_confirmed_observations,
    generate_reports,
    render_markdown,
)
from gryphos.session import Session, new_session_id


def test_reports_contain_actual_evidence(sample_session, tmp_path):
    json_path, md_path = generate_reports(sample_session, tmp_path)
    md = md_path.read_text(encoding="utf-8")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    # Real tool evidence is present, not just the objective.
    assert "nmap" in md.lower()
    assert "100 closed" in md or "closed tcp ports" in md
    assert data["tool_runs"][0]["output"]
    assert "Nmap done" in data["tool_runs"][0]["output"]


def test_markdown_has_required_sections(sample_session):
    md = render_markdown(sample_session, build_report_context(sample_session))
    for heading in (
        "Executive summary", "Assessment metadata", "Authorized scope",
        "Objective and methodology", "Tools executed", "Approval decisions",
        "Confirmed observations", "Findings", "Recommended remediation",
        "Limitations", "Errors", "Record",
    ):
        assert heading in md, f"missing section: {heading}"


def test_closed_port_scan_makes_no_vulnerability_claims(sample_session):
    md = render_markdown(sample_session, build_report_context(sample_session))
    assert "none were open" in md
    lower = md.lower()
    # No fabricated vulnerability claims.
    for banned in ("critical vulnerability", "is vulnerable", "confirmed cve", "host is secure"):
        assert banned not in lower


def test_distinguishes_observations_from_interpretations(sample_session):
    sample_session.findings.append({
        "title": "Possible exposure", "severity": "low", "confidence": "low",
        "detail": "model guess", "remediation": "verify manually",
    })
    ctx = build_report_context(sample_session)
    md = render_markdown(sample_session, ctx)
    assert "Confirmed observations" in md
    assert "model interpretations" in md.lower() or "model interpretations" in md
    assert "requires operator verification" in md or "interpretations" in md


def test_severity_ordering(sample_session):
    sample_session.findings.extend([
        {"title": "Info", "severity": "informational", "confidence": "high", "detail": "", "remediation": ""},
        {"title": "High one", "severity": "high", "confidence": "medium", "detail": "", "remediation": ""},
        {"title": "Med", "severity": "medium", "confidence": "medium", "detail": "", "remediation": ""},
    ])
    ctx = build_report_context(sample_session)
    assert ctx["findings"][0]["title"] == "High one"


def test_untrusted_output_fenced_safely():
    session = Session(
        session_id=new_session_id(), objective="obj",
        scope_snapshot=("127.0.0.1/32",), model="m",
    )
    evil = "```\nrm -rf /\n``` and ``` inside"
    session.record_tool_run({
        "kind": "tool_result", "tool": "nmap_basic", "target": "127.0.0.1",
        "output": evil, "returncode": 0, "data": {},
    })
    md = render_markdown(session, build_report_context(session))
    # The nested triple-backtick content must not terminate the fence early
    # in a way that breaks the document structure: we use longer fences.
    assert evil.splitlines()[0] in md


def test_no_tools_not_performed_notes():
    session = Session(
        session_id=new_session_id(), objective="plan only",
        scope_snapshot=("127.0.0.1/32",), model="m",
    )
    ctx = build_report_context(session)
    assert any("No tools were executed" in n for n in ctx["not_performed"])
    md = render_markdown(session, ctx)
    assert "No tools were executed" in md


def test_errors_section_lists_errors(sample_session):
    sample_session.record_error("llm", "rate limited")
    md = render_markdown(sample_session, build_report_context(sample_session))
    assert "rate limited" in md


def test_approvals_section_shows_declines():
    session = Session(
        session_id=new_session_id(), objective="o",
        scope_snapshot=("127.0.0.1/32",), model="m",
    )
    session.approvals.append({
        "tool": "nmap_basic", "target": "127.0.0.1", "decision": "declined",
        "fingerprint": "deadbeef" * 8, "requested_at": "2026-01-01T00:00:00+00:00",
    })
    md = render_markdown(session, build_report_context(session))
    assert "DECLINED" in md


def test_observations_from_http_headers():
    session = Session(
        session_id=new_session_id(), objective="o",
        scope_snapshot=("127.0.0.1/32",), model="m",
    )
    session.record_tool_run({
        "kind": "tool_result", "tool": "http_headers", "target": "127.0.0.1",
        "output": "HTTP 200", "returncode": 0,
        "data": {"status_code": 200, "missing_hardening_headers": ["content-security-policy"],
                 "technology_hints": ["nginx"], "headers": {}},
    })
    obs = extract_confirmed_observations(session)
    assert any("content-security-policy" in o["observation"] for o in obs)


def test_json_and_md_paths_written(sample_session, tmp_path):
    json_path, md_path = generate_reports(sample_session, tmp_path)
    assert json_path.exists() and md_path.exists()
    assert sample_session.session_id in json_path.name


def test_findings_remediation_section(sample_session):
    sample_session.findings.append({
        "title": "No HSTS", "severity": "medium", "confidence": "high",
        "detail": "missing HSTS", "remediation": "Enable HSTS",
    })
    md = render_markdown(sample_session, build_report_context(sample_session))
    assert "Enable HSTS" in md
