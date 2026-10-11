"""Report generation tests."""

from __future__ import annotations

import json

from gryphos.reporting import (
    build_report_context,
    escape_code,
    escape_markdown,
    extract_confirmed_observations,
    generate_reports,
    render_markdown,
)
from gryphos.session import Session, SessionStore, new_session_id


def test_reports_contain_actual_evidence(sample_session, tmp_path):
    json_path, md_path = generate_reports(sample_session, tmp_path)
    md = md_path.read_text(encoding="utf-8")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    # Real tool evidence is present, not just the objective.
    assert "nmap" in md.lower()
    assert "100 closed" in md or "closed tcp ports" in md
    assert data["tool_runs"][0]["output"]
    assert "Nmap done" in data["tool_runs"][0]["output"]


def test_report_json_matches_stored_session_and_keeps_context(sample_session, tmp_path):
    store = SessionStore(tmp_path / "sessions")
    json_path, _ = generate_reports(sample_session, tmp_path / "reports")
    report_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert "report_context" in report_data
    assert report_data["report_context"]["tools_executed"] == ["nmap_basic"]

    # The session store writes to its own directory; the stored record must keep
    # the report context (no clobbering) and remain the same redacted content.
    store.save(sample_session)
    stored = store.load(sample_session.session_id)
    assert stored.report_context is not None
    assert stored.report_json == str(json_path)
    assert json.loads(sample_session.to_dict()["report_context"] and
                      json.dumps(sample_session.report_context))["tools_executed"] == ["nmap_basic"]


def test_report_json_redacts_secrets(sample_session, tmp_path):
    key = "sk-or-v1-Zyxw9876543210Secret"
    sample_session.tool_runs[0]["output"] = sample_session.tool_runs[0]["output"] + "\n" + key
    sample_session.findings.append({"title": f"Leak {key}", "severity": "low"})
    json_path, md_path = generate_reports(sample_session, tmp_path)
    assert key not in json_path.read_text(encoding="utf-8")
    assert key not in md_path.read_text(encoding="utf-8")


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


def test_escape_helpers():
    # Links are neutralized; newlines collapse; backticks cannot break a code span.
    assert escape_markdown("[click](http://evil)") == r"\[click\](http://evil)"
    assert "a\nb" not in escape_markdown("a\nb")
    assert escape_markdown("a\nb") == "a b"
    assert escape_code("a`b") == "a'b"
    assert "<script>" not in escape_markdown("<script>")
    assert r"\<script\>" in escape_markdown("<script>")


def test_markdown_link_injection_neutralized():
    session = Session(
        session_id=new_session_id(), objective="o",
        scope_snapshot=("127.0.0.1/32",), model="m",
    )
    session.findings.append({
        "title": "[click](http://evil.example)", "severity": "low", "confidence": "low",
        "detail": "see [here](javascript:alert(1))", "remediation": "fix it",
    })
    session.record_error("model", "boom [x](http://evil.example)")
    md = render_markdown(session, build_report_context(session))
    # The clickable anchor sequences are gone; brackets are escaped everywhere.
    assert "[click](http://evil.example)" not in md
    assert "[here](javascript:alert(1))" not in md


def test_multiline_untrusted_prose_fenced():
    session = Session(
        session_id=new_session_id(), objective="o",
        scope_snapshot=("127.0.0.1/32",), model="m",
    )
    hostile = "real line\n- [x] forged list item\n```fake fence```"
    session.final_assessment = hostile
    md = render_markdown(session, build_report_context(session))
    # Multi-line untrusted prose is wrapped in a longer fence (4 backticks here,
    # because the content itself contains a triple-backtick run).
    assert "````text\nreal line\n- [x] forged list item\n```fake fence```\n````" in md


def test_no_open_ports_secure_caveat_present(sample_session):
    md = render_markdown(sample_session, build_report_context(sample_session))
    assert "does NOT mean the system is secure" in md
    assert "No CVE identifiers" in md
    assert "unverified hypotheses" in md.lower()


def test_overlapping_fences_do_not_break_executive_summary(tmp_path):
    # Multi-line fallback finals (Phase Eight) render as an extra-safe fence.
    session = Session(
        session_id=new_session_id(), objective="o",
        scope_snapshot=("127.0.0.1/32",), model="m",
    )
    session.final_assessment = (
        "AI request failed: API server down\n\nEvidence collected so far:\n"
        "Evidence summary: 1 fact(s), 1 tool result(s)\n- 127.0.0.1: 2 open port(s)"
    )
    json_path, md_path = generate_reports(session, tmp_path)
    md = md_path.read_text(encoding="utf-8")
    assert "Evidence summary: 1 fact(s)" in md
    assert json.loads(json_path.read_text(encoding="utf-8"))["final_assessment"]


def test_incomplete_check_note_for_missing_tools(sample_session):
    md = render_markdown(sample_session, build_report_context(sample_session))
    assert "was not executed" in md
    for name in ("http_headers", "tls_cert", "http_redirects"):
        assert f"{name} was not executed" in md
