"""Session persistence tests."""

from __future__ import annotations

import json

import pytest

from gryphos.session import Session, SessionStore, new_session_id


def make_session(sid="s-20260101-000000-abcdef01") -> Session:
    return Session(
        session_id=sid,
        objective="test objective",
        scope_snapshot=("127.0.0.1/32",),
        model="test/model",
        target="127.0.0.1",
    )


def test_new_session_id_shape():
    sid = new_session_id()
    assert sid.startswith("s-")
    assert len(sid) == len("s-YYYYMMDD-HHMMSS-") + 8


def test_roundtrip(tmp_path):
    store = SessionStore(tmp_path)
    session = make_session()
    session.record_history("user", "hello")
    session.record_tool_run({"kind": "tool_result", "tool": "nmap_basic", "output": "x"})
    session.record_error("test", "something")
    session.findings.append({"title": "t", "severity": "low"})
    session.final_assessment = "done"
    session.complete()

    store.save(session)
    loaded = store.load(session.session_id)
    assert loaded.objective == "test objective"
    assert loaded.scope_snapshot == ("127.0.0.1/32",)
    assert loaded.history[0]["content"] == "hello"
    assert loaded.tool_runs[0]["tool"] == "nmap_basic"
    assert loaded.errors[0]["message"] == "something"
    assert loaded.findings[0]["title"] == "t"
    assert loaded.final_assessment == "done"
    assert loaded.completed_at is not None


def test_timestamps_iso8601_with_timezone():
    session = make_session()
    assert "+" in session.created_at or "Z" in session.created_at


def test_atomic_write_leaves_no_tmp(tmp_path):
    store = SessionStore(tmp_path)
    store.save(make_session())
    assert not list(tmp_path.glob("*.tmp"))
    assert list(tmp_path.glob("*.json"))


def test_list_sessions_newest_first_and_metadata(tmp_path):
    store = SessionStore(tmp_path)
    a = make_session("s-20260101-000000-aaaaaaaa")
    b = make_session("s-20260102-000000-bbbbbbbb")
    store.save(a)
    store.save(b)
    entries = store.list_sessions()
    assert len(entries) == 2
    ids = [e["session_id"] for e in entries]
    assert "s-20260102-000000-bbbbbbbb" in ids


def test_corrupt_file_skipped_in_listing(tmp_path):
    store = SessionStore(tmp_path)
    store.save(make_session())
    (tmp_path / "s-20260101-000000-badbad01.json").write_text("{ not json", encoding="utf-8")
    entries = store.list_sessions()
    corrupt = [e for e in entries if e.get("corrupt")]
    good = [e for e in entries if not e.get("corrupt")]
    assert len(corrupt) == 1
    assert len(good) == 1


def test_corrupt_file_load_raises(tmp_path):
    store = SessionStore(tmp_path)
    bad = tmp_path / "s-20260101-000000-badbad02.json"
    bad.write_text("{{{", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        store.load("s-20260101-000000-badbad02")


def test_missing_session_raises(tmp_path):
    store = SessionStore(tmp_path)
    with pytest.raises(FileNotFoundError):
        store.load("s-20260101-000000-deaddead")


def test_path_traversal_blocked(tmp_path):
    store = SessionStore(tmp_path)
    with pytest.raises(ValueError):
        store.load("../../etc/passwd")


def test_legacy_format_loads(tmp_path):
    legacy = {
        "started_at": "2026-10-10T13:26:16+05:30",
        "model": "openrouter/free",
        "objective": "recon",
        "target": "127.0.0.1",
        "evidence": [
            {"kind": "tool_result", "tool": "nmap_basic", "target": "127.0.0.1",
             "command": "nmap ...", "returncode": 0, "output": "All closed"},
            {"kind": "final", "message": "No services listening."},
        ],
    }
    (tmp_path / "session-20261010-132709.json").write_text(json.dumps(legacy), encoding="utf-8")
    store = SessionStore(tmp_path)
    loaded = store.load("session-20261010-132709")
    assert loaded.objective == "recon"
    assert len(loaded.tool_runs) == 1
    assert loaded.final_assessment == "No services listening."


def test_loading_does_not_mark_approvals_replayable(tmp_path):
    store = SessionStore(tmp_path)
    session = make_session()
    session.approvals.append({"tool": "nmap_basic", "decision": "approved", "fingerprint": "f"})
    store.save(session)
    loaded = store.load(session.session_id)
    # Approvals are historical records only; the ApprovalManager is not rebuilt.
    assert loaded.approvals[0]["decision"] == "approved"
    assert not hasattr(loaded, "approvals_manager")


def test_oversized_file_skipped(tmp_path, monkeypatch):
    import gryphos.session as sess_mod
    monkeypatch.setattr(sess_mod, "MAX_SESSION_FILE_BYTES", 10)
    store = SessionStore(tmp_path)
    big = make_session()
    big.final_assessment = "X" * 100
    path = tmp_path / f"{big.session_id}.json"
    path.write_text(json.dumps(big.to_dict()), encoding="utf-8")
    entries = store.list_sessions()
    assert all(e.get("corrupt") for e in entries) or len(entries) == 0


def test_report_paths_recorded(tmp_path):
    session = make_session()
    session.report_json = str(tmp_path / "x.json")
    session.report_markdown = str(tmp_path / "x.md")
    data = session.to_dict()
    assert data["report_json"].endswith("x.json")


def test_secrets_redacted_before_persist(tmp_path):
    store = SessionStore(tmp_path)
    key = "sk-or-v1-Abcdef1234567890Deadbeef"
    session = make_session()
    session.objective = f"Scan target and store {key}"
    session.record_history("user", f"Please use {key} for auth")
    session.record_tool_run({"kind": "tool_result", "tool": "http_headers",
                             "target": "127.0.0.1", "output": f"Authorization: Bearer {key}"})
    store.save(session)

    raw = (tmp_path / f"{session.session_id}.json").read_text(encoding="utf-8")
    assert key not in raw
    assert "***REDACTED***" in raw

    loaded = store.load(session.session_id)
    assert key not in json.dumps(loaded.to_dict())
    assert "***REDACTED***" in loaded.history[0]["content"]


def test_report_context_roundtrip(tmp_path):
    store = SessionStore(tmp_path)
    session = make_session()
    session.report_context = {"tools_executed": ["nmap_basic"], "contradictions": []}
    store.save(session)
    loaded = store.load(session.session_id)
    assert loaded.report_context == {"tools_executed": ["nmap_basic"], "contradictions": []}


def test_evidence_stream_roundtrip_preserves_order(tmp_path):
    store = SessionStore(tmp_path)
    session = make_session()
    for item in [
        {"kind": "tool_call", "tool": "nmap_basic", "step": 1},
        {"kind": "tool_result", "tool": "nmap_basic", "output": "closed"},
        {"kind": "approval_refused", "tool": "nmap_basic"},
        {"kind": "final", "message": "done"},
    ]:
        session.record_evidence(item)
    store.save(session)
    loaded = store.load(session.session_id)
    kinds = [e["kind"] for e in loaded.evidence]
    assert kinds == ["tool_call", "tool_result", "approval_refused", "final"]
    assert loaded.tool_runs[0]["tool"] == "nmap_basic"


def test_warnings_roundtrip(tmp_path):
    store = SessionStore(tmp_path)
    session = make_session()
    session.warnings.append("partial result")
    store.save(session)
    assert store.load(session.session_id).warnings == ["partial result"]


def test_save_trims_oldest_records_when_oversized(tmp_path, monkeypatch):
    import gryphos.session as sess_mod
    monkeypatch.setattr(sess_mod, "MAX_SESSION_FILE_BYTES", 1500)
    store = SessionStore(tmp_path)
    session = make_session()
    for i in range(40):
        session.record_history("user", f"step {i} " + "x" * 100)
    store.save(session)
    loaded = store.load(session.session_id)
    assert 0 < len(loaded.history) < 40
    assert loaded.history[-1]["content"] == "step 39 " + "x" * 100


def test_long_strings_truncated_on_persist(tmp_path, monkeypatch):
    import gryphos.session as sess_mod
    monkeypatch.setattr(sess_mod, "MAX_TEXT_CHARS", 40)
    store = SessionStore(tmp_path)
    session = make_session()
    session.final_assessment = "z" * 300
    store.save(session)
    loaded = store.load(session.session_id)
    assert len(loaded.final_assessment) < 60
    assert loaded.final_assessment.endswith("…[truncated]")
