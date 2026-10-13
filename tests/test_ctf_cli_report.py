"""CTF report writer and CLI `solve` dispatch (offline)."""

from __future__ import annotations

import dataclasses
import json

from rich.console import Console

from gryphos import cli
from gryphos.cli import AppState, handle_line
from gryphos.ctf import SolveOutcome
from gryphos.ctf.report import build_ctf_markdown, generate_ctf_report
from gryphos.llm import GryphosLLM
from gryphos.session import Session, SessionStore, new_session_id
from gryphos.tools import build_registry


def write_challenge(root, cid="warmup"):
    d = root / cid
    d.mkdir(parents=True)
    (d / "challenge.json").write_text(json.dumps({
        "id": cid, "name": "Warmup", "category": "misc",
        "description": "Find it.", "task": "Find the flag.",
    }), encoding="utf-8")
    (d / "notes.txt").write_text("hi", encoding="utf-8")
    return d


def make_state(settings, console):
    return AppState(
        settings=settings,
        llm=GryphosLLM(api_key=settings.api_key, model=settings.default_model,
                       request_timeout=5, max_retries=0),
        registry=build_registry(settings),
        store=SessionStore(settings.reports_dir),
        console=console,
    )


def make_session():
    return Session(
        session_id=new_session_id(), objective="[ctf] Warmup",
        scope_snapshot=(), model="test/model", target=None,
    )


# --- report -----------------------------------------------------------------

def test_report_markdown_has_sections_and_honesty(tmp_path):
    ch = write_challenge(tmp_path)
    session = make_session()
    session.challenge = {
        "id": "warmup", "name": "Warmup", "category": "misc",
        "description": "Find it.", "task": "Find the flag.", "files": ["notes.txt"],
    }
    session.solve_plan = {"items": [{"id": "T1", "description": "inspect", "status": "completed"}]}
    session.flag_candidates = [
        {"value": "flag{fake}", "status": "unverified", "verifier": "detector", "source": "scan"}
    ]
    session.final_assessment = "No flag verified."
    outcome = {"status": "unsolved", "solved": False, "message": "No flag verified.",
               "plan": session.solve_plan, "flag_candidates": session.flag_candidates,
               "hypotheses": [], "evidence": session.evidence}
    md = build_ctf_markdown(session, outcome)
    assert "# CTF Solve Report" in md
    assert "Solved:** NO" in md
    assert "unverified" in md.lower()
    assert "honesty statement" in md.lower()


def test_report_files_written(tmp_path):
    session = make_session()
    session.challenge = {"id": "x", "name": "X", "category": "misc"}
    outcome = {"status": "solved", "solved": True, "flag": "flag{ok}", "message": "ok",
               "plan": {}, "flag_candidates": [{"value": "flag{ok}", "status": "verified",
               "verifier": "heuristic-format", "source": "obs"}],
               "hypotheses": [], "evidence": []}
    json_path, md_path = generate_ctf_report(session, outcome, tmp_path / "reports")
    assert json_path.exists() and md_path.exists()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["report_context"]["kind"] == "ctf"
    assert payload["report_context"]["solved"] is True


def test_report_omits_web_section_without_web_challenge():
    session = make_session()
    session.challenge = {"id": "x", "name": "X", "category": "misc"}
    outcome = {"status": "unsolved", "solved": False, "message": "", "plan": {},
               "flag_candidates": [], "hypotheses": [], "evidence": []}
    md = build_ctf_markdown(session, outcome)
    assert "Web activity" not in md


def test_report_includes_redacted_web_section():
    session = make_session()
    session.challenge = {
        "id": "webby", "name": "Webby", "category": "web",
        "web": {"origin": "http://127.0.0.1:8080", "lab": True,
                "max_requests": 40, "max_body_bytes": 262144},
    }
    evidence = [
        {"kind": "tool_result", "tool": "web_fetch", "command": "web_fetch(GET '/')",
         "data": {"final_status": 200, "request_url": "http://127.0.0.1:8080/"}},
        {"kind": "tool_result", "tool": "web_session", "command": "web_session(POST /login)",
         "data": {"set_cookie_names": ["sid"], "cookies": [{"name": "sid"}],
                  "security_headers": {"content-security-policy": None, "x-frame-options": "DENY"}}},
        {"kind": "tool_result", "tool": "web_analyze", "command": "web_analyze('/')",
         "data": {"endpoints": ["/admin/panel"], "forms": []}},
    ]
    outcome = {"status": "unsolved", "solved": False, "message": "", "plan": {},
               "flag_candidates": [], "hypotheses": [], "evidence": evidence}
    md = build_ctf_markdown(session, outcome)
    assert "7. Web activity" in md
    assert "http://127.0.0.1:8080" in md
    assert "sid" in md
    assert "content-security-policy" in md
    assert "/admin/panel" in md


# --- CLI --------------------------------------------------------------------

def test_solve_in_commands_and_help():
    assert "solve" in cli.COMMANDS


def test_solve_lists_challenges(settings, tmp_path):
    chdir = tmp_path / "challenges"
    write_challenge(chdir, "warmup")
    settings = dataclasses.replace(settings, ctf_challenges_dir=chdir)
    console = Console(width=120, force_terminal=False, color_system=None)
    state = make_state(settings, console)
    assert handle_line(state, "solve") is True


def test_solve_unknown_challenge_reports_error(settings, tmp_path):
    settings = dataclasses.replace(settings, ctf_challenges_dir=tmp_path / "challenges")
    console = Console(width=120, force_terminal=False, color_system=None)
    state = make_state(settings, console)
    assert handle_line(state, "solve nope") is True


def test_solve_end_to_end_with_scripted_outcome(settings, tmp_path, monkeypatch):
    chdir = tmp_path / "challenges"
    write_challenge(chdir, "warmup")
    settings = dataclasses.replace(settings, ctf_challenges_dir=chdir)
    console = Console(width=120, force_terminal=False, color_system=None)
    state = make_state(settings, console)

    def fake_run_solver(llm, settings, challenge, session=None, console=None, ask_user=None, http_post=None):
        session.challenge = challenge.to_dict()
        session.solve_plan = {"items": []}
        session.flag_candidates = [
            {"value": "flag{cli}", "status": "verified", "verifier": "heuristic-format", "source": "s"}
        ]
        return SolveOutcome(status="solved", solved=True, flag="flag{cli}", message="Solved.",
                            plan={"items": []}, flag_candidates=session.flag_candidates,
                            hypotheses=[], evidence=[])

    monkeypatch.setattr(cli, "run_solver", fake_run_solver)
    assert handle_line(state, "solve warmup") is True
    assert state.last_session is not None
    assert state.last_session.challenge["id"] == "warmup"
    # Session and report were persisted.
    assert (settings.reports_dir / f"{state.last_session.session_id}.json").exists()
    assert (settings.reports_dir / f"{state.last_session.session_id}.md").exists()
