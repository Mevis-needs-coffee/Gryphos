"""Bounded CTF solver loop tests (offline, scripted model)."""

from __future__ import annotations

import dataclasses

import pytest
from conftest import FakeLLM, final, tool_call

from gryphos.ctf import Challenge, run_solver
from gryphos.llm import LLMError
from gryphos.models import FlagDecision, ReplanDecision, ToolCallDecision
from gryphos.session import Session, SessionStore, new_session_id


@pytest.fixture
def challenge(tmp_path):
    (tmp_path / "notes.txt").write_text("nothing here yet", encoding="utf-8")
    (tmp_path / "flag.txt").write_text("the flag is flag{found_in_file}\n", encoding="utf-8")
    return Challenge(
        id="warmup", name="Warmup", category="misc",
        description="Find the flag.", task="Find the flag.", root=tmp_path,
    )


def make_session():
    return Session(
        session_id=new_session_id(), objective="[ctf] Warmup",
        scope_snapshot=(), model="test/model", target=None,
    )


def flag(value, source="observed", confidence="high"):
    return FlagDecision(kind="flag", flag=value, source=source, confidence=confidence)


def solver_settings(settings, **overrides):
    return dataclasses.replace(settings, **overrides)


# --- success paths ----------------------------------------------------------

def test_verified_flag_solves(challenge, settings, quiet_console):
    llm = FakeLLM([flag("flag{correct}")])
    session = make_session()
    outcome = run_solver(llm, settings, challenge, session=session, console=quiet_console)
    assert outcome.solved is True
    assert outcome.status == "solved"
    assert outcome.flag == "flag{correct}"
    assert session.challenge is not None
    assert session.challenge["status"] == "solved"


def test_tool_then_flag(challenge, settings, quiet_console):
    llm = FakeLLM([tool_call("challenge_file", {"path": "notes.txt"}, reason="inspect"),
                   flag("flag{done}", source="notes.txt")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.solved is True
    assert any(e.get("kind") == "tool_result" for e in outcome.evidence)
    assert any(e.get("kind") == "flag_verification" for e in outcome.evidence)


# --- honesty / non-solutions ------------------------------------------------

def test_wrong_format_flag_not_solved(challenge, settings, quiet_console):
    llm = FakeLLM([flag("not-a-flag"), final("No flag found.")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.solved is False
    assert outcome.status == "unsolved"
    assert outcome.flag_candidates[0]["status"] == "format_invalid"


def test_detected_flag_is_unverified_not_solved(challenge, settings, quiet_console):
    # Reading the file exposes flag{found_in_file}, which is recorded as
    # detected/unverified; the run must NOT be reported solved from detection.
    llm = FakeLLM([tool_call("challenge_file", {"path": "flag.txt"}, reason="inspect"),
                   final("A flag string was observed but not confirmed.")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.solved is False
    detected = [c for c in outcome.flag_candidates if c["status"] == "unverified"]
    assert any(c["value"] == "flag{found_in_file}" for c in detected)
    assert any(e.get("kind") == "flag_detected" for e in outcome.evidence)


# --- anti-repetition --------------------------------------------------------

def test_repeated_action_not_executed_twice(challenge, settings, quiet_console):
    llm = FakeLLM([tool_call("challenge_file", {"path": "notes.txt"}, reason="first"),
                   tool_call("challenge_file", {"path": "notes.txt"}, reason="again"),
                   final("done")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    runs = [e for e in outcome.evidence if e.get("kind") == "tool_result"]
    assert len(runs) == 1
    assert any("Duplicate action" in str(e.get("message", "")) for e in outcome.evidence)


def test_repeated_flag_candidate_ignored(challenge, settings, quiet_console):
    llm = FakeLLM([flag("bad-flag"), flag("bad-flag"), final("done")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    values = [c["value"] for c in outcome.flag_candidates]
    assert values.count("bad-flag") == 1


# --- planning, replanning, hypotheses ---------------------------------------

def replan(tasks, reason="approach changed"):
    return ReplanDecision(kind="replan", tasks=tasks, reason=reason)


def test_replan_blocks_open_tasks_and_adds_new(challenge, settings, quiet_console):
    llm = FakeLLM([replan(["try a new angle", "inspect header"]), final("done")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    items = outcome.plan["items"]
    assert any(t["status"] == "blocked" for t in items)
    assert any(t["description"] == "try a new angle" for t in items)
    assert any(e.get("kind") == "replan" and e.get("added") for e in outcome.evidence)


def test_hypothesis_recorded_on_tool_call(challenge, settings, quiet_console):
    llm = FakeLLM([
        ToolCallDecision(kind="tool_call", tool="challenge_file",
                         args={"path": "notes.txt"}, reason="inspect",
                         hypothesis="the note may hide a base64 segment"),
        final("done"),
    ])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.hypotheses
    assert any(e.get("kind") == "hypothesis" for e in outcome.evidence)


# --- budgets and failure recovery -------------------------------------------

def test_step_budget_exhaustion(challenge, settings, quiet_console):
    llm = FakeLLM([tool_call("challenge_file", {"path": "notes.txt"}, reason="x")])
    bounded = solver_settings(settings, ctf_max_steps=1)
    outcome = run_solver(llm, bounded, challenge, console=quiet_console)
    assert outcome.status == "steps_exhausted"
    assert outcome.solved is False


def test_consecutive_failures_abort(challenge, settings, quiet_console):
    llm = FakeLLM([tool_call("does_not_exist", {}, reason="a"),
                   tool_call("does_not_exist", {}, reason="b"),
                   tool_call("does_not_exist", {}, reason="c")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.status == "failed"


def test_transient_llm_error_resumes(challenge, settings, quiet_console):
    llm = FakeLLM([LLMError("rate limited", category="rate_limit", retryable=True),
                   flag("flag{after_retry}")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.solved is True


def test_out_of_scope_path_rejected(challenge, settings, quiet_console):
    llm = FakeLLM([tool_call("challenge_file", {"path": "../../etc/passwd"}, reason="escape"),
                   final("Could not proceed.")])
    outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.solved is False
    rejected = [e for e in outcome.evidence if e.get("kind") == "rejected"]
    assert rejected, "traversal must be recorded as a rejection"
    assert not any(e.get("kind") == "tool_result" for e in outcome.evidence)


# --- persistence ------------------------------------------------------------

def test_session_persistence_roundtrip(challenge, settings, quiet_console, tmp_path):
    llm = FakeLLM([flag("flag{persisted}")])
    session = make_session()
    run_solver(llm, settings, challenge, session=session, console=quiet_console)
    store = SessionStore(tmp_path / "reports")
    store.save(session)
    loaded = store.load(session.session_id)
    assert loaded.challenge is not None
    assert loaded.challenge["id"] == "warmup"
    assert loaded.solve_plan is not None
    assert loaded.flag_candidates
    assert loaded.flag_candidates[0]["status"] == "verified"
    assert loaded.model == "test/model"
