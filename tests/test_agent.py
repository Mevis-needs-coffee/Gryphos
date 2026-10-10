"""Agent loop tests: bounds, approvals, refusal, registry-only dispatch."""

from __future__ import annotations

from unittest.mock import patch

from conftest import FakeLLM, final, make_nmap_result, tool_call
from rich.console import Console

from gryphos.agent import Agent, run_agent
from gryphos.llm import LLMError, LLMOutputError
from gryphos.models import ClarificationDecision, ErrorDecision
from gryphos.session import Session, new_session_id

SCOPE = ("127.0.0.1/32", "::1/128")


def make_agent(settings, registry, script, approve=None, ask_user=None, console=None):
    session = Session(
        session_id=new_session_id(),
        objective="test",
        scope_snapshot=settings.allowed_targets,
        model="test/model",
    )
    llm = FakeLLM(script)
    agent = Agent(
        llm, settings, registry, session,
        console=console or Console(width=100, force_terminal=False, color_system=None),
        approve=approve or (lambda req: True),
        ask_user=ask_user or (lambda q: "answer"),
    )
    return agent, session, llm


def test_final_without_tools(settings, registry):
    agent, session, llm = make_agent(settings, registry, [final("no tools needed")])
    outcome = agent.run("explain something", "127.0.0.1")
    assert outcome.status == "final"
    assert outcome.final_message == "no tools needed"
    assert session.tool_runs == []


def test_out_of_scope_target_rejected_before_loop(settings, registry):
    agent, session, llm = make_agent(settings, registry, [final()])
    outcome = agent.run("scan it", "8.8.8.8")
    assert outcome.status == "failed"
    assert llm.calls == []  # model never invoked


def test_hostname_target_rejected(settings, registry):
    agent, session, llm = make_agent(settings, registry, [final()])
    outcome = agent.run("scan it", "evil.example.com")
    assert outcome.status == "failed"
    assert llm.calls == []


def test_approved_tool_executes_and_records(settings, registry):
    script = [tool_call("nmap_basic", {"target": "127.0.0.1"}), final("done")]
    agent, session, llm = make_agent(settings, registry, script)
    with patch("gryphos.tools.nmap._run_nmap_basic", return_value=make_nmap_result()) as run_tool:
        outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "final"
    assert len(session.tool_runs) == 1
    assert session.tool_runs[0]["tool"] == "nmap_basic"
    assert any(a["decision"] == "approved" for a in session.approvals)
    run_tool.assert_called_once()


def test_refused_tool_never_executes(settings, registry):
    script = [tool_call("nmap_basic", {"target": "127.0.0.1"}), final("ok")]
    agent, session, llm = make_agent(settings, registry, script, approve=lambda req: False)
    with patch("gryphos.tools.nmap._run_nmap_basic") as run_tool:
        outcome = agent.run("recon", "127.0.0.1")
    run_tool.assert_not_called()
    assert session.tool_runs == []
    assert any(a["decision"] == "declined" for a in session.approvals)
    assert any(e.get("kind") == "approval_refused" for e in agent.evidence)


def test_unregistered_tool_rejected(settings, registry):
    script = [tool_call("shell_exec", {"cmd": "rm -rf /"}), final("ok")]
    agent, session, llm = make_agent(settings, registry, script)
    outcome = agent.run("hack", "127.0.0.1")
    assert outcome.status == "final"
    assert session.tool_runs == []
    assert any(e.get("kind") == "rejected" for e in agent.evidence)


def test_tool_with_injected_flags_rejected(settings, registry):
    script = [tool_call("nmap_basic", {"target": "127.0.0.1", "flags": "-sS"}), final("ok")]
    agent, session, llm = make_agent(settings, registry, script)
    with patch("gryphos.tools.nmap._run_nmap_basic") as run_tool:
        agent.run("recon", "127.0.0.1")
    run_tool.assert_not_called()


def test_out_of_scope_proposal_rejected_inside_loop(settings, registry):
    script = [tool_call("nmap_basic", {"target": "8.8.8.8"}), final("ok")]
    agent, session, llm = make_agent(settings, registry, script)
    with patch("gryphos.tools.nmap._run_nmap_basic") as run_tool:
        agent.run("recon", "127.0.0.1")
    run_tool.assert_not_called()


def test_target_mismatch_with_session_rejected(settings, registry):
    script = [tool_call("nmap_basic", {"target": "::1"}), final("ok")]
    agent, session, llm = make_agent(settings, registry, script)
    with patch("gryphos.tools.nmap._run_nmap_basic") as run_tool:
        agent.run("recon", "127.0.0.1")
    run_tool.assert_not_called()


def test_duplicate_tool_call_prevented(settings, registry):
    script = [
        tool_call("nmap_basic", {"target": "127.0.0.1"}),
        tool_call("nmap_basic", {"target": "127.0.0.1"}),  # duplicate
        final("done"),
    ]
    agent, session, llm = make_agent(settings, registry, script)
    calls = {"count": 0}

    def fake_execute(args, scope, evidence):
        calls["count"] += 1
        return make_nmap_result()

    with patch.object(registry["nmap_basic"], "execute", side_effect=fake_execute):
        outcome = agent.run("recon", "127.0.0.1")
    assert calls["count"] == 1
    assert outcome.status == "final"


def test_step_limit_enforced(settings, registry):
    script = [tool_call("summarize_evidence", {}) for _ in range(10)]
    agent, session, llm = make_agent(settings, registry, script)
    outcome = agent.run("keep going", "127.0.0.1")
    assert outcome.status == "steps_exhausted"
    assert len(llm.calls) == settings.max_agent_steps


def test_time_budget_enforced(settings, registry):
    agent, session, llm = make_agent(settings, registry, [final()])
    with patch("gryphos.agent.time.monotonic", side_effect=[0, 10_000]):
        outcome = agent.run("slow", "127.0.0.1")
    assert outcome.status == "time_budget"
    assert llm.calls == []


def test_llm_api_failure_stops_safely(settings, registry):
    agent, session, llm = make_agent(
        settings, registry,
        [LLMError("auth failed", category="auth"), final()],
    )
    outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "failed"
    assert session.tool_runs == []


def test_llm_invalid_output_stops_safely(settings, registry):
    agent, session, llm = make_agent(settings, registry, [LLMOutputError("bad json")])
    outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "failed"


def test_model_error_decision_reported(settings, registry):
    agent, session, llm = make_agent(
        settings, registry, [ErrorDecision(kind="error", message="cannot proceed safely")]
    )
    outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "failed"
    assert "cannot proceed safely" in (outcome.final_message or "")


def test_clarification_flow(settings, registry):
    script = [
        ClarificationDecision(kind="clarification", question="Which port?"),
        final("answered"),
    ]
    asked = []
    agent, session, llm = make_agent(
        settings, registry, script, ask_user=lambda q: (asked.append(q), "8080")[1]
    )
    outcome = agent.run("check web", "127.0.0.1")
    assert asked == ["Which port?"]
    assert outcome.status == "final"
    assert any(h.get("role") == "user" and "8080" in h["content"] for h in session.history)


def test_clarification_empty_answer_recorded(settings, registry):
    script = [
        ClarificationDecision(kind="clarification", question="Target?"),
        final(),
    ]
    agent, session, llm = make_agent(settings, registry, script, ask_user=lambda q: "")
    agent.run("go", "127.0.0.1")
    clar = [e for e in agent.evidence if e.get("kind") == "clarification"]
    assert clar and clar[0]["answer"] == "(no answer provided)"


def test_keyboard_interrupt_during_approval_cancels(settings, registry):
    def approve(req):
        raise KeyboardInterrupt

    agent, session, llm = make_agent(
        settings, registry, [tool_call("nmap_basic", {"target": "127.0.0.1"}), final()],
        approve=approve,
    )
    with patch("gryphos.tools.nmap._run_nmap_basic") as run_tool:
        outcome = agent.run("recon", "127.0.0.1")
    run_tool.assert_not_called()
    assert outcome.status == "cancelled"


def test_passive_tool_runs_without_network(settings, registry):
    script = [tool_call("summarize_evidence", {}), final("summarized")]
    agent, session, llm = make_agent(settings, registry, script)
    with patch("gryphos.tools.net.requests.request") as req:
        outcome = agent.run("summarize", "127.0.0.1")
    req.assert_not_called()
    assert outcome.status == "final"
    assert session.tool_runs[0]["tool"] == "summarize_evidence"


def test_tool_error_recorded_and_loop_continues(settings, registry):
    script = [tool_call("nmap_basic", {"target": "127.0.0.1"}), final("recovered")]
    agent, session, llm = make_agent(settings, registry, script)

    def boom(args, scope, evidence):
        raise RuntimeError("internal explosion")

    with patch.object(registry["nmap_basic"], "execute", side_effect=boom):
        outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "final"
    assert any(e.get("kind") == "tool_error" for e in agent.evidence)


def test_failure_streak_aborts_after_repeated_rejections(settings, registry):
    # Three consecutive out-of-scope proposals should abort before the step limit.
    script = [tool_call("nmap_basic", {"target": "8.8.8.8"}) for _ in range(6)]
    agent, session, llm = make_agent(settings, registry, script)
    outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "failed"
    assert len(llm.calls) == 3
    assert "consecutive" in (outcome.final_message or "")


def test_findings_from_final_are_recorded(settings, registry):
    f = {"title": "Missing CSP", "severity": "low", "confidence": "high",
         "detail": "no CSP header", "remediation": "add a CSP"}
    agent, session, llm = make_agent(settings, registry, [final("done", findings=[f])])
    outcome = agent.run("headers", "127.0.0.1")
    assert outcome.findings[0]["title"] == "Missing CSP"
    assert session.findings[0]["severity"] == "low"


def test_run_agent_convenience(settings, registry):
    llm = FakeLLM([final("hi")])
    outcome = run_agent(llm, settings, "hello", "127.0.0.1", registry=registry)
    assert outcome.status == "final"
