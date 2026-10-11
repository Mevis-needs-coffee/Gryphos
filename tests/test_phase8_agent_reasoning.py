"""Phase Eight: disciplined reasoning, justification gate, evidence correlation."""

from __future__ import annotations

from unittest.mock import patch

from conftest import FakeLLM, final, make_nmap_result, tool_call
from rich.console import Console

from gryphos.agent import Agent
from gryphos.llm import LLMError
from gryphos.models import ToolCallDecision
from gryphos.session import Session, new_session_id


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


# -- justification gate ------------------------------------------------------

def test_empty_reason_rejected_before_execution(settings, registry):
    proposal = ToolCallDecision(
        kind="tool_call", tool="nmap_basic",
        args={"target": "127.0.0.1"}, reason="   ",
    )
    agent, session, llm = make_agent(settings, registry, [proposal, final("ok")])
    with patch("gryphos.tools.nmap._run_nmap_basic") as run_tool:
        outcome = agent.run("recon", "127.0.0.1")
    run_tool.assert_not_called()
    assert outcome.status == "final"
    assert session.tool_runs == []
    rejected = [e for e in agent.evidence
                if e.get("kind") == "rejected" and e.get("tool") == "nmap_basic"]
    assert rejected and "justification" in rejected[0]["reason"]


def test_passive_tool_without_justification_rejected(settings, registry):
    proposal = ToolCallDecision(
        kind="tool_call", tool="summarize_evidence", args={}, reason="",
    )
    agent, session, llm = make_agent(settings, registry, [proposal, final("ok")])
    outcome = agent.run("summarize", "127.0.0.1")
    assert outcome.status == "final"
    assert session.tool_runs == []
    assert any(e.get("kind") == "rejected" for e in agent.evidence)


def test_justified_passive_tool_still_allowed(settings, registry):
    script = [tool_call("summarize_evidence", {}), final("summarized")]
    agent, session, llm = make_agent(settings, registry, script)
    outcome = agent.run("summarize", "127.0.0.1")
    assert outcome.status == "final"
    assert session.tool_runs and session.tool_runs[0]["tool"] == "summarize_evidence"


# -- evidence digest ---------------------------------------------------------

def test_evidence_digest_passed_and_grows(settings, registry):
    script = [tool_call("nmap_basic", {"target": "127.0.0.1"}), final("done")]
    agent, session, llm = make_agent(settings, registry, script)
    with patch("gryphos.tools.nmap._run_nmap_basic",
               return_value=make_nmap_result(open_ports=True)):
        outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "final"
    assert len(llm.calls) == 2
    # Step 1: digest present but no facts yet.
    assert "Evidence summary" in llm.calls[0]["evidence_digest"]
    assert "0 fact(s)" in llm.calls[0]["evidence_digest"]
    # Step 2: digest now reflects the recorded nmap evidence.
    digest = llm.calls[1]["evidence_digest"]
    assert "1 fact(s)" in digest
    assert "open port" in digest
    assert "127.0.0.1" in digest


def test_digest_flags_cross_tool_contradiction(settings, registry):
    # nmap says no open ports, yet an HTTP probe succeeded on 443 -> contradiction.
    nmap = make_nmap_result(open_ports=False).to_evidence()
    http = {
        "kind": "tool_result", "tool": "http_headers", "target": "127.0.0.1",
        "returncode": 0, "network_active": True,
        "data": {"port": "443", "status_code": 200},
        "output": "HTTP probe succeeded",
    }
    agent, session, llm = make_agent(settings, registry, [final()])
    agent.evidence = [nmap, http]
    digest = llm.decide("x", "127.0.0.1", agent.evidence, 1, "sys", evidence_digest=None)
    assert digest  # a final is returned
    # Reproduce the digest deterministically to check it surfaces the conflict.
    from gryphos.analysis import summarize_evidence
    text = summarize_evidence([nmap, http]).output
    assert "Cross-tool contradictions" in text
    assert "http_headers" in text


# -- bounded recovery from transient API failures ----------------------------

def test_transient_llm_error_resumes_and_recovers(settings, registry):
    script = [
        LLMError("rate limited", category="rate_limit", retryable=True),
        final("recovered"),
    ]
    agent, session, llm = make_agent(settings, registry, script)
    outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "final"
    assert len(llm.calls) == 2
    assert session.warnings and "Transient" in session.warnings[0]


def test_exhausted_transient_produces_evidence_based_fallback(settings, registry):
    error = LLMError("API server down", category="server_error", retryable=True)
    script = [tool_call("nmap_basic", {"target": "127.0.0.1"}), error, error, error]
    agent, session, llm = make_agent(settings, registry, script)
    with patch("gryphos.tools.nmap._run_nmap_basic",
               return_value=make_nmap_result(open_ports=True)):
        outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "failed"
    # Decides: step 1 (tool) + step 2 (initial + 2 resume attempts = 3 calls).
    assert len(llm.calls) == 4
    assert "not an AI interpretation" in outcome.final_message
    assert "open port" in outcome.final_message
    assert outcome.errors
    assert session.tool_runs and session.tool_runs[0]["tool"] == "nmap_basic"
    assert session.final_assessment == outcome.final_message


def test_fallback_without_evidence_says_inconclusive(settings, registry):
    error = LLMError("API server down", category="server_error", retryable=True)
    agent, session, llm = make_agent(settings, registry, [error, error, error])
    outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "failed"
    assert session.tool_runs == []
    assert "Nothing can yet be concluded" in outcome.final_message


def test_non_transient_error_not_resumed(settings, registry):
    script = [LLMError("auth failed", category="auth", retryable=False)]
    agent, session, llm = make_agent(settings, registry, script)
    outcome = agent.run("recon", "127.0.0.1")
    assert outcome.status == "failed"
    assert len(llm.calls) == 1
    assert session.warnings == []


# -- evidence-based stop conditions ------------------------------------------

def test_step_limit_message_grounds_in_evidence(settings, registry):
    script = [
        tool_call("nmap_basic", {"target": "127.0.0.1"}),
        tool_call("summarize_evidence", {}),
        tool_call("summarize_evidence", {}),
        tool_call("summarize_evidence", {}),
    ]
    agent, session, llm = make_agent(settings, registry, script)
    with patch("gryphos.tools.nmap._run_nmap_basic",
               return_value=make_nmap_result(open_ports=True)):
        outcome = agent.run("keep going", "127.0.0.1")
    assert outcome.status == "steps_exhausted"
    assert "Evidence collected so far" in (outcome.final_message or "")
    assert "open port" in (outcome.final_message or "")
    assert session.final_assessment == outcome.final_message
