"""End-to-end solver integration for an authorized web challenge (offline)."""

from __future__ import annotations

import dataclasses

from conftest import FakeLLM, tool_call
from webserver import MockWebServer

from gryphos.ctf import Challenge, run_solver
from gryphos.ctf.webconfig import WebConfig
from gryphos.models import FlagDecision


def flag(value, source="observed", confidence="high"):
    return FlagDecision(kind="flag", flag=value, source=source, confidence=confidence)


def make_challenge(tmp_path, server):
    return Challenge(
        id="webby",
        name="Webby",
        category="web",
        description="Find the flag on the authorized origin.",
        task="Find the flag.",
        root=tmp_path,
        flag_format=r"flag\{[^}]+\}",
        web=WebConfig.from_dict({"origin": server.origin, "lab": True, "max_requests": 20}),
    )


def test_web_fetch_then_verify_solves(tmp_path, settings, quiet_console):
    with MockWebServer() as server:
        server.html("/", "<html>welcome flag{web_solved}</html>")
        challenge = make_challenge(tmp_path, server)
        llm = FakeLLM([
            tool_call("web_fetch", {"path": "/"}, reason="read the root page"),
            flag("flag{web_solved}", source="web_fetch root page"),
        ])
        outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.solved is True
    assert outcome.flag == "flag{web_solved}"
    assert any(e.get("kind") == "tool_result" and e.get("tool") == "web_fetch"
               for e in outcome.evidence)
    assert any(e.get("kind") == "flag_detected" and "web_solved" in str(e)
               for e in outcome.evidence)


def test_plan_seeds_web_tasks_with_origin(tmp_path, settings, quiet_console):
    from gryphos.ctf.solver import Solver

    with MockWebServer() as server:
        server.html("/", "nothing")
        challenge = make_challenge(tmp_path, server)
        solver = Solver(FakeLLM([]), settings, challenge, console=quiet_console)
        prompt = solver.system_prompt
        descriptions = " ".join(item.description for item in solver.plan.items)
    assert server.origin in prompt
    assert "ONLY this origin" in prompt
    assert "web_crawl" in descriptions or "web_fetch" in descriptions


def test_web_kill_switch_disables_web_tools(tmp_path, settings, quiet_console):
    with MockWebServer() as server:
        server.html("/", "flag{nope}")
        challenge = make_challenge(tmp_path, server)
        disabled = dataclasses.replace(settings, ctf_web_enabled=False)
        llm = FakeLLM([tool_call("web_fetch", {"path": "/"}, reason="try anyway")])
        outcome = run_solver(llm, disabled, challenge, console=quiet_console)
    assert any(e.get("kind") == "rejected" and "web_fetch" in str(e) for e in outcome.evidence)


def test_web_origin_not_contactable_without_authorization(tmp_path, settings, quiet_console):
    # No web block: the solver has no web tools and cannot reach any origin.
    with MockWebServer() as server:
        server.html("/", "flag{unreachable}")
        challenge = Challenge(
            id="plain", name="Plain", category="misc",
            description="offline", task="offline", root=tmp_path,
        )
        llm = FakeLLM([tool_call("web_fetch", {"path": "/"}, reason="try")])
        outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert any(e.get("kind") == "rejected" for e in outcome.evidence)
    assert server.requests == []
