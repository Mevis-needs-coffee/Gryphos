"""End-to-end solver integration for an authorized network challenge (offline)."""

from __future__ import annotations

import dataclasses

from conftest import FakeLLM, tool_call
from tcpserver import MockTcpServer

from gryphos.ctf import Challenge, run_solver
from gryphos.ctf.netconfig import TargetConfig
from gryphos.ctf.report import build_ctf_markdown
from gryphos.models import FlagDecision
from gryphos.session import Session, new_session_id


def flag(value, source="observed", confidence="high"):
    return FlagDecision(kind="flag", flag=value, source=source, confidence=confidence)


def make_challenge(tmp_path, port) -> Challenge:
    return Challenge(
        id="netty",
        name="Netty",
        category="network",
        description="Enumerate the authorized target.",
        task="Find the flag.",
        root=tmp_path,
        flag_format=r"flag\{[^}]+\}",
        target=TargetConfig.from_dict({"host": "127.0.0.1", "lab": True, "ports": str(port)}),
    )


def test_net_portscan_then_flag_solves(tmp_path, settings, quiet_console):
    with MockTcpServer() as tcp:
        port = tcp.listen(banner=b"flag{net_solved}\n")
        challenge = make_challenge(tmp_path, port)
        llm = FakeLLM([
            tool_call("net_portscan", {"ports": str(port)}, reason="scan the authorized target"),
            flag("flag{net_solved}", source="net_portscan banner"),
        ])
        outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert outcome.solved is True
    assert outcome.flag == "flag{net_solved}"
    assert any(e.get("kind") == "tool_result" and e.get("tool") == "net_portscan"
               for e in outcome.evidence)


def test_plan_seeds_network_tasks_and_prompt(tmp_path, settings, quiet_console):
    from gryphos.ctf.solver import Solver

    with MockTcpServer() as tcp:
        port = tcp.listen()
        challenge = make_challenge(tmp_path, port)
        solver = Solver(FakeLLM([]), settings, challenge, console=quiet_console)
        prompt = solver.system_prompt
        descriptions = " ".join(item.description for item in solver.plan.items)
    assert "127.0.0.1" in prompt
    assert "ONLY this target" in prompt
    assert "net_portscan" in descriptions
    assert "net_clues" in descriptions


def test_net_kill_switch_disables_net_tools(tmp_path, settings, quiet_console):
    with MockTcpServer() as tcp:
        port = tcp.listen(banner=b"flag{nope}")
        challenge = make_challenge(tmp_path, port)
        disabled = dataclasses.replace(settings, ctf_net_enabled=False)
        llm = FakeLLM([tool_call("net_portscan", {"ports": str(port)}, reason="try anyway")])
        outcome = run_solver(llm, disabled, challenge, console=quiet_console)
    assert any(e.get("kind") == "rejected" and "net_portscan" in str(e) for e in outcome.evidence)


def test_network_tools_absent_without_authorization(tmp_path, settings, quiet_console):
    with MockTcpServer() as tcp:
        port = tcp.listen(banner=b"flag{unreachable}")
        challenge = Challenge(
            id="plain", name="Plain", category="misc",
            description="offline", task="offline", root=tmp_path,
        )
        llm = FakeLLM([tool_call("net_portscan", {"ports": str(port)}, reason="try")])
        outcome = run_solver(llm, settings, challenge, console=quiet_console)
    assert any(e.get("kind") == "rejected" for e in outcome.evidence)
    assert tcp.connections == []


def test_private_target_without_lab_disables_tools(tmp_path, settings, quiet_console):
    from gryphos.ctf.solver import Solver

    challenge = Challenge(
        id="priv", name="Priv", category="network", root=tmp_path,
        target=TargetConfig.from_dict({"host": "10.10.5.12", "lab": False}),
    )
    solver = Solver(FakeLLM([]), settings, challenge, console=quiet_console)
    assert solver.net_scope is None
    assert solver.net_error
    assert "net_portscan" not in solver.registry


# --- report -----------------------------------------------------------------

def test_report_includes_network_section():
    session = Session(
        session_id=new_session_id(), objective="[ctf] Netty",
        scope_snapshot=(), model="test/model", target=None,
    )
    session.challenge = {
        "id": "netty", "name": "Netty", "category": "network",
        "target": {"host": "127.0.0.1", "lab": True, "ports": "1-1024", "max_connections": 200},
    }
    evidence = [
        {"kind": "tool_result", "tool": "net_portscan", "command": "net_portscan(...)",
         "data": {"scanned": 2, "open_ports": [
             {"port": 22, "service": "ssh", "banner": "OpenSSH"}]}},
        {"kind": "tool_result", "tool": "net_http_probe", "command": "net_http_probe(...)",
         "data": {"responses": [{"url": "http://127.0.0.1:80/admin"}]}},
    ]
    outcome = {"status": "unsolved", "solved": False, "message": "", "plan": {},
               "flag_candidates": [], "hypotheses": [], "evidence": evidence}
    md = build_ctf_markdown(session, outcome)
    assert "Network activity" in md
    assert "127.0.0.1" in md
    assert "22/ssh" in md


def test_report_omits_network_section_without_target():
    session = Session(
        session_id=new_session_id(), objective="[ctf] Plain",
        scope_snapshot=(), model="test/model", target=None,
    )
    session.challenge = {"id": "x", "name": "X", "category": "misc"}
    outcome = {"status": "unsolved", "solved": False, "message": "", "plan": {},
               "flag_candidates": [], "hypotheses": [], "evidence": []}
    md = build_ctf_markdown(session, outcome)
    assert "Network activity" not in md


# --- CLI --------------------------------------------------------------------

def test_parse_solve_args_variants():
    from gryphos.cli import _parse_solve_args

    assert _parse_solve_args("") == ("", None, False)
    assert _parse_solve_args("web1") == ("web1", None, False)
    assert _parse_solve_args("web1 --target 10.0.0.1") == ("web1", "10.0.0.1", False)
    assert _parse_solve_args("web1 --target=10.0.0.1 --lab") == ("web1", "10.0.0.1", True)
    assert _parse_solve_args("web1 10.0.0.1") == ("web1", "10.0.0.1", False)


def test_apply_target_override_builds_and_replaces():
    from gryphos.cli import _apply_target_override

    plain = Challenge(id="n", name="N", category="network")
    _apply_target_override(plain, "10.0.0.1", True)
    assert plain.target.host == "10.0.0.1"
    assert plain.target.lab is True
    assert "1-1024" in plain.target.ports

    declared = Challenge(
        id="n", name="N", category="network",
        target=TargetConfig.from_dict({"host": "10.0.0.2", "lab": True, "ports": "22,80"}),
    )
    _apply_target_override(declared, "10.0.0.3", False)
    assert declared.target.host == "10.0.0.3"
    assert declared.target.lab is True  # preserved from the declared target
    assert declared.target.ports == "22,80"
