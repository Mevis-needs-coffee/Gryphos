"""Phase 5 — approval levels and scope-enforcement boundary tests.

Everything here is offline: sockets, DNS resolution, and subprocesses are
patched or avoided. No real network activity.
"""

from __future__ import annotations

import dataclasses
import socket
from unittest.mock import patch

import pytest
from conftest import FakeLLM, final, make_nmap_result, tool_call
from rich.console import Console

from gryphos.agent import Agent
from gryphos.approval import (
    DEFAULT_MAX_ENABLED_LEVEL,
    ApprovalRequest,
    level_allowed,
    level_impact,
    level_name,
    level_purpose,
    requires_approval,
    validate_level,
)
from gryphos.cli import AppState, handle_line
from gryphos.llm import GryphosLLM
from gryphos.scope import (
    EXPAND_SCOPE_CONFIRMATION,
    ScopeError,
    ScopeManager,
    describe_change,
    is_subset,
    resolve_and_validate,
    validate_connected_peer,
)
from gryphos.session import Session, SessionStore, new_session_id
from gryphos.tools import ToolError, ToolSpec, build_registry, validate_args

SCOPE = ("127.0.0.1/32",)
BASELINE = ("127.0.0.1/32", "::1/128")


# --- approval level policy --------------------------------------------------

def test_levels_0_to_4_defined():
    for level in range(5):
        assert level_name(level)
        assert level_purpose(level)
        assert level_impact(level)


def test_require_approval_from_level_2():
    assert requires_approval(0) is False
    assert requires_approval(1) is False
    assert requires_approval(2) is True
    assert requires_approval(3) is True
    assert requires_approval(4) is True


def test_validate_level_rejects_bad_values():
    for bad in (-1, 5, "2", 2.0, True, None):
        with pytest.raises(ValueError):
            validate_level(bad)


def test_level4_disabled_by_default():
    assert DEFAULT_MAX_ENABLED_LEVEL == 3
    assert level_allowed(4) is False
    assert level_allowed(3) is True
    assert level_allowed(4, max_enabled=4) is True


def test_approval_request_carries_level_and_requires_flag():
    req = ApprovalRequest(
        tool="tcp_banner", target="127.0.0.1", args={"target": "127.0.0.1", "port": 22},
        purpose="p", display="d", network_active=True, timeout=10, output_limit=100,
        risk="medium", side_effects="s", approval_level=3,
    )
    assert req.approval_level == 3
    assert req.approval_required is True
    record = req.to_record()
    assert record["approval_level"] == 3
    assert "Level 3" in record["approval_level_name"]


def test_approval_request_default_level_is_2():
    req = ApprovalRequest(
        tool="t", target="127.0.0.1", args={}, purpose="p", display="d",
        network_active=True, timeout=1, output_limit=1, risk="low", side_effects="s",
    )
    assert req.approval_level == 2
    assert req.approval_required is True


# --- tool spec level consistency --------------------------------------------

def _spec(**overrides) -> ToolSpec:
    base = dict(
        name="t", description="d", purpose="p",
        input_schema={"type": "object", "properties": {}},
        risk="low", side_effects="s", network_active=True,
        approval_policy="explicit", timeout=10, max_output_chars=100,
        execute=lambda *a, **k: None, activity="active", approval_level=2,
    )
    base.update(overrides)
    return ToolSpec(**base)


def test_spec_rejects_level_and_policy_mismatch():
    with pytest.raises(ValueError, match="explicit"):
        _spec(approval_level=2, approval_policy="none")
    with pytest.raises(ValueError, match="none"):
        _spec(approval_level=1, approval_policy="explicit",
              network_active=False, activity="passive")


def test_spec_rejects_passive_network_tool():
    with pytest.raises(ValueError, match="network-active"):
        _spec(approval_level=0, approval_policy="none", network_active=True,
              activity="passive")


def test_spec_requires_active_for_high_levels():
    with pytest.raises(ValueError, match="active"):
        _spec(approval_level=3, activity="passive")


def test_registry_levels_match_policy(registry):
    for spec in registry.values():
        assert 0 <= spec.approval_level <= 4
        assert spec.requires_approval == requires_approval(spec.approval_level)
        if spec.approval_level >= 2:
            assert spec.approval_policy == "explicit"
            assert spec.network_active is True
        else:
            assert spec.approval_policy == "none"
            assert spec.network_active is False


def test_registry_gates_by_max_level(settings):
    low = dataclasses.replace(settings, max_approval_level=1)
    reg = build_registry(low)
    assert all(spec.approval_level <= 1 for spec in reg.values())
    assert "nmap_basic" not in reg
    assert "tcp_banner" not in reg
    assert "summarize_evidence" in reg


def test_registry_default_includes_level3_but_not_level4(registry):
    assert registry["tcp_banner"].approval_level == 3
    assert all(spec.approval_level <= 3 for spec in registry.values())


# --- scope change guard -----------------------------------------------------

def test_scope_manager_preserves_default_baseline():
    mgr = ScopeManager(baseline=BASELINE)
    assert mgr.effective == BASELINE
    assert mgr.baseline == BASELINE


def test_scope_narrowing_allowed_without_confirmation():
    mgr = ScopeManager(baseline=BASELINE)
    record = mgr.change(("127.0.0.1/32",))
    assert record["kind"] == "narrow"
    assert record["authorization"] == "automatic-narrowing"
    assert mgr.effective == ("127.0.0.1/32",)
    assert mgr.baseline == BASELINE  # baseline untouched


def test_scope_expansion_blocked_without_token():
    mgr = ScopeManager(baseline=BASELINE)
    with pytest.raises(ScopeError, match="expansion requires"):
        mgr.change(("10.0.0.0/8",))
    assert mgr.effective == BASELINE  # unchanged
    assert mgr.changes == []


def test_scope_expansion_allowed_with_token():
    mgr = ScopeManager(baseline=BASELINE)
    record = mgr.change(("10.0.0.0/8",), confirmation=EXPAND_SCOPE_CONFIRMATION)
    assert record["kind"] == "expand"
    assert record["authorization"] == "explicit"
    assert mgr.effective == ("10.0.0.0/8",)


def test_scope_reset_restores_baseline():
    mgr = ScopeManager(baseline=BASELINE)
    mgr.change(("127.0.0.1/32",))
    assert mgr.effective == ("127.0.0.1/32",)
    record = mgr.reset()
    assert record["kind"] == "same"
    assert mgr.effective == BASELINE


def test_scope_change_rejects_malformed_entries():
    mgr = ScopeManager(baseline=BASELINE)
    with pytest.raises(ScopeError):
        mgr.change(("not-an-ip",))


def test_scope_manager_rejects_effective_outside_baseline():
    with pytest.raises(ScopeError):
        ScopeManager(baseline=BASELINE, effective=("10.0.0.0/8",))


def test_is_subset_and_describe_change():
    assert is_subset(("127.0.0.1/32",), BASELINE) is True
    assert is_subset(("10.0.0.0/8",), BASELINE) is False
    assert describe_change(BASELINE, BASELINE) == "same"
    assert describe_change(BASELINE, ("127.0.0.1/32",)) == "narrow"
    assert describe_change(BASELINE, ("10.0.0.0/8",)) == "expand"


# --- resolved-IP / peer validation ------------------------------------------

def test_resolve_and_validate_literal_ip():
    assert resolve_and_validate("127.0.0.1", SCOPE) == "127.0.0.1"


def test_resolve_and_validate_rejects_out_of_scope_literal():
    with pytest.raises(ScopeError):
        resolve_and_validate("8.8.8.8", SCOPE)


def test_resolve_and_validate_rejects_hostname_by_default():
    with pytest.raises(ScopeError, match="hostnames are not permitted"):
        resolve_and_validate("example.com", SCOPE)


def _addrinfo(*ips):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


def test_resolve_and_validate_hostname_all_in_scope():
    with patch("gryphos.scope.socket.getaddrinfo", return_value=_addrinfo("127.0.0.1")):
        assert resolve_and_validate("localhost.test", SCOPE, allow_hostnames=True) == "127.0.0.1"


def test_resolve_and_validate_hostname_mixed_set_blocked():
    with patch("gryphos.scope.socket.getaddrinfo",
               return_value=_addrinfo("127.0.0.1", "8.8.8.8")):
        with pytest.raises(ScopeError):
            resolve_and_validate("rebind.test", SCOPE, allow_hostnames=True)


def test_resolve_and_validate_hostname_unresolvable():
    def boom(*a, **k):
        raise socket.gaierror("nope")
    with patch("gryphos.scope.socket.getaddrinfo", side_effect=boom):
        with pytest.raises(ScopeError, match="Could not resolve"):
            resolve_and_validate("nope.test", SCOPE, allow_hostnames=True)


def test_validate_connected_peer():
    assert validate_connected_peer("127.0.0.1", SCOPE) == "127.0.0.1"
    with pytest.raises(ScopeError):
        validate_connected_peer("8.8.8.8", SCOPE)
    with pytest.raises(ScopeError):
        validate_connected_peer("not-an-ip", SCOPE)


# --- tcp_banner (Level 3) ---------------------------------------------------

class FakeSock:
    def __init__(self, peer="127.0.0.1", data=b""):
        self._peer = (peer, 2222)
        self._data = data
        self.closed = False
        self.timeout = None

    def getpeername(self):
        return self._peer

    def settimeout(self, value):
        self.timeout = value

    def recv(self, _n):
        return self._data

    def close(self):
        self.closed = True


def test_tcp_banner_scope_enforced_before_connect(registry):
    spec = registry["tcp_banner"]
    with patch("gryphos.tools.tcp_banner.socket.create_connection") as conn:
        with pytest.raises(ScopeError):
            spec.execute({"target": "8.8.8.8", "port": 22}, SCOPE, [])
        conn.assert_not_called()


def test_tcp_banner_reads_banner_and_sends_no_payload(registry):
    spec = registry["tcp_banner"]
    sock = FakeSock(peer="127.0.0.1", data=b"SSH-2.0-OpenSSH_9.0\r\n")
    with patch("gryphos.tools.tcp_banner.socket.create_connection", return_value=sock):
        result = spec.execute({"target": "127.0.0.1", "port": 22}, SCOPE, [])
    assert "SSH-2.0" in result.output
    assert result.data["payload_sent"] is False
    assert result.data["peer"] == "127.0.0.1"
    assert result.network_active is True
    assert sock.closed is True


def test_tcp_banner_revalidates_connected_peer(registry):
    spec = registry["tcp_banner"]
    sock = FakeSock(peer="8.8.8.8", data=b"data")
    with patch("gryphos.tools.tcp_banner.socket.create_connection", return_value=sock):
        result = spec.execute({"target": "127.0.0.1", "port": 22}, SCOPE, [])
    assert result.error is not None
    assert sock.closed is True


def test_tcp_banner_requires_port(registry):
    spec = registry["tcp_banner"]
    with pytest.raises(ToolError):
        validate_args(spec, {"target": "127.0.0.1"})


# --- agent-level gating -----------------------------------------------------

def _agent(settings, registry, script, approve=None):
    session = Session(
        session_id=new_session_id(), objective="t",
        scope_snapshot=settings.allowed_targets, model="m",
    )
    return Agent(
        FakeLLM(script), settings, registry, session,
        console=Console(width=100, force_terminal=False, color_system=None),
        approve=approve or (lambda req: True),
    ), session


def test_agent_rejects_tool_above_max_level(settings, registry):
    # Registry built with the default ceiling (includes tcp_banner L3), but the
    # active settings cap the level at 1 — the agent must refuse L3 anyway.
    low = dataclasses.replace(settings, max_approval_level=1)
    approved = []
    agent, session = _agent(
        low, registry,
        [tool_call("tcp_banner", {"target": "127.0.0.1", "port": 22}), final("ok")],
        approve=lambda req: (approved.append(req), True)[1],
    )
    with patch("gryphos.tools.tcp_banner.socket.create_connection") as conn:
        outcome = agent.run("recon", "127.0.0.1")
    conn.assert_not_called()
    approved_any = approved
    assert approved_any == []  # never even asked
    assert any(e.get("kind") == "rejected" for e in agent.evidence)
    assert outcome.status == "final"


def test_agent_records_approval_level_in_session(settings, registry):
    script = [tool_call("nmap_basic", {"target": "127.0.0.1"}), final("done")]
    agent, session = _agent(settings, registry, script)
    with patch("gryphos.tools.nmap._run_nmap_basic", return_value=make_nmap_result()):
        agent.run("recon", "127.0.0.1")
    approved = [a for a in session.approvals if a.get("decision") == "approved"]
    assert approved and approved[0]["approval_level"] == 2


def test_agent_default_approval_ui_shows_level_and_defaults_no(settings, registry):
    agent, session = _agent(settings, registry, [final()])
    req = ApprovalRequest(
        tool="tcp_banner", target="127.0.0.1", args={"target": "127.0.0.1", "port": 22},
        purpose="p", display="EXACT-ACTION", network_active=True, timeout=10,
        output_limit=100, risk="medium", side_effects="s", approval_level=3,
    )
    captured = {}
    with patch("gryphos.agent.Confirm.ask",
               side_effect=lambda *a, **k: captured.update(k) or False) as ask:
        decision = agent._default_approve(req)
    assert decision is False
    assert ask.call_args.kwargs.get("default") is False
    assert captured.get("default") is False


def test_passive_level_does_not_prompt(settings, registry):
    asked = []
    agent, session = _agent(
        settings, registry,
        [tool_call("summarize_evidence", {}), final("ok")],
        approve=lambda req: (asked.append(req), True)[1],
    )
    agent.run("summarize", "127.0.0.1")
    assert asked == []
    assert any(a.get("decision") == "auto-passive" for a in session.approvals)


# --- CLI scope commands -----------------------------------------------------

def _cli_state(settings, tmp_path):
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    llm = GryphosLLM(api_key=settings.api_key, model=settings.default_model,
                     request_timeout=5, max_retries=0)
    return AppState(
        settings=settings, llm=llm, registry=build_registry(settings),
        store=SessionStore(settings.reports_dir),
        console=Console(width=120, force_terminal=False, color_system=None),
    )


def test_cli_scope_narrow_without_confirmation(settings, tmp_path):
    state = _cli_state(settings, tmp_path)
    assert handle_line(state, "scope narrow 127.0.0.1/32") is True
    assert state.scope.effective == ("127.0.0.1/32",)


def test_cli_scope_expansion_requires_token(settings, tmp_path):
    state = _cli_state(settings, tmp_path)
    with patch.object(state.console, "input", return_value="yes"):
        handle_line(state, "scope set 10.0.0.0/8")
    assert state.scope.effective == settings.allowed_targets  # aborted


def test_cli_scope_expansion_with_token(settings, tmp_path):
    state = _cli_state(settings, tmp_path)
    with patch.object(state.console, "input", return_value=EXPAND_SCOPE_CONFIRMATION):
        handle_line(state, "scope set 10.0.0.0/8")
    assert state.scope.effective == ("10.0.0.0/8",)


def test_cli_scope_reset(settings, tmp_path):
    state = _cli_state(settings, tmp_path)
    handle_line(state, "scope narrow 127.0.0.1/32")
    assert handle_line(state, "scope reset") is True
    assert state.scope.effective == settings.allowed_targets


def test_cli_scope_rejects_invalid_entry(settings, tmp_path):
    state = _cli_state(settings, tmp_path)
    assert handle_line(state, "scope set not-an-ip") is True
    assert state.scope.effective == settings.allowed_targets
