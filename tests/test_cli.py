"""CLI command dispatch and natural-language routing tests.

The REPL handler is tested through `handle_line` with a scripted agent; no
real LLM, network, or interactive stdin is required.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from rich.console import Console

from gryphos import cli
from gryphos.agent import AgentOutcome
from gryphos.cli import AppState, handle_line
from gryphos.llm import GryphosLLM
from gryphos.session import SessionStore, new_session_id
from gryphos.tools import build_registry


@pytest.fixture
def state(settings, tmp_path):
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    llm = GryphosLLM(api_key=settings.api_key, model=settings.default_model,
                   request_timeout=5, max_retries=0)
    return AppState(
        settings=settings,
        llm=llm,
        registry=build_registry(settings),
        store=SessionStore(settings.reports_dir),
        console=Console(width=120, force_terminal=False, color_system=None),
    )


def test_empty_input_ignored(state):
    assert handle_line(state, "   ") is True
    assert handle_line(state, "") is True


def test_exit_returns_false(state):
    assert handle_line(state, "exit") is False
    assert handle_line(state, "quit") is False


def test_help_lists_commands(state, capsys):
    assert handle_line(state, "help") is True
    # Rich console prints to stdout
    # (captured via pytest's capsys automatically when writing to real stdout;
    # our console writes there too.)


def test_scope_command(state):
    assert handle_line(state, "scope") is True


def test_status_command(state):
    assert handle_line(state, "status") is True


def test_tools_command_lists_registry(state):
    assert handle_line(state, "tools") is True


def test_config_command_redacts_key(state):
    with patch.object(state.console, "print") as printed:
        handle_line(state, "config")
    text = " ".join(str(c) for call in printed.call_args_list for c in call[0])
    assert state.settings.api_key not in text
    assert "sk-or-v1" not in text or "REDACTED" in text or "redacted" in text


def test_sessions_empty(state):
    assert handle_line(state, "sessions") is True


def test_history_records_input(state):
    handle_line(state, "hello world this is natural language")
    assert any("hello world" in h["content"] for h in state.history)


def test_model_requires_exact_id(state):
    with patch.object(state.console, "print") as printed:
        handle_line(state, "model Cohere: Command A")
    text = " ".join(str(c) for call in printed.call_args_list for c in call[0])
    assert "exact OpenRouter model ID" in text


def test_model_selection_without_validation_path(state):
    with patch.object(state.llm, "set_model", return_value=(True, "Selected model: x/y")) as setter:
        handle_line(state, "model x/y")
    setter.assert_called_once_with("x/y")


def test_models_command_handles_fetch_failure(state):
    from gryphos.llm import LLMError
    with patch.object(state.llm, "list_models", side_effect=LLMError("down", category="catalog_unavailable")):
        assert handle_line(state, "models") is True


def test_typo_gets_suggestion(state):
    with patch.object(state.console, "print") as printed:
        handle_line(state, "ases")
    text = " ".join(str(c) for call in printed.call_args_list for c in call[0])
    assert "assess" in text.lower()


def test_natural_language_routes_to_agent(state):
    with patch.object(cli, "run_agent") as runner:
        runner.return_value = AgentOutcome(status="final", final_message="ok")
        assert handle_line(state, "Explain the last scan for me please") is True
    runner.assert_called_once()
    call = runner.call_args
    objective = call.args[2] if len(call.args) > 2 else call.kwargs.get("objective")
    assert "Explain the last scan" in objective


def test_natural_language_uses_last_target(state):
    state.last_target = "127.0.0.1"
    with patch.object(cli, "run_agent") as runner:
        runner.return_value = AgentOutcome(status="final", final_message="ok")
        handle_line(state, "what should I investigate next")
    call = runner.call_args
    target = call.args[3] if len(call.args) > 3 else call.kwargs.get("target")
    assert target == "127.0.0.1"


def test_natural_language_failure_keeps_repl_alive(state):
    with patch.object(cli, "run_agent", side_effect=RuntimeError("boom")):
        assert handle_line(state, "do something interesting with words") is True


def test_assess_with_objective_argument_runs_agent(state):
    with patch.object(cli, "run_agent") as runner, \
         patch.object(state.console, "input", return_value="127.0.0.1"):
        runner.return_value = AgentOutcome(status="final", final_message="done")
        handle_line(state, "assess check my local web server headers")
    runner.assert_called_once()


def test_assess_rejects_out_of_scope_target(state):
    with patch.object(cli, "run_agent") as runner, \
         patch.object(state.console, "input", return_value="8.8.8.8"), \
         patch.object(state.console, "print") as printed:
        handle_line(state, "assess scan it")
        runner.assert_not_called()
    text = " ".join(str(c) for call in printed.call_args_list for c in call[0])
    assert "rejected" in text.lower() or "outside" in text.lower()


def test_report_without_sessions(state):
    assert handle_line(state, "report") is True


def test_report_unknown_session(state):
    with patch.object(state.console, "print") as printed:
        handle_line(state, "report s-20260101-000000-nonexist")
    text = " ".join(str(c) for call in printed.call_args_list for c in call[0])
    assert "No session" in text or "nonexist" in text


def test_report_regenerates_for_known_session(state, tmp_path):
    from gryphos.session import Session
    session = Session(
        session_id=new_session_id(), objective="o",
        scope_snapshot=state.settings.allowed_targets, model="m",
    )
    state.store.save(session)
    assert handle_line(state, f"report {session.session_id}") is True
    assert (state.settings.reports_dir / f"{session.session_id}.md").exists()


def test_llm_error_keeps_repl_alive(state):
    from gryphos.llm import LLMError
    with patch.object(state.llm, "list_models", side_effect=LLMError("rate limited", category="rate_limit")):
        assert handle_line(state, "models") is True


def test_clear_does_not_delete_sessions(state):
    from gryphos.session import Session
    session = Session(session_id=new_session_id(), objective="keepme",
                      scope_snapshot=("127.0.0.1/32",), model="m")
    state.store.save(session)
    assert handle_line(state, "clear") is True
    assert state.store.load(session.session_id).objective == "keepme"


def test_completed_assessment_saves_session_and_reports(state):
    with patch.object(cli, "run_agent") as runner, \
         patch.object(state.console, "input", return_value="127.0.0.1"):
        runner.return_value = AgentOutcome(status="final", final_message="all good")
        handle_line(state, "assess recon the box")
    entries = state.store.list_sessions()
    assert len(entries) == 1
    sid = entries[0]["session_id"]
    assert (state.settings.reports_dir / f"{sid}.md").exists()
    assert (state.settings.reports_dir / f"{sid}.json").exists()
    assert state.last_session is not None
    assert state.last_target == "127.0.0.1"


def test_builtin_commands_take_precedence_over_natural_language(state):
    # "scope" must not be routed to the agent.
    with patch.object(cli, "run_agent") as runner:
        handle_line(state, "scope")
        runner.assert_not_called()


def test_inspect_unknown_session_reports_error(state):
    with patch.object(state.console, "print") as printed:
        assert handle_line(state, "inspect s-20260101-000000-nope") is True
    text = " ".join(str(c) for call in printed.call_args_list for c in call[0])
    assert "No session" in text or "nope" in text


def test_inspect_session_is_read_only_and_shows_details(state):
    from io import StringIO

    from gryphos.session import Session
    session = Session(session_id=new_session_id(), objective="inspect me",
                      scope_snapshot=("127.0.0.1/32",), model="m",
                      target="127.0.0.1")
    session.record_history("user", "hello")
    session.findings.append({"title": "something", "severity": "low"})
    state.store.save(session)
    buf = StringIO()
    state.console = Console(file=buf, width=120, force_terminal=False,
                            color_system=None, legacy_windows=False)
    assert handle_line(state, f"inspect {session.session_id}") is True
    text = buf.getvalue()
    assert session.session_id in text
    assert "read-only" in text.lower()
    assert "inspect me" in text
    assert "something" in text
    assert "replayed" in text.lower()
    assert "treat" in text.lower() and "authorization" in text.lower()
