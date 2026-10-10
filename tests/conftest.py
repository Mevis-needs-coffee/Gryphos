"""Shared fixtures. No network access, no real API key required."""

from __future__ import annotations

import pytest
from rich.console import Console

from gryphos.config import Settings
from gryphos.models import (
    FinalDecision,
    ToolCallDecision,
)
from gryphos.session import Session, new_session_id
from gryphos.tools import ToolResult, build_registry


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        api_key="sk-or-v1-" + "0" * 40,
        default_model="openrouter/free",
        allowed_targets=("127.0.0.1/32", "::1/128"),
        command_timeout=10,
        max_output_chars=5000,
        max_agent_steps=4,
        request_timeout=10,
        max_retries=0,
        time_budget_seconds=60,
        reports_dir=tmp_path / "reports",
        log_dir=tmp_path / "logs",
    )


@pytest.fixture
def registry(settings):
    return build_registry(settings)


@pytest.fixture
def quiet_console() -> Console:
    return Console(width=100, force_terminal=False, color_system=None)


class FakeLLM:
    """Scripted LLM: replays pre-built decisions in order."""

    def __init__(self, script: list, model: str = "test/model"):
        self.script = list(script)
        self.model = model
        self.calls: list[dict] = []

    def decide(self, objective, target, evidence, step, system_prompt, history=None):
        self.calls.append({"objective": objective, "target": target, "step": step, "evidence": list(evidence)})
        if not self.script:
            return FinalDecision(kind="final", message="Scripted LLM exhausted; finalizing.")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def tool_call(tool: str, args: dict, reason: str = "because") -> ToolCallDecision:
    return ToolCallDecision(kind="tool_call", tool=tool, args=args, reason=reason)


def final(message: str = "Analysis complete.", findings: list | None = None) -> FinalDecision:
    return FinalDecision(kind="final", message=message, findings=findings or [])


def make_nmap_result(target: str = "127.0.0.1", open_ports: bool = False) -> ToolResult:
    if open_ports:
        output = (
            "PORT     STATE SERVICE VERSION\n"
            "80/tcp   open  http    nginx 1.24\n"
            "22/tcp   open  ssh     OpenSSH 9.0\n"
        )
        data = {"open_ports": [
            {"port": "80/tcp", "service": "http", "version": "nginx 1.24"},
            {"port": "22/tcp", "service": "ssh", "version": "OpenSSH 9.0"},
        ], "non_open_count": 0}
    else:
        output = "Not shown: 100 closed tcp ports (conn-refused)\nNmap done: 1 IP address"
        data = {"open_ports": [], "non_open_count": 100}
    return ToolResult(
        tool="nmap_basic", target=target,
        display=f"nmap -n -Pn -sT -sV --top-ports 100 -T2 --reason {target}",
        returncode=0, output=output, network_active=True, data=data,
    )


@pytest.fixture
def sample_session(settings) -> Session:
    session = Session(
        session_id=new_session_id(),
        objective="Check local services",
        scope_snapshot=settings.allowed_targets,
        model="test/model",
        target="127.0.0.1",
    )
    result = make_nmap_result("127.0.0.1", open_ports=False)
    session.record_tool_run(result.to_evidence())
    session.approvals.append({
        "tool": "nmap_basic", "target": "127.0.0.1",
        "decision": "approved", "fingerprint": "abc123", "requested_at": "2026-01-01T00:00:00+00:00",
    })
    session.final_assessment = "No open ports among the top 100 TCP ports on 127.0.0.1."
    session.complete()
    return session
