"""Tool registry, argument validation, and execution tests.

Network tools are tested with mocks or against localhost only; no unrelated
machines are ever scanned.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest
import requests

from gryphos.scope import ScopeError
from gryphos.tools import (
    ToolError,
    ToolSpec,
    _parse_nmap_output,
    _run_nmap_basic,
    validate_args,
)

SCOPE = ("127.0.0.1/32",)


# --- registry ---------------------------------------------------------------

def test_registry_contains_expected_tools(registry):
    assert set(registry) == {"nmap_basic", "http_headers", "http_redirects", "tls_cert", "summarize_evidence"}


def test_every_tool_requires_or_declares_policy(registry):
    for spec in registry.values():
        assert spec.approval_policy in {"explicit", "none"}
        if spec.network_active:
            assert spec.approval_policy == "explicit"
            assert spec.timeout > 0
            assert spec.max_output_chars > 0


def test_unregistered_tool_cannot_execute(registry):
    assert "shell_exec" not in registry
    assert "run_command" not in registry


def test_registry_specs_are_immutable_enough(registry):
    for spec in registry.values():
        assert isinstance(spec, ToolSpec)
        assert isinstance(spec.execute, type(lambda: None))


# --- argument validation ----------------------------------------------------

def test_validate_args_rejects_unknown_props(registry):
    spec = registry["nmap_basic"]
    with pytest.raises(ToolError, match="Unknown argument"):
        validate_args(spec, {"target": "127.0.0.1", "flags": "--script vuln"})


def test_validate_args_rejects_missing_required(registry):
    spec = registry["nmap_basic"]
    with pytest.raises(ToolError, match="Missing required"):
        validate_args(spec, {})


def test_validate_args_rejects_non_dict(registry):
    with pytest.raises(ToolError, match="JSON object"):
        validate_args(registry["nmap_basic"], "target=127.0.0.1")


def test_validate_args_rejects_extra_port_on_nmap(registry):
    with pytest.raises(ToolError, match="Unknown argument"):
        validate_args(registry["nmap_basic"], {"target": "127.0.0.1", "ports": "1-65535"})


# --- nmap -------------------------------------------------------------------

def test_nmap_argv_is_fixed_and_safe():
    with patch("gryphos.tools.shutil.which", return_value="/usr/bin/nmap"), \
         patch("gryphos.tools.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="PORT STATE\n80/tcp open http\n", stderr=""
        )
        result = _run_nmap_basic("127.0.0.1", SCOPE, timeout=5, max_output_chars=1000)
        argv = run.call_args[0][0]
        assert argv[0] == "/usr/bin/nmap"
        assert "--top-ports" in argv and "100" in argv
        assert argv[-1] == "127.0.0.1"
        assert run.call_args[1]["shell"] is False
        assert run.call_args[1]["timeout"] == 5
        assert result.data["open_ports"][0]["port"] == "80/tcp"


def test_nmap_out_of_scope_never_executes():
    with patch("gryphos.tools.subprocess.run") as run:
        with pytest.raises(ScopeError):
            _run_nmap_basic("8.8.8.8", SCOPE, timeout=5, max_output_chars=1000)
        run.assert_not_called()


def test_nmap_hostname_never_executes():
    with patch("gryphos.tools.subprocess.run") as run:
        with pytest.raises(ScopeError):
            _run_nmap_basic("evil.example.com", SCOPE, timeout=5, max_output_chars=1000)
        run.assert_not_called()


def test_nmap_missing_binary():
    with patch("gryphos.tools.shutil.which", return_value=None):
        with pytest.raises(ToolError, match="not installed"):
            _run_nmap_basic("127.0.0.1", SCOPE, timeout=5, max_output_chars=1000)


def test_nmap_timeout_returns_result_not_crash():
    def fake_run(*args, **kwargs):
        exc = subprocess.TimeoutExpired(cmd="nmap", timeout=5)
        exc.stdout = "partial"
        raise exc
    with patch("gryphos.tools.shutil.which", return_value="/usr/bin/nmap"), \
         patch("gryphos.tools.subprocess.run", side_effect=fake_run):
        result = _run_nmap_basic("127.0.0.1", SCOPE, timeout=5, max_output_chars=1000)
        assert result.returncode is None
        assert "Timed out" in result.output
        assert "partial" in result.output


def test_nmap_output_truncated():
    with patch("gryphos.tools.shutil.which", return_value="/usr/bin/nmap"), \
         patch("gryphos.tools.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="X" * 5000, stderr=""
        )
        result = _run_nmap_basic("127.0.0.1", SCOPE, timeout=5, max_output_chars=100)
        assert len(result.output) <= 100


def test_parse_nmap_open_ports():
    out = "80/tcp open http nginx\n22/tcp open ssh\n999/tcp closed something"
    data = _parse_nmap_output(out)
    assert len(data["open_ports"]) == 2
    assert data["open_ports"][0]["service"] == "http"


# --- HTTP tools with mocked transport ---------------------------------------

class FakeResponse:
    def __init__(self, status=200, headers=None, reason="OK"):
        self.status_code = status
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self.reason = reason
        self.raw = MagicMock()
        self.raw.read.return_value = b""

    def close(self):
        pass


def test_http_headers_scope_enforced(registry):
    spec = registry["http_headers"]
    with patch("gryphos.tools.requests.request") as req:
        with pytest.raises(ScopeError):
            spec.execute({"target": "8.8.8.8", "port": 80, "scheme": "http"}, SCOPE, [])
        req.assert_not_called()


def test_http_headers_reports_missing_hardening(registry):
    spec = registry["http_headers"]
    fake = FakeResponse(status=200, headers={"Server": "nginx/1.24", "Content-Type": "text/html"})
    with patch("gryphos.tools.requests.request", return_value=fake):
        result = spec.execute({"target": "127.0.0.1", "port": 80, "scheme": "http"}, SCOPE, [])
    assert result.data["status_code"] == 200
    assert "content-security-policy" in result.data["missing_hardening_headers"]
    assert result.data["technology_hints"] == ["nginx/1.24"]


def test_http_headers_request_failure_handled(registry):
    spec = registry["http_headers"]
    with patch("gryphos.tools.requests.request", side_effect=requests.ConnectionError("boom")):
        result = spec.execute({"target": "127.0.0.1", "port": 80, "scheme": "http"}, SCOPE, [])
    assert result.error == "ConnectionError"
    assert "Request failed" in result.output


def test_http_redirects_blocks_offscope_hop(registry):
    spec = registry["http_redirects"]
    redirect = FakeResponse(status=302, headers={"Location": "http://8.8.8.8/steal"})
    with patch("gryphos.tools.requests.request", return_value=redirect):
        result = spec.execute(
            {"target": "127.0.0.1", "port": 80, "scheme": "http", "path": "/"}, SCOPE, []
        )
    assert result.data["blocked"] is not None
    assert "scope policy" in result.data["blocked"]
    # Only the first hop was ever requested.
    assert len(result.data["hops"]) == 1


def test_http_redirects_blocks_hostname_hop(registry):
    spec = registry["http_redirects"]
    redirect = FakeResponse(status=301, headers={"Location": "http://evil.example.com/x"})
    with patch("gryphos.tools.requests.request", return_value=redirect):
        result = spec.execute(
            {"target": "127.0.0.1", "port": 80, "scheme": "http", "path": "/"}, SCOPE, []
        )
    assert result.data["blocked"] is not None


def test_http_redirects_traces_inscoop_chain(registry):
    spec = registry["http_redirects"]
    responses = [
        FakeResponse(status=301, headers={"Location": "http://127.0.0.1:8080/new"}),
        FakeResponse(status=200, headers={"Content-Type": "text/html"}),
    ]
    with patch("gryphos.tools.requests.request", side_effect=responses) as req:
        result = spec.execute(
            {"target": "127.0.0.1", "port": 80, "scheme": "http", "path": "/"}, SCOPE, []
        )
    assert len(result.data["hops"]) == 2
    assert result.data["hops"][1]["port"] == 8080
    assert result.data["blocked"] is None
    assert req.call_count == 2


def test_tls_cert_handshake_failure_handled(registry):
    spec = registry["tls_cert"]
    with patch("gryphos.tools.socket.create_connection", side_effect=OSError("refused")):
        result = spec.execute({"target": "127.0.0.1", "port": 443}, SCOPE, [])
    assert result.error is not None
    assert "handshake failed" in result.output


def test_tls_cert_scope_enforced(registry):
    spec = registry["tls_cert"]
    with patch("gryphos.tools.socket.create_connection") as conn:
        with pytest.raises(ScopeError):
            spec.execute({"target": "8.8.8.8", "port": 443}, SCOPE, [])
        conn.assert_not_called()


def test_tls_sni_validation(registry):
    spec = registry["tls_cert"]
    with pytest.raises(ToolError, match="server_hostname"):
        spec.execute(
            {"target": "127.0.0.1", "port": 443, "server_hostname": "http://evil"},
            SCOPE, [],
        )


# --- passive tool -----------------------------------------------------------

def test_summarize_evidence_no_network(registry):
    spec = registry["summarize_evidence"]
    evidence = [{
        "kind": "tool_result", "tool": "nmap_basic", "target": "127.0.0.1",
        "returncode": 0, "output": "...",
        "data": {"open_ports": [{"port": "80/tcp", "service": "http"}], "non_open_count": 99},
    }]
    with patch("gryphos.tools.requests.request") as req, \
         patch("gryphos.tools.subprocess.run") as run:
        result = spec.execute({}, SCOPE, evidence)
        req.assert_not_called()
        run.assert_not_called()
    assert "80/tcp" in result.output
    assert result.network_active is False
