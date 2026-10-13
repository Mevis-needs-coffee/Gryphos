"""Network tools: scan, service probe, HTTP probe, offline clues (all offline)."""

from __future__ import annotations

import socket

import pytest
from tcpserver import MockTcpServer
from webserver import MockWebServer

from gryphos.ctf.flag import FlagFormat
from gryphos.ctf.netclient import NetClient, service_hint
from gryphos.ctf.netconfig import TOP_PORTS, TargetConfig
from gryphos.ctf.netscope import NetScope
from gryphos.ctf.nettools import (
    collect_net_clues,
    net_clues_spec,
    net_http_probe_spec,
    net_portscan_spec,
    net_service_probe_spec,
)
from gryphos.tools.base import ToolError, validate_args


def build(host="127.0.0.1", lab=True, **overrides):
    config = TargetConfig.from_dict({"host": host, "lab": lab, **overrides})
    scope = NetScope(config)
    client = NetClient(scope, read_timeout_ms=300)
    return scope, client


def run(spec, **args):
    cleaned = validate_args(spec, args)
    return spec.execute(cleaned, (), [])


def ports_arg(ports):
    return ",".join(str(p) for p in ports)


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_service_hint_mapping():
    assert service_hint(22, "SSH-2.0-OpenSSH_9.0") == "ssh"
    assert service_hint(80, "") == "http"
    assert service_hint(3306, "") == "mysql"
    assert service_hint(12345, "") == ""


# --- net_portscan -----------------------------------------------------------

def test_portscan_finds_open_port_and_banner():
    with MockTcpServer() as tcp:
        port = tcp.listen(banner=b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n")
        scope, client = build(ports=ports_arg([port]))
        spec = net_portscan_spec(scope, client, FlagFormat(), 30, 8000)
        result = run(spec, ports=ports_arg([port]))
    assert result.network_active is True
    assert result.activity == "active"
    assert result.data["scanned"] == 1
    open_ports = result.data["open_ports"]
    assert open_ports and open_ports[0]["port"] == port
    assert open_ports[0]["service"] == "ssh"
    assert "OpenSSH" in open_ports[0]["banner"]
    assert port in tcp.connections


def test_portscan_reports_closed_ports():
    with MockTcpServer() as tcp:
        open_port = tcp.listen()
        closed_port = free_port()
        ports = ports_arg([open_port, closed_port])
        scope, client = build(ports=ports)
        spec = net_portscan_spec(scope, client, FlagFormat(), 30, 8000)
        result = run(spec, ports=ports)
    states = {entry["port"]: entry["state"] for entry in result.data["results"]}
    assert states[open_port] == "open"
    assert states[closed_port] == "closed"
    assert [entry["port"] for entry in result.data["open_ports"]] == [open_port]


def test_portscan_detects_flag_in_banner():
    with MockTcpServer() as tcp:
        port = tcp.listen(banner=b"flag{banner_flag}\n")
        scope, client = build(ports=ports_arg([port]))
        spec = net_portscan_spec(scope, client, FlagFormat(), 30, 8000)
        result = run(spec, ports=ports_arg([port]))
    assert "flag{banner_flag}" in result.data["flags"]


def test_portscan_top_ports_bounded():
    with MockTcpServer() as tcp:
        port = tcp.listen()
        assert port not in TOP_PORTS  # ephemeral listener is outside the built-in set
        scope, client = build()
        spec = net_portscan_spec(scope, client, FlagFormat(), 30, 8000)
        result = run(spec, top=True)
    assert result.data["scanned"] == len(TOP_PORTS)
    assert result.data["open_ports"] == []


# --- net_service_probe ------------------------------------------------------

def test_service_probe_fingerprints_banner():
    with MockTcpServer() as tcp:
        port = tcp.listen(banner=b"220 FTP server ready\r\n")
        scope, client = build(ports=ports_arg([port]))
        spec = net_service_probe_spec(scope, client, FlagFormat(), 30, 8000)
        result = run(spec, ports=ports_arg([port]))
    services = result.data["services"]
    assert services[0]["port"] == port
    assert services[0]["service"] == "ftp"
    assert "FTP server" in services[0]["banner"]


def test_service_probe_defaults_to_discovered_ports():
    with MockTcpServer() as tcp:
        port = tcp.listen(banner=b"-NOAUTH Authentication required\r\n")
        scope, client = build(ports=ports_arg([port]))
        spec = net_service_probe_spec(scope, client, FlagFormat(), 30, 8000)
        evidence = [{
            "kind": "tool_result", "tool": "net_portscan", "command": "net_portscan(...)",
            "data": {"open_ports": [{"port": port, "service": "redis"}]},
        }]
        result = spec.execute({}, (), evidence)
    assert result.data["services"][0]["port"] == port


def test_connection_budget_exhausted_is_a_tool_error():
    with MockTcpServer() as tcp:
        port = tcp.listen()
        scope, client = build(ports=str(port), max_connections=1)
        spec = net_service_probe_spec(scope, client, FlagFormat(), 30, 8000)
        run(spec, ports=str(port))
        with pytest.raises(ToolError, match="budget"):
            run(spec, ports=str(port))


# --- net_http_probe ---------------------------------------------------------

def test_http_probe_renders_status_and_detects_flag():
    with MockWebServer() as web:
        web.html("/", "welcome flag{http_flag}")
        scope, client = build(ports=str(web.port))
        spec = net_http_probe_spec(scope, client, FlagFormat(), 30, 8000)
        result = run(spec, port=web.port, path="/")
    assert result.network_active is True
    assert result.data["final_status"] == 200
    assert "welcome" in result.output
    assert "flag{http_flag}" in result.data["flags"]


def test_http_probe_multiple_paths():
    with MockWebServer() as web:
        web.html("/", "home")
        web.html("/admin", "flag{admin}")
        scope, client = build(ports=str(web.port))
        spec = net_http_probe_spec(scope, client, FlagFormat(), 30, 8000)
        result = run(spec, port=web.port, paths=["/", "/admin"])
    assert len(result.data["responses"]) == 2
    assert result.data["final_status"] == 200
    assert any("flag{admin}" in value for value in result.data["flags"])


def test_http_probe_rejects_state_changing_method():
    scope, client = build()
    spec = net_http_probe_spec(scope, client, FlagFormat(), 30, 8000)
    with pytest.raises(ToolError, match="one of"):
        validate_args(spec, {"port": 80, "method": "POST"})


# --- registry wiring --------------------------------------------------------

def test_registry_only_exposes_net_tools_when_authorized(tmp_path):
    from gryphos.ctf.tools import build_solver_registry

    offline = build_solver_registry(tmp_path, 30, 8000)
    assert "net_portscan" not in offline

    scope, client = build()
    online = build_solver_registry(tmp_path, 30, 8000, net_scope=scope, net_client=client)
    assert {
        "net_portscan",
        "net_service_probe",
        "net_http_probe",
        "net_clues",
    } <= set(online)
    assert online["net_clues"].network_active is False


def test_registry_requires_scope_and_client_together(tmp_path):
    from gryphos.ctf.tools import build_solver_registry

    scope, _ = build()
    registry = build_solver_registry(tmp_path, 30, 8000, net_scope=scope)
    assert "net_portscan" not in registry


# --- net_clues (offline) ----------------------------------------------------

def _sample_evidence():
    return [
        {
            "kind": "tool_result", "tool": "net_portscan", "command": "net_portscan(...)",
            "data": {"open_ports": [
                {"port": 22, "service": "ssh", "banner": "OpenSSH_7.2"},
                {"port": 3306, "service": "mysql", "banner": "mysql-nag"},
            ]},
        },
        {
            "kind": "tool_result", "tool": "net_http_probe", "command": "net_http_probe(...)",
            "data": {"responses": [{"url": "http://127.0.0.1:80/admin"}]},
        },
    ]


def test_clues_prioritize_and_summarize():
    clues, meta = collect_net_clues(_sample_evidence())
    assert "22/ssh" in meta["open_ports"]
    values = {entry["value"] for entry in clues.values()}
    assert {"22/ssh", "3306/mysql", "http://127.0.0.1:80/admin"} <= values

    spec = net_clues_spec(FlagFormat(), 8000)
    result = spec.execute({"max_items": 10}, (), _sample_evidence())
    assert result.network_active is False
    assert result.activity == "passive"
    priorities = [entry["priority"] for entry in result.data["clues"]]
    assert priorities == sorted(priorities, reverse=True)
    assert "22/ssh" in result.data["open_ports"]


def test_clues_empty_evidence():
    spec = net_clues_spec(FlagFormat(), 8000)
    result = spec.execute({}, (), [])
    assert result.data["clues"] == []
    assert "no network clues" in result.output
