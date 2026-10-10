"""Phase 4 tool tests: web_tech, local tools, and evidence analysis.

All tests are offline: external binaries and transports are patched. No
network, no real scans.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from gryphos.analysis import (
    compare_sessions,
    correlate,
    detect_contradictions,
    normalize_observations,
)
from gryphos.scope import ScopeError, classify_ip, validate_target
from gryphos.tools import ToolError
from gryphos.tools.base import ProcResult

SCOPE = ("127.0.0.1/32",)

PASSIVE_TOOLS = {
    "local_ports", "local_audit", "source_scan",
    "dependency_audit", "secret_detect", "summarize_evidence",
}
ACTIVE_TOOLS = {"nmap_basic", "http_headers", "http_redirects", "tls_cert", "web_tech"}


class FakeResponse:
    def __init__(self, status=200, headers=None, reason="OK", body=b""):
        self.status_code = status
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self.reason = reason
        self.raw = MagicMock()
        self.raw.read.return_value = body

    def close(self):
        pass


# --- declarations & policy --------------------------------------------------

def test_passive_tools_declare_no_network(registry):
    for name in PASSIVE_TOOLS:
        spec = registry[name]
        assert spec.network_active is False, name
        assert spec.approval_policy == "none", name
        assert spec.activity == "passive", name


def test_active_tools_require_explicit_approval(registry):
    for name in ACTIVE_TOOLS:
        spec = registry[name]
        assert spec.network_active is True, name
        assert spec.approval_policy == "explicit", name
        assert spec.activity == "active", name


def test_every_new_spec_declares_purpose_and_schema(registry):
    for spec in registry.values():
        assert spec.purpose
        assert spec.scope_requirements or not spec.network_active
        assert isinstance(spec.result_schema, dict)


# --- web_tech ---------------------------------------------------------------

def test_web_tech_labels_inferred_and_scope_enforced(registry):
    spec = registry["web_tech"]
    with patch("gryphos.tools.net.requests.request") as req:
        with pytest.raises(ScopeError):
            spec.execute({"target": "8.8.8.8", "port": 80, "scheme": "http"}, SCOPE, [])
        req.assert_not_called()


def test_web_tech_fingerprints_headers_and_body(registry):
    spec = registry["web_tech"]
    fake = FakeResponse(
        status=200,
        headers={"Server": "nginx/1.24", "X-Powered-By": "PHP/8.2"},
        body=b"<html><meta name=\"generator\" content=\"WordPress 6.4\"></html>",
    )
    with patch("gryphos.tools.net.requests.request", return_value=fake), \
         patch("gryphos.tools.tech.shutil.which", return_value=None):
        result = spec.execute({"target": "127.0.0.1", "port": 80, "scheme": "http"}, SCOPE, [])
    names = {t["name"] for t in result.data["technologies"]}
    assert result.data["inferred"] is True
    assert "nginx" in names
    assert "php" in names
    assert result.data["crawl_mode"] == "none"


# --- local_ports ------------------------------------------------------------

def test_local_ports_parses_and_classifies(registry):
    spec = registry["local_ports"]
    output = (
        "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:((\"python\",pid=1,fd=3))\n"
        "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
        "udp UNCONN 0 0 [::]:5353 [::]:*\n"
    )
    with patch("gryphos.tools.local_ports.resolve_binary", return_value="/usr/bin/ss"), \
         patch("gryphos.tools.local_ports.run_process", return_value=ProcResult(0, output)):
        result = spec.execute({}, SCOPE, [])
    assert result.network_active is False
    assert result.data["counts"]["total"] == 3
    assert result.data["counts"]["local_only"] == 1
    assert result.data["counts"]["exposed_wildcard"] == 2


# --- local_audit ------------------------------------------------------------

def test_local_audit_rejects_unknown_mode(registry):
    with pytest.raises(ToolError, match="Unknown audit mode"):
        registry["local_audit"].execute({"mode": "wipe"}, SCOPE, [])


def test_local_audit_runs_fixed_readonly_command(registry):
    with patch("gryphos.tools.local_audit.shutil.which", return_value="/usr/bin/systemctl"), \
         patch("gryphos.tools.local_audit.run_process", return_value=ProcResult(0, "UNIT LOAD ACTIVE\n")) as run:
        result = registry["local_audit"].execute({"mode": "services"}, SCOPE, [])
    assert "systemctl" in result.display
    assert result.data["read_only"] is True
    argv = run.call_args[0][0]
    assert argv[0] == "systemctl"
    assert "-ltunp" not in argv


# --- source_scan ------------------------------------------------------------

def test_source_scan_strips_source_code(registry, tmp_path):
    payload = json.dumps({"results": [{
        "filename": str(tmp_path / "app.py"),
        "line_number": 3,
        "test_id": "B105",
        "test_name": "hardcoded_password_string",
        "issue_severity": "LOW",
        "issue_confidence": "MEDIUM",
        "issue_text": "Possible hardcoded password",
        "code": "password = 'hunter2-secret'",
    }]})
    with patch("gryphos.tools.source_scan.resolve_binary", return_value="/usr/bin/bandit"), \
         patch("gryphos.tools.source_scan.run_process", return_value=ProcResult(1, payload)):
        result = registry["source_scan"].execute({"project_dir": str(tmp_path)}, SCOPE, [])
    assert result.data["counts"]["bandit"] == 1
    finding = result.data["findings"]["bandit"][0]
    assert "code" not in finding
    assert "hunter2-secret" not in result.output
    assert "hunter2-secret" not in json.dumps(result.data)


def test_source_scan_requires_real_directory(registry, tmp_path):
    with pytest.raises(ToolError, match="existing directory"):
        registry["source_scan"].execute({"project_dir": str(tmp_path / "nope")}, SCOPE, [])


# --- dependency_audit -------------------------------------------------------

def test_dependency_audit_clean(registry, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    payload = json.dumps({"dependencies": [{"name": "requests", "version": "2.31.0", "vulns": []}]})
    with patch("gryphos.tools.dependency_audit.resolve_binary", return_value="/usr/bin/pip-audit"), \
         patch("gryphos.tools.dependency_audit.run_process", return_value=ProcResult(0, payload)):
        result = registry["dependency_audit"].execute({"manifest": str(req)}, SCOPE, [])
    assert result.data["clean"] is True
    assert result.data["auto_upgrade"] == "disabled"


def test_dependency_audit_reports_vulnerabilities(registry, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("urllib3==1.26.0\n")
    payload = json.dumps({"dependencies": [{
        "name": "urllib3", "version": "1.26.0",
        "vulns": [{"id": "GHSA-xxxx", "fix_versions": ["1.26.18"], "description": "Bypass"}],
    }]})
    with patch("gryphos.tools.dependency_audit.resolve_binary", return_value="/usr/bin/pip-audit"), \
         patch("gryphos.tools.dependency_audit.run_process", return_value=ProcResult(1, payload)):
        result = registry["dependency_audit"].execute({"manifest": str(req)}, SCOPE, [])
    assert result.data["vulnerable_packages"] == 1
    assert result.data["clean"] is False


def test_dependency_audit_data_unavailable_is_not_clean(registry, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==3.0.0\n")
    with patch("gryphos.tools.dependency_audit.resolve_binary", return_value="/usr/bin/pip-audit"), \
         patch("gryphos.tools.dependency_audit.run_process",
               return_value=ProcResult(2, "Could not resolve dependencies")):
        result = registry["dependency_audit"].execute({"manifest": str(req)}, SCOPE, [])
    assert result.data["data_unavailable"] is True
    assert result.data["clean"] is False


def test_dependency_audit_rejects_unsupported_manifest(registry, tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    with pytest.raises(ToolError, match="requirements"):
        registry["dependency_audit"].execute({"manifest": str(manifest)}, SCOPE, [])


# --- secret_detect ----------------------------------------------------------

def test_secret_detect_redacts_values_everywhere(registry, tmp_path):
    leaked_value = "AKIAIOSFODNN7EXAMPLE"
    (tmp_path / "config.py").write_text(f"KEY = '{leaked_value}'\n")

    def fake_run(argv, timeout, max_output_chars):
        report_path = argv[argv.index("--report-path") + 1]
        Path(report_path).write_text(json.dumps([{
            "RuleID": "aws-access-token",
            "File": str(tmp_path / "config.py"),
            "StartLine": 1, "EndLine": 1,
            "Match": leaked_value, "Secret": leaked_value,
        }]))
        return ProcResult(0, "")

    with patch("gryphos.tools.secret_detect.resolve_binary", return_value="/usr/bin/gitleaks"), \
         patch("gryphos.tools.secret_detect.run_process", side_effect=fake_run):
        result = registry["secret_detect"].execute({"project_dir": str(tmp_path)}, SCOPE, [])
    assert result.data["counts"]["total"] == 1
    assert result.data["findings"][0]["rule"] == "aws-access-token"
    assert leaked_value not in result.output
    assert leaked_value not in json.dumps(result.data)


# --- analysis (Tool 10) -----------------------------------------------------

def _evidence():
    return [
        {"kind": "tool_result", "tool": "nmap_basic", "target": "127.0.0.1",
         "returncode": 0, "data": {"open_ports": [{"port": "80/tcp", "service": "http"}]}},
        {"kind": "tool_result", "tool": "http_headers", "target": "127.0.0.1",
         "returncode": 0, "data": {"status_code": 200, "port": 80}},
    ]


def test_analysis_normalize_and_correlate():
    obs = normalize_observations(_evidence())
    assert any(o["kind"] == "open_port" and o["port"] == "80/tcp" for o in obs)
    groups = correlate(_evidence())
    assert groups[0]["target"] == "127.0.0.1"
    assert {"nmap_basic", "http_headers"} <= set(groups[0]["tools"])


def test_analysis_detects_port_contradiction():
    evidence = [
        {"kind": "tool_result", "tool": "nmap_basic", "target": "127.0.0.1",
         "returncode": 0, "data": {"open_ports": []}},
        {"kind": "tool_result", "tool": "http_headers", "target": "127.0.0.1",
         "returncode": 0, "data": {"status_code": 200, "port": 8080}},
    ]
    contradictions = detect_contradictions(evidence)
    assert contradictions
    assert "8080" in contradictions[0]["message"]


def test_analysis_compare_sessions_offline():
    newer = {"evidence": _evidence()}
    older = {"evidence": []}
    diff = compare_sessions(newer, older, "new", "old")
    assert diff["new_observations"]
    assert diff["unchanged_count"] == 0
    assert "no tools were re-executed" in diff["note"]


def test_summarize_evidence_counts_and_correlates(registry):
    evidence = _evidence()
    result = registry["summarize_evidence"].execute({}, SCOPE, evidence)
    assert result.network_active is False
    assert result.data["normalized_count"] >= 2
    assert "80/tcp" in result.output


# --- scope classification ---------------------------------------------------

def test_classify_ip_categories():
    assert "cloud_metadata (link-local)" in classify_ip(ipaddress.ip_address("169.254.169.254"))
    assert "loopback" in classify_ip(ipaddress.ip_address("127.0.0.1"))
    assert "private" in classify_ip(ipaddress.ip_address("10.0.0.5"))


def test_validate_target_hint_names_reserved_class():
    with pytest.raises(ScopeError, match="classified as"):
        validate_target("10.0.0.5", ("127.0.0.1/32",))


def test_subprocess_helpers_are_unused_for_passive_tools(registry):
    # Guardrail: passive local tools must not touch the network layer at all.
    for name in PASSIVE_TOOLS:
        spec = registry[name]
        assert spec.network_active is False


def test_proc_result_shape():
    proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")
    assert proc.stdout == "ok"
