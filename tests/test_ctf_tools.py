"""Solver tool registry and challenge_file confinement (offline)."""

from __future__ import annotations

import hashlib

import pytest

from gryphos.ctf.tools import build_solver_registry
from gryphos.tools import ToolError, validate_args


@pytest.fixture
def root(tmp_path):
    (tmp_path / "notes.txt").write_text("hello flag{from_file}\n", encoding="utf-8")
    (tmp_path / "binary.bin").write_bytes(bytes(range(0, 200)))
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "inner.txt").write_text("inner", encoding="utf-8")
    return tmp_path


@pytest.fixture
def registry(root):
    return build_solver_registry(root, timeout=10, out_limit=4096)


def test_registry_has_expected_tools(registry):
    assert set(registry) == {"challenge_file", "summarize_evidence"}


def test_no_shell_or_command_tools(registry):
    assert "shell_exec" not in registry
    assert "run_command" not in registry


def test_read_file_inside_root(registry):
    result = registry["challenge_file"].execute({"path": "notes.txt"}, (), [])
    assert "flag{from_file}" in result.output
    assert result.network_active is False
    assert result.data["sha256"] == hashlib.sha256(b"hello flag{from_file}\n").hexdigest()


def test_read_nested_file(registry):
    result = registry["challenge_file"].execute({"path": "sub/inner.txt"}, (), [])
    assert "inner" in result.output


def test_directory_listing(registry):
    result = registry["challenge_file"].execute({"path": "sub"}, (), [])
    assert result.data["kind"] == "directory"
    assert "sub/inner.txt" in result.output


def test_traversal_rejected(registry):
    with pytest.raises(ToolError, match="escapes"):
        registry["challenge_file"].execute({"path": "../../etc/passwd"}, (), [])


def test_absolute_path_rejected(registry):
    with pytest.raises(ToolError, match="relative"):
        registry["challenge_file"].execute({"path": "/etc/passwd"}, (), [])


def test_missing_file_rejected(registry):
    with pytest.raises(ToolError, match="No such file"):
        registry["challenge_file"].execute({"path": "nope.txt"}, (), [])


def test_binary_file_hex_preview(registry):
    result = registry["challenge_file"].execute({"path": "binary.bin"}, (), [])
    assert result.data.get("binary") is True
    assert "Hex preview" in result.output


def test_read_is_bounded(registry):
    result = registry["challenge_file"].execute({"path": "binary.bin", "max_bytes": 10}, (), [])
    assert result.data["read_bytes"] == 10
    assert result.data["size"] == 200


def test_validate_args_rejects_unknown(registry):
    with pytest.raises(ToolError, match="Unknown argument"):
        validate_args(registry["challenge_file"], {"path": "x", "op": "run"})


def test_validate_args_requires_path(registry):
    with pytest.raises(ToolError, match="Missing required"):
        validate_args(registry["challenge_file"], {})


def test_summarize_evidence_tool_runs_offline(registry):
    evidence = [{"kind": "tool_result", "tool": "challenge_file", "target": "notes.txt",
                 "returncode": 0, "data": {}}]
    result = registry["summarize_evidence"].execute({}, (), evidence)
    assert "Evidence summary" in result.output
