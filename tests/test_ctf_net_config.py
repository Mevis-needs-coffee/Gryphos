"""Network-target configuration parsing and challenge/loader integration (Phase 4)."""

from __future__ import annotations

import json

import pytest

from gryphos.ctf import TargetConfig, TargetConfigError, load_challenge
from gryphos.ctf.models import Challenge
from gryphos.ctf.netconfig import TOP_PORTS, parse_port_spec

# --- TargetConfig.from_dict -------------------------------------------------

def test_minimal_host_defaults():
    cfg = TargetConfig.from_dict({"host": "10.10.5.12", "lab": True})
    assert cfg.host == "10.10.5.12"
    assert cfg.host_is_ip is True
    assert cfg.lab is True
    assert cfg.ports == "1-1024"
    assert cfg.max_ports == 1024
    assert cfg.max_connections == 200
    assert cfg.connect_timeout_ms == 1500
    assert cfg.min_interval_ms == 0


def test_hostname_target_allowed():
    cfg = TargetConfig.from_dict({"host": "target.example.test"})
    assert cfg.host_is_ip is False


@pytest.mark.parametrize("bad", [
    {},
    {"host": ""},
    {"host": "bad host"},
    {"host": "10.0.0.1/x"},
    {"host": "a\nb"},
    {"origin": "http://127.0.0.1"},
    "not-a-dict",
])
def test_invalid_targets_rejected(bad):
    with pytest.raises(TargetConfigError):
        TargetConfig.from_dict(bad)


def test_bounds_are_clamped_and_validated():
    cfg = TargetConfig.from_dict({
        "host": "10.0.0.1", "lab": True,
        "max_ports": 99_999, "max_connections": 99_999,
        "connect_timeout_ms": 99_999, "min_interval_ms": 99_999,
    })
    assert cfg.max_ports == 4096
    assert cfg.max_connections == 2000
    assert cfg.connect_timeout_ms == 5000
    assert cfg.min_interval_ms == 5000


def test_below_floor_rejected():
    with pytest.raises(TargetConfigError, match="connect_timeout_ms"):
        TargetConfig.from_dict({"host": "10.0.0.1", "connect_timeout_ms": 1})


def test_declared_ports_validated_at_parse_time():
    cfg = TargetConfig.from_dict({"host": "10.0.0.1", "lab": True, "ports": "22,80,443"})
    assert cfg.ports == "22,80,443"
    with pytest.raises(TargetConfigError, match="above the configured maximum"):
        TargetConfig.from_dict({"host": "10.0.0.1", "lab": True, "ports": "1-2000", "max_ports": 100})


@pytest.mark.parametrize("spec", ["80", "1-1024", "22,80,443", "22, 80, 1000-1002"])
def test_parse_port_spec_ok(spec):
    ports = parse_port_spec(spec, 4096)
    assert ports == sorted(ports)
    assert ports


@pytest.mark.parametrize("spec", ["", "abc", "0", "70000", "10-5", "-", "1-", "1--2"])
def test_parse_port_spec_bad(spec):
    with pytest.raises(TargetConfigError):
        parse_port_spec(spec, 4096)


def test_port_spec_over_max_rejected():
    with pytest.raises(TargetConfigError, match="maximum"):
        parse_port_spec("1-2000", 100)


def test_top_ports_are_plausible():
    assert {21, 22, 80, 443, 3389} <= set(TOP_PORTS)
    assert all(1 <= port <= 65535 for port in TOP_PORTS)


def test_roundtrip_dict():
    cfg = TargetConfig.from_dict({"host": "10.0.0.1", "lab": True, "ports": "22,80"})
    assert TargetConfig.from_dict(cfg.to_dict()) == cfg
    assert "lab" in cfg.describe()


# --- Challenge / loader integration -----------------------------------------

def test_challenge_without_target_block_has_none():
    challenge = Challenge(id="n", name="N", category="network")
    assert challenge.target is None
    assert challenge.to_dict()["target"] is None


def test_challenge_from_dict_parses_target():
    challenge = Challenge.from_dict(
        {"id": "n", "category": "network", "target": {"host": "10.10.5.12", "lab": True}},
        root=".",
    )
    assert challenge.target is not None
    assert challenge.target.lab is True


def test_challenge_from_dict_rejects_bad_target():
    with pytest.raises(ValueError, match="invalid target block"):
        Challenge.from_dict({"id": "n", "category": "network", "target": {"host": ""}}, root=".")


def test_loader_reads_target_block(tmp_path):
    root = tmp_path / "net-warmup"
    root.mkdir()
    (root / "challenge.json").write_text(json.dumps({
        "id": "net-warmup", "name": "Network Warmup", "category": "network",
        "target": {"host": "10.10.5.12", "lab": True, "ports": "22,80"},
    }), encoding="utf-8")
    challenge = load_challenge(tmp_path, "net-warmup")
    assert challenge.target is not None
    assert challenge.target.host == "10.10.5.12"
    assert challenge.target.ports == "22,80"
