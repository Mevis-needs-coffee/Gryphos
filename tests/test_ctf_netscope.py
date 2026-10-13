"""Network scope enforcement: single target, IP policy, port bounds (Phase 4)."""

from __future__ import annotations

import socket

import pytest

from gryphos.ctf.netconfig import TargetConfig
from gryphos.ctf.netscope import NetScope, NetScopeError

PUBLIC = "93.184.216.34"


def scope(host="127.0.0.1", lab=True, **kw):
    return NetScope(TargetConfig.from_dict({"host": host, "lab": lab, **kw}))


# --- IP policy --------------------------------------------------------------

def test_loopback_allowed_with_lab():
    s = scope(lab=True)
    assert s.resolve_destination("127.0.0.1") == ["127.0.0.1"]
    assert s.host == "127.0.0.1"


def test_loopback_refused_without_lab():
    with pytest.raises(NetScopeError, match="lab"):
        scope(host="127.0.0.1", lab=False)


def test_public_address_allowed_without_lab():
    s = scope(host=PUBLIC, lab=False)
    assert PUBLIC in s.resolve_destination(PUBLIC)


def test_private_allowed_with_lab():
    s = scope(host="10.10.5.12", lab=True)
    assert s.resolve_destination("10.10.5.12") == ["10.10.5.12"]


def test_cloud_metadata_blocked_even_with_lab():
    with pytest.raises(NetScopeError, match="blocked range"):
        scope(host="169.254.169.254", lab=True)


def test_link_local_blocked_even_with_lab():
    with pytest.raises(NetScopeError, match="blocked range"):
        scope(host="169.254.10.10", lab=True)


def test_hostname_mixed_resolution_refused(monkeypatch):
    def fake_getaddrinfo(host, port, proto=None):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(NetScopeError, match="private"):
        scope(host="lab.example.test", lab=False)


def test_hostname_all_loopback_allowed_with_lab(monkeypatch):
    def fake_getaddrinfo(host, port, proto=None):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    s = scope(host="challenge.test", lab=True)
    assert s.resolve_destination("challenge.test") == ["127.0.0.1"]


# --- single-target policy ---------------------------------------------------

def test_authorize_host_accepts_only_the_target():
    s = scope(lab=True)
    assert s.authorize_host("127.0.0.1") == "127.0.0.1"
    assert s.authorize_host(None) == "127.0.0.1"
    with pytest.raises(NetScopeError, match="only the authorized target"):
        s.authorize_host("10.0.0.9")


# --- port policy ------------------------------------------------------------

def test_authorize_ports_defaults_and_bounds():
    s = scope(lab=True, ports="22,80,443", max_ports=10)
    assert s.authorize_ports(None) == [22, 80, 443]
    assert s.authorize_ports("22") == [22]
    with pytest.raises(NetScopeError):
        s.authorize_ports("1-100")


def test_authorize_port_range():
    s = scope(lab=True)
    assert s.authorize_port("80") == 80
    with pytest.raises(NetScopeError):
        s.authorize_port(0)
    with pytest.raises(NetScopeError):
        s.authorize_port("nope")


def test_properties_and_describe():
    s = scope(lab=True, ports="22,80", max_connections=5, connect_timeout_ms=900)
    assert s.max_connections == 5
    assert s.default_ports == "22,80"
    assert s.connect_timeout_ms == 900
    assert s.lab is True
    assert "host=127.0.0.1" in s.describe()
