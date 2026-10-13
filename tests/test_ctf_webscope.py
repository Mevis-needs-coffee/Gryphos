"""Web scope enforcement: origin, IP policy, redirects, path validation."""

from __future__ import annotations

import socket

import pytest

from gryphos.ctf.webconfig import WebConfig
from gryphos.ctf.webscope import WebScope, WebScopeError, WebTarget

PUBLIC = "93.184.216.34"


def scope(origin="http://127.0.0.1:8080", lab=True, **kw):
    return WebScope(WebConfig.from_dict({"origin": origin, "lab": lab, **kw}))


# --- IP policy --------------------------------------------------------------

def test_loopback_allowed_with_lab():
    s = scope(lab=True)
    assert s.resolve_destination("127.0.0.1") == ["127.0.0.1"]


def test_loopback_refused_without_lab():
    with pytest.raises(WebScopeError, match="lab"):
        scope(origin="http://127.0.0.1:8080", lab=False)


def test_public_address_allowed_without_lab():
    s = scope(origin=f"http://{PUBLIC}:80", lab=False)
    assert PUBLIC in s.resolve_destination(PUBLIC)


def test_cloud_metadata_blocked_even_with_lab():
    with pytest.raises(WebScopeError, match="blocked range"):
        scope(origin="http://169.254.169.254:80", lab=True)


def test_link_local_blocked_even_with_lab():
    with pytest.raises(WebScopeError, match="blocked range"):
        scope(origin="http://169.254.10.10:80", lab=True)


def test_private_allowed_with_lab():
    s = scope(origin="http://10.0.0.5:8080", lab=True)
    assert s.resolve_destination("10.0.0.5") == ["10.0.0.5"]


def test_hostname_mixed_resolution_refused(monkeypatch):
    def fake_getaddrinfo(host, port, proto=None):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(WebScopeError, match="private"):
        scope(origin="http://lab.example.test:8080", lab=False)


def test_hostname_all_loopback_allowed_with_lab(monkeypatch):
    def fake_getaddrinfo(host, port, proto=None):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    s = scope(origin="http://challenge.test:8080", lab=True)
    assert s.resolve_destination("challenge.test") == ["127.0.0.1"]


# --- path / endpoint --------------------------------------------------------

def test_path_normalization():
    s = scope(lab=True)
    assert s.authorize_request("").path == "/"
    assert s.authorize_request("index.php").path == "/index.php"
    assert s.authorize_request("/a/b?x=1").path == "/a/b?x=1"


@pytest.mark.parametrize("bad", [
    "http://evil.test/",
    "//evil.test/",
    "/a\r\nHost: evil",
    "/" + "a" * 3000,
])
def test_bad_paths_rejected(bad):
    with pytest.raises(WebScopeError):
        scope(lab=True).authorize_request(bad)


def test_wrong_port_rejected():
    with pytest.raises(WebScopeError, match="cross-origin"):
        scope(lab=True).authorize_request("/", port=9999)


def test_wrong_host_rejected():
    with pytest.raises(WebScopeError, match="cross-origin"):
        scope(lab=True).authorize_request("/", host="evil.test")


def test_wrong_scheme_rejected():
    with pytest.raises(WebScopeError, match="cross-origin"):
        scope(lab=True).authorize_request("/", scheme="https")


# --- redirects --------------------------------------------------------------

def test_same_origin_redirect_allowed():
    s = scope(lab=True)
    current = s.authorize_request("/start")
    nxt = s.authorize_redirect("/login", current)
    assert nxt.path == "/login"
    assert nxt.host == "127.0.0.1"


def test_relative_redirect_allowed():
    s = scope(lab=True)
    current = s.authorize_request("/a/b")
    assert s.authorize_redirect("../c", current).path == "/c"


def test_cross_origin_redirect_blocked_by_default():
    s = scope(lab=True)
    current = s.authorize_request("/start")
    with pytest.raises(WebScopeError, match="cross-origin"):
        s.authorize_redirect(f"http://{PUBLIC}:80/", current)


def test_cross_origin_redirect_allowed_when_opted_in():
    s = scope(lab=True, allow_cross_origin_redirects=True)
    current = s.authorize_request("/start")
    nxt = s.authorize_redirect(f"http://{PUBLIC}:80/next", current)
    assert nxt.host == PUBLIC


def test_cross_origin_redirect_to_metadata_blocked_even_when_opted_in():
    s = scope(lab=True, allow_cross_origin_redirects=True)
    current = s.authorize_request("/start")
    with pytest.raises(WebScopeError, match="blocked range"):
        s.authorize_redirect("http://169.254.169.254/latest/meta-data/", current)


def test_redirect_with_credentials_rejected():
    s = scope(lab=True, allow_cross_origin_redirects=True)
    current = s.authorize_request("/start")
    with pytest.raises(WebScopeError, match="credentials"):
        s.authorize_redirect("http://user:pass@127.0.0.1:8080/", current)


def test_target_url_property():
    target = WebTarget("http", "127.0.0.1", 8080, "/x")
    assert target.url == "http://127.0.0.1:8080/x"
