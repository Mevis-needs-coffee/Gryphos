"""Scope enforcement tests — the security boundary."""

import pytest

from gryphos.scope import (
    ScopeError,
    authorize_url,
    normalize_ip,
    parse_scope,
    validate_path,
    validate_port,
    validate_target,
)

SCOPE = ("127.0.0.1/32", "192.168.56.0/24", "::1/128", "fd00::/8")


def test_valid_ipv4_in_scope():
    assert validate_target("127.0.0.1", SCOPE) == "127.0.0.1"
    assert validate_target("192.168.56.10", SCOPE) == "192.168.56.10"


def test_valid_ipv6_in_scope():
    assert validate_target("::1", SCOPE) == "::1"
    assert validate_target("fd00::1", SCOPE) == "fd00::1"


def test_ipv6_normalization():
    assert validate_target("0:0:0:0:0:0:0:1", SCOPE) == "::1"


def test_out_of_scope_rejected():
    with pytest.raises(ScopeError, match="outside the configured"):
        validate_target("8.8.8.8", SCOPE)


def test_hostname_rejected():
    with pytest.raises(ScopeError):
        validate_target("example.com", SCOPE)
    with pytest.raises(ScopeError):
        validate_target("localhost", SCOPE)


def test_url_rejected_as_target():
    with pytest.raises(ScopeError):
        validate_target("http://127.0.0.1/", SCOPE)


def test_cidr_rejected_as_target():
    with pytest.raises(ScopeError):
        validate_target("127.0.0.1/32", SCOPE)
    with pytest.raises(ScopeError):
        validate_target("192.168.56.0/24", SCOPE)


def test_bracketed_ipv6_rejected():
    with pytest.raises(ScopeError):
        validate_target("[::1]", SCOPE)


def test_ambiguous_short_form_rejected():
    with pytest.raises(ScopeError):
        validate_target("127.1", SCOPE)


def test_empty_rejected():
    with pytest.raises(ScopeError):
        validate_target("", SCOPE)


def test_ipv4_mapped_ipv6_rejected():
    with pytest.raises(ScopeError, match="IPv4-mapped"):
        validate_target("::ffff:127.0.0.1", SCOPE)


def test_version_isolation():
    # IPv6 loopback must not match an IPv4-only scope entry.
    with pytest.raises(ScopeError):
        validate_target("::1", ("127.0.0.1/32",))


def test_malformed_scope_entry():
    with pytest.raises(ScopeError, match="Invalid GRYPHOS_ALLOWED_TARGETS"):
        parse_scope(("not-a-network",))


def test_empty_scope():
    with pytest.raises(ScopeError, match="No authorized targets"):
        parse_scope(())


def test_normalize_ip_rejects_garbage():
    with pytest.raises(ScopeError):
        normalize_ip("  ")
    with pytest.raises(ScopeError):
        normalize_ip("999.1.1.1")


# --- URL authorization -----------------------------------------------------

def test_url_in_scope_ok():
    result = authorize_url("http://127.0.0.1:8080/login", SCOPE)
    assert result["host"] == "127.0.0.1"
    assert result["port"] == 8080
    assert result["path"] == "/login"


def test_url_default_ports():
    assert authorize_url("http://127.0.0.1/", SCOPE)["port"] == 80
    assert authorize_url("https://127.0.0.1/", SCOPE)["port"] == 443


def test_url_hostname_rejected():
    with pytest.raises(ScopeError, match="literal IP"):
        authorize_url("http://localhost/", SCOPE)


def test_url_out_of_scope_rejected():
    with pytest.raises(ScopeError, match="outside"):
        authorize_url("http://8.8.8.8/", SCOPE)


def test_url_bad_scheme_rejected():
    with pytest.raises(ScopeError, match="scheme"):
        authorize_url("ftp://127.0.0.1/", SCOPE)
    with pytest.raises(ScopeError, match="scheme"):
        authorize_url("file:///etc/passwd", SCOPE)


def test_url_credentials_rejected():
    with pytest.raises(ScopeError):
        authorize_url("http://user:pass@127.0.0.1/", SCOPE)


def test_url_crlf_rejected():
    with pytest.raises(ScopeError):
        authorize_url("http://127.0.0.1/\r\nX", SCOPE)


def test_url_bad_port_rejected():
    with pytest.raises(ScopeError):
        authorize_url("http://127.0.0.1:99999/", SCOPE)


# --- ports and paths -------------------------------------------------------

def test_port_bounds():
    assert validate_port(80) == 80
    with pytest.raises(ScopeError):
        validate_port(0)
    with pytest.raises(ScopeError):
        validate_port(65536)
    with pytest.raises(ScopeError):
        validate_port("abc")


def test_path_validation():
    assert validate_path("/a/b") == "/a/b"
    with pytest.raises(ScopeError):
        validate_path("a/b")
    with pytest.raises(ScopeError):
        validate_path("/a b")
    with pytest.raises(ScopeError):
        validate_path("/a\r\nb")
