"""Web-mission configuration parsing and challenge/loader integration (Phase 3)."""

from __future__ import annotations

import json

import pytest

from gryphos.ctf import WebConfig, WebConfigError, load_challenge
from gryphos.ctf.models import Challenge

# --- WebConfig.from_dict ----------------------------------------------------

def test_minimal_origin_defaults():
    cfg = WebConfig.from_dict({"origin": "http://127.0.0.1:8080"})
    assert cfg.scheme == "http"
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 8080
    assert cfg.origin == "http://127.0.0.1:8080"
    assert cfg.lab is False
    assert cfg.allow_cross_origin_redirects is False
    assert cfg.max_requests == 40


def test_default_ports():
    assert WebConfig.from_dict({"origin": "http://example.test"}).port == 80
    assert WebConfig.from_dict({"origin": "https://example.test"}).port == 443


def test_hostname_origin_allowed():
    cfg = WebConfig.from_dict({"origin": "https://challenge.example.test:8443", "lab": True})
    assert cfg.host == "challenge.example.test"
    assert cfg.host_is_ip is False
    assert cfg.lab is True


def test_trailing_path_root_ok_but_subpath_rejected():
    assert WebConfig.from_dict({"origin": "http://127.0.0.1:80/"}).port == 80
    with pytest.raises(WebConfigError, match="path"):
        WebConfig.from_dict({"origin": "http://127.0.0.1:80/admin"})


@pytest.mark.parametrize("bad", [
    {"origin": ""},
    {"origin": "ftp://127.0.0.1"},
    {"origin": "http://user:pass@127.0.0.1"},
    {"origin": "http://127.0.0.1:8080/evil?x=1"},
    {"origin": "http://127.0.0.1:99999"},
    {"origin": "http://bad host/"},
    {"origin": "http://127.0.0.1\n/"},
    {},
    "not-a-dict",
])
def test_invalid_origins_rejected(bad):
    with pytest.raises(WebConfigError):
        WebConfig.from_dict(bad)


def test_bounds_are_clamped_and_validated():
    cfg = WebConfig.from_dict({
        "origin": "http://127.0.0.1:8080",
        "max_requests": 10_000,
        "max_body_bytes": 999_999_999,
        "min_interval_ms": 99_999,
    })
    assert cfg.max_requests == 500
    assert cfg.max_body_bytes == 4 * 1024 * 1024
    assert cfg.min_interval_ms == 5000
    with pytest.raises(WebConfigError, match="max_requests"):
        WebConfig.from_dict({"origin": "http://127.0.0.1:8080", "max_requests": 0})


def test_roundtrip_dict():
    cfg = WebConfig.from_dict({"origin": "http://127.0.0.1:8080", "lab": True, "max_requests": 5})
    again = WebConfig.from_dict(cfg.to_dict())
    assert again == cfg
    assert "lab" in cfg.describe()


# --- Challenge / loader integration -----------------------------------------

def test_challenge_without_web_block_has_none():
    challenge = Challenge(id="w", name="W", category="web")
    assert challenge.web is None
    assert challenge.to_dict()["web"] is None


def test_challenge_from_dict_parses_web():
    challenge = Challenge.from_dict(
        {"id": "w", "category": "web", "web": {"origin": "http://127.0.0.1:8080", "lab": True}},
        root=".",
    )
    assert challenge.web is not None
    assert challenge.web.lab is True


def test_challenge_from_dict_rejects_bad_web():
    with pytest.raises(ValueError, match="invalid web block"):
        Challenge.from_dict({"id": "w", "category": "web", "web": {"origin": "ftp://x"}}, root=".")


def test_loader_reads_web_block(tmp_path):
    root = tmp_path / "web-warmup"
    root.mkdir()
    (root / "challenge.json").write_text(json.dumps({
        "id": "web-warmup", "name": "Web Warmup", "category": "web",
        "web": {"origin": "http://127.0.0.1:8081", "lab": True},
    }), encoding="utf-8")
    challenge = load_challenge(tmp_path, "web-warmup")
    assert challenge.web is not None
    assert challenge.web.origin == "http://127.0.0.1:8081"
