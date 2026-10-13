"""Web client bounds: limits, retries, dedup, redirects, redaction (offline)."""

from __future__ import annotations

import time

import pytest
from webserver import MockWebServer, Route

from gryphos.ctf.webclient import (
    REDACTED,
    WebClient,
    WebClientError,
    redact_body,
    redact_headers,
    redact_url,
)
from gryphos.ctf.webconfig import WebConfig
from gryphos.ctf.webscope import WebScope


def make_client(server, **overrides):
    config = WebConfig.from_dict({
        "origin": server.origin, "lab": True, "min_interval_ms": 0, **overrides,
    })
    scope = WebScope(config)
    return WebClient(scope, timeout=2)


@pytest.fixture
def server():
    with MockWebServer() as srv:
        srv.html("/", "<html><body>hello flag{web}</body></html>")
        srv.html("/other", "other page")
        srv.json("/api", {"ok": True, "items": [1, 2, 3]})
        srv.add("/big", Route(status=200, body=b"x" * 10000, content_type="text/plain"))
        srv.add("/slow", Route(status=200, body=b"late", delay=1.5))
        srv.add("/flaky", Route(sequence=[(503, b"unavailable"), (200, b"recovered")]))
        yield srv


def get(server, path="/", **kw):
    client = make_client(server, **kw.pop("config", {}))
    target = client.scope.authorize_request(path)
    return client, client.request("GET", target, **kw)


# --- basic fetch ------------------------------------------------------------

def test_get_status_headers_body(server):
    _, resp = get(server)
    assert resp.status == 200
    assert resp.ok
    assert "flag{web}" in resp.body
    assert resp.content_type == "text/html"


def test_json_response(server):
    _, resp = get(server, "/api")
    assert resp.status == 200
    assert '"ok": true' in resp.body
    assert resp.content_type == "application/json"


def test_head_has_no_body(server):
    client = make_client(server)
    resp = client.request("HEAD", client.scope.authorize_request("/"))
    assert resp.status == 200
    assert resp.body == ""


def test_missing_route_404(server):
    _, resp = get(server, "/nope")
    assert resp.status == 404


# --- limits -----------------------------------------------------------------

def test_oversized_body_truncated(server):
    client = make_client(server, max_body_bytes=1024)
    resp = client.request("GET", client.scope.authorize_request("/big"))
    assert resp.body_truncated is True
    assert resp.body_length == 1024


def test_request_budget_exhausted(server):
    client = make_client(server, max_requests=1)
    client.request("GET", client.scope.authorize_request("/"))
    with pytest.raises(WebClientError, match="budget"):
        client.request("GET", client.scope.authorize_request("/other"))


def test_identical_request_served_from_cache(server):
    client = make_client(server)
    target = client.scope.authorize_request("/")
    first = client.request("GET", target)
    second = client.request("GET", target)
    assert first.reused is False
    assert second.reused is True
    assert len(server.requests) == 1
    assert client.request_count == 1


def test_allow_repeat_issues_second_request(server):
    client = make_client(server)
    target = client.scope.authorize_request("/")
    client.request("GET", target)
    client.request("GET", target, allow_repeat=True)
    assert len(server.requests) == 2
    assert client.request_count == 2


def test_rate_limit_enforced(server):
    client = make_client(server, min_interval_ms=150)
    start = time.monotonic()
    client.request("GET", client.scope.authorize_request("/"))
    client.request("GET", client.scope.authorize_request("/other"))
    assert time.monotonic() - start >= 0.15


# --- methods / errors -------------------------------------------------------

@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "TRACE"])
def test_destructive_methods_rejected(server, method):
    client = make_client(server)
    with pytest.raises(WebClientError, match="not allowed"):
        client.request(method, client.scope.authorize_request("/"))
    assert server.requests == []


def test_get_with_body_rejected(server):
    client = make_client(server)
    with pytest.raises(WebClientError, match="body"):
        client.request("GET", client.scope.authorize_request("/"), body=b"x=1")


def test_post_body_recorded(server):
    client = make_client(server)
    resp = client.request(
        "POST", client.scope.authorize_request("/"), body=b"a=1&b=2",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status == 200
    assert server.requests[0]["body"] == b"a=1&b=2"
    assert server.requests[0]["method"] == "POST"


def test_connection_refused_returns_error():
    config = WebConfig.from_dict({"origin": "http://127.0.0.1:1", "lab": True})
    client = WebClient(WebScope(config), timeout=1)
    resp = client.request("GET", client.scope.authorize_request("/"))
    assert resp.ok is False
    assert resp.error


def test_timeout_returns_error(server):
    config = WebConfig.from_dict({"origin": server.origin, "lab": True})
    client = WebClient(WebScope(config), timeout=1)
    resp = client.request("GET", client.scope.authorize_request("/slow"))
    assert resp.ok is False
    assert "timeout" in (resp.error or "").lower()


# --- retries ----------------------------------------------------------------

def test_get_retries_transient_5xx(server):
    _, resp = get(server, "/flaky")
    assert resp.status == 200
    assert resp.body == "recovered"
    assert resp.attempts == 2


def test_post_does_not_retry(server):
    client = make_client(server)
    resp = client.request("POST", client.scope.authorize_request("/flaky"), body=b"x=1")
    assert resp.status == 503
    assert len(server.requests) == 1


# --- redirects --------------------------------------------------------------

def test_same_origin_redirect_chain(server):
    server.redirect("/a", "/b")
    server.html("/b", "destination")
    client = make_client(server)
    chain = client.request_with_redirects("GET", client.scope.authorize_request("/a"))
    assert [r.status for r in chain] == [302, 200]
    assert "destination" in chain[-1].body


def test_cross_origin_redirect_blocked(server):
    server.redirect("/to-elsewhere", "http://127.0.0.1:9/")
    client = make_client(server)
    chain = client.request_with_redirects("GET", client.scope.authorize_request("/to-elsewhere"))
    assert len(chain) == 1
    assert "redirect blocked" in (chain[-1].error or "")


def test_cross_origin_redirect_to_metadata_blocked(server):
    server.redirect("/meta", "http://169.254.169.254/latest/meta-data/")
    client = make_client(server, allow_cross_origin_redirects=True)
    chain = client.request_with_redirects("GET", client.scope.authorize_request("/meta"))
    assert "blocked range" in (chain[-1].error or "")


# --- redaction --------------------------------------------------------------

def test_redact_headers_cookies_and_auth():
    headers = [
        ("Set-Cookie", "session=abc123; Path=/; HttpOnly"),
        ("Authorization", "Bearer sk-or-v1-secretsecretsecret"),
        ("Content-Type", "text/html"),
    ]
    out = dict((k, v) for k, v in redact_headers(headers))
    assert out["Set-Cookie"] == "session=" + REDACTED + "; Path=/; HttpOnly"
    assert out["Authorization"] == REDACTED
    assert out["Content-Type"] == "text/html"


def test_redact_url_sensitive_params():
    redacted = redact_url("http://x/echo?token=abc&q=hello")
    assert "token=" + REDACTED in redacted or "token=%2A" in redacted or REDACTED in redacted
    assert "q=hello" in redacted


def test_redact_body_api_key():
    assert "sk-or-v1-" not in redact_body("key sk-or-v1-abcdefghijkl")


def test_to_dict_redacts(server):
    client = make_client(server)
    resp = client.request("GET", client.scope.authorize_request("/"))
    payload = resp.to_dict(redacted=True)
    assert payload["method"] == "GET"
    assert payload["status"] == 200
