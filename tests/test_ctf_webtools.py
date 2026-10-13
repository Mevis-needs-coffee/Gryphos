"""web_fetch tool: bounded fetch, redirects, scope refusal, redaction (offline)."""

from __future__ import annotations

import pytest
from webserver import MockWebServer, Route

from gryphos.ctf.flag import FlagFormat
from gryphos.ctf.webclient import WebClient
from gryphos.ctf.webconfig import WebConfig
from gryphos.ctf.webscope import WebScope
from gryphos.ctf.webtools import web_fetch_spec
from gryphos.tools.base import ToolError, validate_args


def build(server, **overrides):
    config = WebConfig.from_dict({"origin": server.origin, "lab": True, **overrides})
    scope = WebScope(config)
    client = WebClient(scope, timeout=2)
    spec = web_fetch_spec(scope, client, FlagFormat(), 30, 8000)
    return spec, client


@pytest.fixture
def server():
    with MockWebServer() as srv:
        srv.html("/", "<html><body>home flag{web_fetch} page</body></html>")
        srv.json("/api", {"token": "secret", "ok": True})
        srv.redirect("/go", "/dest")
        srv.html("/dest", "destination reached")
        srv.redirect("/out", "http://example.com/elsewhere")
        srv.add("/big", Route(status=200, body=b"A" * 5000, content_type="text/plain"))
        srv.add("/cookie", Route(
            status=200, body=b"set", content_type="text/plain",
            headers=[("Set-Cookie", "sid=deadbeef; Path=/; HttpOnly")],
        ))
        yield srv


def run(spec, client, **args):
    cleaned = validate_args(spec, args)
    return spec.execute(cleaned, (), [])


def test_fetch_renders_status_and_body(server):
    spec, client = build(server)
    result = run(spec, client, path="/")
    assert result.returncode == 200
    assert result.network_active is True
    assert result.activity == "active"
    assert "200" in result.output
    assert "home" in result.output


def test_fetch_detects_flag(server):
    spec, client = build(server)
    result = run(spec, client, path="/")
    assert result.data["flags"] == ["flag{web_fetch}"]
    assert "Flag-shaped strings detected" in result.output


def test_fetch_head_has_no_body(server):
    spec, client = build(server)
    result = run(spec, client, path="/", method="HEAD")
    assert result.returncode == 200
    assert "home flag" not in result.output


def test_fetch_missing_route(server):
    spec, client = build(server)
    result = run(spec, client, path="/nope")
    assert result.data["final_status"] == 404


def test_fetch_follows_same_origin_redirect(server):
    spec, client = build(server)
    result = run(spec, client, path="/go", follow_redirects=True)
    assert result.data["final_status"] == 200
    assert "destination reached" in result.output
    assert len(result.data["responses"]) == 2


def test_cross_origin_redirect_annotated_blocked(server):
    spec, client = build(server)
    result = run(spec, client, path="/out", follow_redirects=True)
    # The first hop is returned; the redirect is refused rather than followed.
    assert len(result.data["responses"]) == 1
    assert "redirect blocked" in result.output


def test_absolute_cross_origin_path_refused(server):
    spec, client = build(server)
    with pytest.raises(ToolError, match="authorized origin"):
        run(spec, client, path="http://example.com/x")


def test_absolute_same_origin_url_accepted(server):
    spec, client = build(server)
    result = run(spec, client, path=f"{server.origin}/")
    assert result.returncode == 200


def test_oversized_body_truncated(server):
    spec, client = build(server, max_body_bytes=1024)
    result = run(spec, client, path="/big")
    assert result.data["responses"][0]["body_truncated"] is True


def test_set_cookie_redacted(server):
    spec, client = build(server)
    result = run(spec, client, path="/cookie")
    assert "deadbeef" not in result.output
    assert "set-cookie: ***REDACTED***" in result.output.lower() or "REDACTED" in result.output


def test_budget_exhausted_is_rejected(server):
    spec, client = build(server, max_requests=1)
    run(spec, client, path="/")
    with pytest.raises(ToolError, match="budget"):
        run(spec, client, path="/dest")


def test_unknown_argument_rejected(server):
    spec, _ = build(server)
    with pytest.raises(ToolError, match="Unknown argument"):
        validate_args(spec, {"path": "/", "shell": "rm -rf /"})


def test_bad_method_rejected_by_schema(server):
    spec, _ = build(server)
    with pytest.raises(ToolError, match="one of"):
        validate_args(spec, {"path": "/", "method": "DELETE"})


def test_registry_only_exposes_web_tools_when_authorized(server, tmp_path):
    from gryphos.ctf.tools import build_solver_registry

    offline = build_solver_registry(tmp_path, 30, 8000)
    assert "web_fetch" not in offline

    config = WebConfig.from_dict({"origin": server.origin, "lab": True})
    scope = WebScope(config)
    client = WebClient(scope, timeout=2)
    online = build_solver_registry(tmp_path, 30, 8000, web_scope=scope, web_client=client)
    assert "web_fetch" in online
