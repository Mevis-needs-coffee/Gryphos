"""web_fetch tool: bounded fetch, redirects, scope refusal, redaction (offline)."""

from __future__ import annotations

import pytest
from webserver import MockWebServer, Route

from gryphos.ctf.flag import FlagFormat
from gryphos.ctf.webclient import WebClient
from gryphos.ctf.webconfig import WebConfig
from gryphos.ctf.webscope import WebScope
from gryphos.ctf.webtools import (
    web_analyze_spec,
    web_crawl_spec,
    web_fetch_spec,
    web_probe_spec,
    web_session_spec,
)
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


# --- web_crawl --------------------------------------------------------------

def _crawl_spec(server, **overrides):
    config = WebConfig.from_dict({"origin": server.origin, "lab": True, **overrides})
    scope = WebScope(config)
    client = WebClient(scope, timeout=2)
    return web_crawl_spec(scope, client, FlagFormat(), 30, 12000), scope, client


@pytest.fixture
def linky():
    with MockWebServer() as srv:
        srv.html("/", '<a href="/a">A</a> <a href="/b">B</a> <a href="http://example.com/out">out</a>')
        srv.html("/a", '<a href="/c">C</a>')
        srv.html("/b", "B page")
        srv.html("/c", "C page")
        yield srv


def test_crawl_visits_same_origin_and_lists_offsite(linky):
    spec, scope, client = _crawl_spec(linky)
    result = run(spec, client, path="/", max_pages=5, depth=2)
    paths = {page["path"] for page in result.data["pages"]}
    assert {"/", "/a", "/b", "/c"} <= paths
    assert any("example.com" in ref for ref in result.data["offsite_references"])
    fetched = {req["route"] for req in linky.requests}
    assert "example.com" not in " ".join(fetched)


def test_crawl_respects_max_pages(linky):
    spec, scope, client = _crawl_spec(linky)
    result = run(spec, client, path="/", max_pages=2, depth=3)
    assert len(result.data["pages"]) <= 2


def test_crawl_stops_at_budget(linky):
    spec, scope, client = _crawl_spec(linky, max_requests=1)
    result = run(spec, client, path="/", max_pages=5, depth=3)
    assert len(result.data["pages"]) == 1
    assert result.data["stopped"]


# --- web_analyze ------------------------------------------------------------

def _analyze_spec(server, **overrides):
    config = WebConfig.from_dict({"origin": server.origin, "lab": True, **overrides})
    scope = WebScope(config)
    client = WebClient(scope, timeout=2)
    return web_analyze_spec(scope, client, FlagFormat(), 30, 12000), scope, client


@pytest.fixture
def rich_page():
    page = (
        "<html><head><title>Login</title>"
        '<meta name="generator" content="flask"></head><body>'
        "<!-- TODO: remove debug admin panel -->"
        '<form action="/login" method="post">'
        '<input name="username"><input name="password" type="password">'
        '<input type="hidden" name="csrf" value="x"></form>'
        '<script src="/static/app.js"></script>'
        '<script>fetch("/api/items"); go("/admin/panel");</script>'
        "flag{analyze_me}</body></html>"
    )
    with MockWebServer() as srv:
        srv.html("/", page)
        srv.add("/robots.txt", Route(status=200, body=b"User-agent: *\nDisallow: /admin", content_type="text/plain"))
        srv.add("/sitemap.xml", Route(status=200, body=b"<urlset></urlset>", content_type="application/xml"))
        yield srv


def test_analyze_extracts_structure(rich_page):
    spec, scope, client = _analyze_spec(rich_page)
    result = run(spec, client, path="/")
    assert result.data["title"] == "Login"
    assert result.data["meta"]["generator"] == "flask"
    assert result.data["forms"][0]["method"] == "post"
    assert {f["name"] for f in result.data["forms"][0]["fields"]} == {"username", "password", "csrf"}
    assert "/api/items" in result.data["endpoints"]
    assert any("TODO" in c for c in result.data["comments"])
    assert result.data["flags"] == ["flag{analyze_me}"]


def test_analyze_optional_robots(rich_page):
    spec, scope, client = _analyze_spec(rich_page)
    result = run(spec, client, path="/", include_robots=True)
    extra_paths = {extra["path"]: extra for extra in result.data["extras"]}
    assert extra_paths["/robots.txt"]["status"] == 200
    assert "Disallow" in extra_paths["/robots.txt"]["body"]


def test_registry_exposes_all_web_tools(linky):
    from gryphos.ctf.tools import build_solver_registry

    config = WebConfig.from_dict({"origin": linky.origin, "lab": True})
    scope = WebScope(config)
    client = WebClient(scope, timeout=2)
    registry = build_solver_registry(linky, 30, 8000, web_scope=scope, web_client=client)
    assert {"web_fetch", "web_crawl", "web_analyze"} <= set(registry)


# --- web_session ------------------------------------------------------------

def _session_spec(server, **overrides):
    config = WebConfig.from_dict({"origin": server.origin, "lab": True, **overrides})
    scope = WebScope(config)
    client = WebClient(scope, timeout=2)
    return web_session_spec(scope, client, FlagFormat(), 30, 12000), scope, client


@pytest.fixture
def session_server():
    def login(server, handler):
        return Route(
            status=200,
            body=b"<a href='/dashboard'>d</a>",
            content_type="text/html",
            headers=[("Set-Cookie", "sid=secret123; Path=/; HttpOnly")],
        )

    def dashboard(server, handler):
        if "sid=secret123" in (handler.headers.get("Cookie") or ""):
            return Route(status=200, body=b"welcome flag{session_ok}", content_type="text/html")
        return Route(status=403, body=b"denied", content_type="text/html")

    with MockWebServer() as srv:
        srv.add("/login", login)
        srv.add("/dashboard", dashboard)
        yield srv


def test_session_stores_and_uses_cookie(session_server):
    spec, scope, client = _session_spec(session_server)
    result = run(spec, client, path="/login", method="POST", fields={"user": "a", "pass": "b"})
    assert "sid" in result.data["set_cookie_names"]
    assert "secret123" not in result.output
    assert result.data["cookies"][0]["http_only"] is True

    follow = run(spec, client, path="/dashboard", method="GET")
    assert follow.data["final_status"] == 200
    assert any("session_ok" in f for f in follow.data.get("flags", []))


def test_session_clear_cookies(session_server):
    spec, scope, client = _session_spec(session_server)
    run(spec, client, path="/login", method="POST", fields={"user": "a"})
    run(spec, client, path="/dashboard", method="GET", clear_cookies=True)
    result = run(spec, client, path="/dashboard", method="GET")
    assert result.data["final_status"] == 403


def test_session_reports_security_headers(session_server):
    spec, scope, client = _session_spec(session_server)
    result = run(spec, client, path="/login", method="GET")
    assert "content-security-policy" in result.data["security_headers"]


def test_secure_cookie_not_sent_over_http():
    def login(server, handler):
        return Route(status=200, body=b"ok", headers=[("Set-Cookie", "sid=x; Path=/; Secure")])

    def secure_only(server, handler):
        has = "sid=x" in (handler.headers.get("Cookie") or "")
        return Route(status=200 if has else 403, body=b"")

    with MockWebServer() as srv:
        srv.add("/login", login)
        srv.add("/private", secure_only)
        spec, scope, client = _session_spec(srv)
        run(spec, client, path="/login", method="GET")
        result = run(spec, client, path="/private", method="GET")
        assert result.data["final_status"] == 403


# --- web_probe --------------------------------------------------------------

def _probe_spec(server, **overrides):
    config = WebConfig.from_dict({"origin": server.origin, "lab": True, **overrides})
    scope = WebScope(config)
    client = WebClient(scope, timeout=2)
    return web_probe_spec(scope, client, FlagFormat(), 30, 12000), scope, client


@pytest.fixture
def probe_server():
    from urllib.parse import parse_qs
    from urllib.parse import urlsplit as us

    def search(server, handler):
        q = parse_qs(us(handler.path).query).get("q", [""])[0]
        if q == "admin":
            return Route(status=200, body=b"flag{probe_admin}", content_type="text/plain")
        return Route(status=200, body=b"no results", content_type="text/plain")

    def api(server, handler):
        import json as _json
        return Route(status=200, body=_json.dumps({"ok": True, "n": 1}).encode(), content_type="application/json")

    with MockWebServer() as srv:
        srv.add("/search", search)
        srv.add("/api", api)
        yield srv


def test_probe_compares_variants(probe_server):
    spec, scope, client = _probe_spec(probe_server)
    result = run(spec, client, path="/search", method="GET", variants=[
        {"label": "normal", "query": {"q": "x"}},
        {"label": "admin", "query": {"q": "admin"}},
    ])
    admin = result.data["variants"][1]
    assert admin["diff_vs_baseline"]
    assert any("probe_admin" in f for f in result.data.get("flags", []))


def test_probe_json_summary(probe_server):
    spec, scope, client = _probe_spec(probe_server)
    result = run(spec, client, path="/api", method="GET", variants=[{"label": "one"}])
    assert result.data["variants"][0]["json"]["keys"] == ["n", "ok"]


def test_registry_exposes_session_and_probe(session_server):
    from gryphos.ctf.tools import build_solver_registry

    config = WebConfig.from_dict({"origin": session_server.origin, "lab": True})
    scope = WebScope(config)
    client = WebClient(scope, timeout=2)
    registry = build_solver_registry(session_server, 30, 8000, web_scope=scope, web_client=client)
    assert {"web_session", "web_probe"} <= set(registry)
