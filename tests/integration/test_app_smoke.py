"""
OPS-22: the application factory builds, and every route in its URL map is behind sign-in.

A route added without a decorator, or a blueprint registered by mistake, fails here.
"""

import pytest

# Reachable without a session, on purpose.
PUBLIC = {
    "/",  # redirects to the dashboard
    "/login",
    "/register",  # closed once a user exists
    "/totp/verify",  # second step of sign-in; redirects without a pending sign-in
    "/healthz",  # container healthcheck, 404 through nginx
    "/api/health",
    "/static/<path:filename>",
}


def _rules(app):
    return sorted(app.url_map.iter_rules(), key=lambda r: r.rule)


def _path(rule) -> str:
    path = rule.rule
    for arg in rule.arguments:
        for conv in ("int:", "path:", "string:", ""):
            path = path.replace(f"<{conv}{arg}>", "1")
    return path


def test_create_app_builds_and_registers_the_expected_parts(full_app):
    endpoints = {r.endpoint for r in full_app.url_map.iter_rules()}
    assert {
        "auth.login",
        "auth.logout",
        "dashboard.index",
        "dashboard.help_page",
        "healthz",
    } <= endpoints
    assert any(e.startswith("channel_monitor.") for e in endpoints)
    assert not any("oauth" in e for e in endpoints), "OAuth routes were removed"
    assert "csrf_token" in full_app.jinja_env.globals
    assert full_app.config["SESSION_COOKIE_NAME"] == "__Host-session"
    assert full_app.config["SESSION_COOKIE_SECURE"] is True
    assert full_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert len(list(full_app.url_map.iter_rules())) > 100


def test_every_route_needs_a_session(full_app, db):
    from tests.helpers import make_user

    make_user(db, "exists")  # otherwise /login redirects to first-admin setup
    client = full_app.test_client()
    with client.session_transaction() as sess:
        sess["_csrf"] = "smoke"
    open_routes = []
    for rule in _rules(full_app):
        if rule.rule in PUBLIC:
            continue
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            resp = client.open(_path(rule), method=method, headers={"X-CSRF-Token": "smoke"})
            if rule.rule.startswith("/api/"):
                ok = resp.status_code == 401
            else:
                ok = resp.status_code == 302 and "/login" in resp.headers.get("Location", "")
            if not ok:
                open_routes.append(f"{method} {rule.rule} -> {resp.status_code}")
    assert open_routes == []


def test_public_list_is_exact(full_app):
    rules = {r.rule for r in full_app.url_map.iter_rules()}
    assert PUBLIC <= rules, f"stale entries in PUBLIC: {PUBLIC - rules}"


def test_signed_in_pages_render(full_app, db):
    from tests.helpers import make_user, sign_in

    client = full_app.test_client()
    sign_in(client, db, make_user(db, "boss", admin=True))
    for path in ("/dashboard", "/quick-scan", "/help"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        body = resp.get_data(as_text=True)
        assert 'name="csrf-token"' in body or path == "/help"
    help_page = client.get("/help").get_data(as_text=True)
    for phrase in (
        "Google Translate",
        "90 days",
        "Only administrators",
        "Two-factor sign-in is mandatory",
    ):
        assert phrase in help_page


def test_debug_server_is_gone():
    """OPS-10: no app.run() and no FLASK_DEBUG switch; gunicorn serves create_app()."""
    import inspect

    from darkweb_scanner.dashboard import app as app_module

    source = inspect.getsource(app_module)
    assert "app.run(" not in source and "FLASK_DEBUG" not in source
    assert not hasattr(app_module, "app"), "no application object is built at import time"


@pytest.mark.parametrize("env,name,secure", [("", "__Host-session", True), ("1", "session", False)])
def test_plain_http_cookie_only_with_the_development_switch(monkeypatch, db, env, name, secure):
    monkeypatch.setenv("DASHBOARD_SECRET_KEY", "test-secret-key-0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("DASHBOARD_ALLOW_HTTP", env)
    from darkweb_scanner.dashboard.app import create_app

    app = create_app()
    assert (app.config["SESSION_COOKIE_NAME"], app.config["SESSION_COOKIE_SECURE"]) == (
        name,
        secure,
    )
