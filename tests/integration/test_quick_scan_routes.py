"""
Integration tests for the /api/quick-scan/* routes.

Covers auth enforcement (unauthenticated blocked, cross-user 403), the single-active
-scan 409 guard, and the full start -> poll status -> list findings happy path.

The background worker is run inline (threading.Thread patched to execute its target
synchronously) so the scan completes deterministically within the request and shares
the same in-memory SQLite connection.
"""

from unittest.mock import patch

import pytest
from flask import Blueprint, Flask

from darkweb_scanner import quick_scan as qs
from darkweb_scanner.dashboard.dashboard_routes import dashboard_bp
from darkweb_scanner.dashboard.storage_helper import close_db
from darkweb_scanner.storage import Storage

_SEARCH_HTML = (
    '<html><body>results '
    '<a href="http://aaaaaaaaaaaaaaaaaaaaaaaaaa.onion/hit1">r1</a>'
    '</body></html>'
)
_HIT_HTML = '<html><body>acme.com credentials leaked and for sale here</body></html>'


def _page_for(url):
    if "/hit" in url:
        return 200, _HIT_HTML
    return 200, _SEARCH_HTML


class _InlineThread:
    """Drop-in for threading.Thread that runs its target synchronously on start()."""

    def __init__(self, target=None, daemon=None, name=None, args=(), kwargs=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        if self._target:
            self._target(*self._args, **self._kwargs)


@pytest.fixture
def storage():
    return Storage("sqlite:///:memory:")


@pytest.fixture
def app(storage):
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-quick-scan-secret"
    flask_app.teardown_appcontext(close_db)

    # Stub auth blueprint so require_login's redirect target (auth.login) resolves.
    auth_bp = Blueprint("auth", __name__)

    @auth_bp.route("/login")
    def login():
        return "login", 200

    flask_app.register_blueprint(auth_bp)
    flask_app.register_blueprint(dashboard_bp)
    return flask_app


def _login(client, user_id=1, username="tester"):
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["user_id"] = user_id
        sess["username"] = username


# ── Auth ─────────────────────────────────────────────────────────────────────


def test_unauthenticated_is_blocked(app, storage):
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.get_storage", return_value=storage
    ), app.test_client() as client:
        resp = client.get("/api/quick-scan/sessions")
    # require_login redirects unauthenticated requests to the login page.
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("Location", "")


def test_cross_user_status_is_forbidden(app, storage):
    other_sid = storage.create_quick_scan_session(
        2, "acme.com", "domain", ["acme.com"], ["ahmia"]
    )
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.get_storage", return_value=storage
    ), app.test_client() as client:
        _login(client, user_id=1)
        resp = client.get(f"/api/quick-scan/status/{other_sid}")
        findings_resp = client.get(f"/api/quick-scan/findings/{other_sid}")
    assert resp.status_code == 403
    assert findings_resp.status_code == 403


# ── 409 single-active-scan guard ───────────────────────────────────────────────


def test_second_start_while_active_returns_409(app, storage):
    # Seed an already-active (pending) scan for user 1.
    storage.create_quick_scan_session(1, "prior.com", "domain", ["prior.com"], ["ahmia"])
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.get_storage", return_value=storage
    ), app.test_client() as client:
        _login(client, user_id=1)
        resp = client.post(
            "/api/quick-scan/start", json={"target": "acme.com", "target_type": None, "sources": None}
        )
    assert resp.status_code == 409


# ── Happy path ─────────────────────────────────────────────────────────────────


def test_start_poll_and_list_findings(app, storage, monkeypatch):
    monkeypatch.setenv("QUICK_SCAN_DELAY_MIN", "0")
    monkeypatch.setenv("QUICK_SCAN_DELAY_MAX", "0")

    async def _fake_fetch(url, tor_client):
        return _page_for(url)

    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.get_storage", return_value=storage
    ), patch("threading.Thread", _InlineThread), patch.object(
        qs, "_fetch", _fake_fetch
    ), app.test_client() as client:
        _login(client, user_id=1)

        start = client.post(
            "/api/quick-scan/start",
            json={"target": "acme.com", "target_type": "domain", "sources": ["ahmia"]},
        )
        assert start.status_code == 201
        session_id = start.get_json()["session_id"]

        # Inline worker means the scan is already done by the time start returns.
        status = client.get(f"/api/quick-scan/status/{session_id}")
        assert status.status_code == 200
        body = status.get_json()
        assert body["status"] == "completed"
        assert body["urls_visited"] >= 1
        assert body["findings_count"] >= 1

        findings = client.get(f"/api/quick-scan/findings/{session_id}")
        assert findings.status_code == 200
        rows = findings.get_json()
        assert rows
        assert rows[0]["matched_variant"] == "acme.com"
        assert "acme.com" in rows[0]["context"]

        # high_signal_only filter returns a subset that is all high-signal.
        hi = client.get(f"/api/quick-scan/findings/{session_id}?high_signal_only=1")
        assert hi.status_code == 200
        assert all(r["high_signal"] for r in hi.get_json())

        # Session shows up in the user's session list.
        sessions = client.get("/api/quick-scan/sessions")
        assert sessions.status_code == 200
        assert any(s["id"] == session_id for s in sessions.get_json())


def test_start_requires_target(app, storage):
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.get_storage", return_value=storage
    ), app.test_client() as client:
        _login(client, user_id=1)
        resp = client.post("/api/quick-scan/start", json={"target": "  "})
    assert resp.status_code == 400
