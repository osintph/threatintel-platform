"""
Integration tests for SEC-FABLE-6: verify that stack traces and resolved IPs
are not returned to clients in error responses.
"""

import json
from unittest.mock import patch

import pytest
from flask import Flask

from darkweb_scanner.dashboard.http_client import SafeFetchError
from darkweb_scanner.dashboard.storage_helper import close_db


@pytest.fixture
def app():
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-error-disclosure-secret"
    flask_app.teardown_appcontext(close_db)

    from darkweb_scanner.dashboard.dashboard_routes import dashboard_bp
    flask_app.register_blueprint(dashboard_bp)
    return flask_app


def _authed_client(app):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["user_id"] = 1
    return client


def test_report_pdf_error_does_not_leak_traceback(app):
    """api_report_pdf must not return the traceback or exception message to the client."""
    sentinel = "SENSITIVE_INTERNAL_DETAIL_XYZ"
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.get_storage",
        side_effect=RuntimeError(sentinel),
    ):
        resp = _authed_client(app).get("/api/report/pdf")

    assert resp.status_code == 500
    body = resp.get_data(as_text=True)
    assert sentinel not in body, "Exception message must not appear in response"
    assert "Traceback" not in body, "Stack trace must not appear in response"
    assert "traceback" not in body.lower(), "Stack trace must not appear in response"

    data = json.loads(body)
    assert "error_id" in data, "Response must include an opaque error_id"
    assert sentinel not in data.get("error", "")


def test_safe_fetch_error_does_not_leak_ip(app):
    """Proxy routes must not return resolved private IPs from SafeFetchError messages."""
    private_ip = "10.0.0.5"
    err_msg = f"Blocked: 'feodotracker.abuse.ch' resolves to a private/loopback address '{private_ip}'"
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.safe_fetch",
        side_effect=SafeFetchError(err_msg),
    ):
        resp = _authed_client(app).get("/api/proxy/feodo")

    assert resp.status_code == 502
    body = resp.get_data(as_text=True)
    assert private_ip not in body, "Private IP must not appear in client response"
    assert "10.0.0" not in body, "IP octets must not appear in client response"
