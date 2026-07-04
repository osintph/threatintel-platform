"""
Integration tests for SEC-05/SEC-06: verify that dashboard proxy routes
and dns_crawler.fetch_crtsh use safe_fetch instead of insecure urllib/requests.

Tests confirm that:
  1. /api/proxy/threatfox calls safe_fetch with the correct abuse.ch URL.
  2. /api/proxy/urlhaus calls safe_fetch with the correct abuse.ch URL.
  3. /api/proxy/feodo calls safe_fetch with the Feodo Tracker URL.
  4. /api/dns/certs/<domain> calls safe_fetch with the crt.sh URL.
  5. dns_crawler.fetch_crtsh() calls safe_fetch with the crt.sh URL.
"""

from unittest.mock import patch

import pytest
from flask import Flask

from darkweb_scanner.dashboard.storage_helper import close_db

_TEST_DB_URL = "sqlite:///:memory:"


def _ok(url: str, body: bytes = b'{"query_status":"ok"}') -> dict:
    return {"status": 200, "headers": {}, "body": body, "url": url}


@pytest.fixture
def app():
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-proxy-safety-secret"
    flask_app.teardown_appcontext(close_db)

    from darkweb_scanner.dashboard.dashboard_routes import dashboard_bp
    flask_app.register_blueprint(dashboard_bp)
    return flask_app


def _authed_client(app):
    """Return a test client with a valid login session."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["user_id"] = 1
    return client


# ── Proxy route tests ─────────────────────────────────────────────────────────

def test_threatfox_proxy_calls_safe_fetch(app):
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.safe_fetch",
        return_value=_ok("https://threatfox-api.abuse.ch/api/v1/"),
    ) as mock_fetch:
        resp = _authed_client(app).post(
            "/api/proxy/threatfox",
            json={"query": "get_iocs", "type": "url"},
        )

    assert resp.status_code == 200
    mock_fetch.assert_called_once()
    assert "threatfox-api.abuse.ch" in mock_fetch.call_args[0][0]


def test_urlhaus_proxy_calls_safe_fetch(app):
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.safe_fetch",
        return_value=_ok("https://urlhaus-api.abuse.ch/v1/urls/recent/"),
    ) as mock_fetch:
        resp = _authed_client(app).post("/api/proxy/urlhaus")

    assert resp.status_code == 200
    mock_fetch.assert_called_once()
    assert "urlhaus-api.abuse.ch" in mock_fetch.call_args[0][0]


def test_feodo_proxy_calls_safe_fetch(app):
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.safe_fetch",
        return_value=_ok(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            body=b'[{"ip": "1.2.3.4"}]',
        ),
    ) as mock_fetch:
        resp = _authed_client(app).get("/api/proxy/feodo")

    assert resp.status_code == 200
    mock_fetch.assert_called_once()
    assert "feodotracker.abuse.ch" in mock_fetch.call_args[0][0]


def test_dns_certs_calls_safe_fetch(app):
    cert_body = (
        b'[{"id":1,"issuer_name":"C=US, O=Test CA","common_name":"example.com",'
        b'"name_value":"example.com","not_before":"2024-01-01","not_after":"2025-01-01"}]'
    )
    with patch(
        "darkweb_scanner.dashboard.dashboard_routes.safe_fetch",
        return_value=_ok("https://crt.sh/?q=%.example.com&output=json", body=cert_body),
    ) as mock_fetch:
        resp = _authed_client(app).get("/api/dns/certs/example.com")

    # Route may return 200 or 500 depending on cert-parsing, but safe_fetch must be called
    mock_fetch.assert_called_once()
    call_url = mock_fetch.call_args[0][0]
    assert "crt.sh" in call_url
    assert "example.com" in call_url


# ── dns_crawler.fetch_crtsh uses safe_fetch ───────────────────────────────────

def test_dns_crawler_fetch_crtsh_calls_safe_fetch():
    """fetch_crtsh must route through safe_fetch, not _safe_http directly."""
    crtsh_body = b'[{"name_value": "www.example.com\\napi.example.com"}]'
    with patch(
        "darkweb_scanner.dashboard.http_client.safe_fetch",
        return_value=_ok("https://crt.sh/?q=%.example.com&output=json", body=crtsh_body),
    ) as mock_fetch:
        from darkweb_scanner.dns_crawler import fetch_crtsh
        result = fetch_crtsh("example.com")

    mock_fetch.assert_called_once()
    call_url = mock_fetch.call_args[0][0]
    assert "crt.sh" in call_url
    assert "%.example.com" in call_url
    assert isinstance(result, list)
