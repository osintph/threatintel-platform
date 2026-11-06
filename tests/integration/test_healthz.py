"""OPS-13 / OPS-4: /healthz answers 200 only when a database query works."""

import importlib

import pytest

from darkweb_scanner.dashboard import storage_helper
from darkweb_scanner.storage import Storage


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("DASHBOARD_SECRET_KEY", "test-healthz-secret-0123456789abcdef0123456789")
    monkeypatch.setattr(storage_helper, "_storage", Storage("sqlite:///:memory:"))
    app_module = importlib.import_module("darkweb_scanner.dashboard.app")
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def test_healthz_ok_without_login(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok", "database": "ok"}


def test_healthz_503_when_the_database_is_unreachable(client, monkeypatch):
    def broken():
        raise RuntimeError("connection refused: secret-host:5432")

    monkeypatch.setattr(storage_helper, "get_db", broken)
    resp = client.get("/healthz")
    assert resp.status_code == 503
    body = resp.get_data(as_text=True)
    assert resp.get_json()["database"] == "unreachable"
    assert "secret-host" not in body, "the error detail must stay in the server log"


def test_healthcheck_requests_are_filtered_from_the_access_log():
    import logging

    from darkweb_scanner.dashboard.app import _SkipHealthcheckLog

    f = _SkipHealthcheckLog()
    keep = logging.LogRecord(
        "werkzeug", logging.INFO, "", 0, '127.0.0.1 - - "GET /login HTTP/1.1" 200 -', None, None
    )
    drop = logging.LogRecord(
        "werkzeug", logging.INFO, "", 0, '127.0.0.1 - - "GET /healthz HTTP/1.1" 200 -', None, None
    )
    assert f.filter(keep) is True
    assert f.filter(drop) is False
