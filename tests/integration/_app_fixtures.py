"""Fixtures for tests that run the real application (create_app) on an empty database."""

import os

import pytest

from darkweb_scanner.storage import Storage
from tests.helpers import use_storage

SECRET_KEY = "test-secret-key-0123456789abcdef0123456789abcdef"
SETUP_TOKEN = "test-setup-token-0123456789abcdef"


@pytest.fixture(autouse=True)
def db(monkeypatch):
    """Every test gets its own empty database behind the app and the auth layer.

    In-memory SQLite by default. With TEST_DATABASE_URL set (CI's PostgreSQL job)
    the tests run on that database, which is emptied before each test: never
    point it at a database that holds anything.
    """
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        yield use_storage(monkeypatch, Storage("sqlite:///:memory:"))
        return
    empty_database(url)
    storage = Storage(url)
    try:
        yield use_storage(monkeypatch, storage)
    finally:
        storage.engine.dispose()


def empty_database(url: str) -> None:
    """Drop every table in a PostgreSQL test database, including alembic_version."""
    from sqlalchemy import create_engine, text

    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()


@pytest.fixture
def data_dir(monkeypatch, tmp_path):
    """Point the files the dashboard writes (keywords, seeds, subscribers ...) at a temp dir."""
    from darkweb_scanner import digest
    from darkweb_scanner.dashboard import dashboard_routes as dr

    for name, rel in (
        ("DATA_DIR", ""),
        ("KEYWORDS_FILE", "keywords.yaml"),
        ("SEEDS_FILE", "seeds.txt"),
        ("CRAWL_FLAG", "crawl.start"),
        ("STOP_FLAG", "crawl.stop"),
    ):
        monkeypatch.setattr(dr, name, tmp_path / rel if rel else tmp_path)
    monkeypatch.setattr(digest, "DATA_DIR", tmp_path)
    monkeypatch.setattr(digest, "SUBSCRIBERS_FILE", tmp_path / "digest_subscribers.txt")
    return tmp_path


@pytest.fixture
def full_app(monkeypatch, db, data_dir):
    """The real application from create_app(), on an empty database."""
    monkeypatch.setenv("DASHBOARD_SECRET_KEY", SECRET_KEY)
    monkeypatch.setenv("SETUP_TOKEN", SETUP_TOKEN)
    monkeypatch.delenv("DASHBOARD_ALLOW_HTTP", raising=False)
    from darkweb_scanner.dashboard.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(full_app):
    return full_app.test_client()
