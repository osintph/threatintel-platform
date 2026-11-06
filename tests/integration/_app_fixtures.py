"""Fixtures for tests that run the real application (create_app) on an empty database."""

import os

import pytest

from darkweb_scanner.storage import Base, Storage
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
    storage = Storage(url)
    Base.metadata.drop_all(storage.engine)
    Base.metadata.create_all(storage.engine)
    try:
        yield use_storage(monkeypatch, storage)
    finally:
        storage.engine.dispose()


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
        ("CLEARNET_SEEDS_FILE", "clearnet_seeds.txt"),
        ("PASTE_SOURCES_FILE", "paste_sources.txt"),
        ("TELEGRAM_CHANNELS_FILE", "telegram_channels.txt"),
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
