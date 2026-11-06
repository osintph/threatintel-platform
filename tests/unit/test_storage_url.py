"""OPS-4: a bare postgresql:// URL must not select a driver the image does not ship."""

import pytest

from darkweb_scanner.storage import normalise_database_url


@pytest.mark.parametrize(
    "url,expected",
    [
        ("postgresql://u:p@postgres:5432/db", "postgresql+psycopg2://u:p@postgres:5432/db"),
        ("postgres://u:p@postgres:5432/db", "postgresql+psycopg2://u:p@postgres:5432/db"),
        ("postgresql+psycopg2://u:p@postgres:5432/db", "postgresql+psycopg2://u:p@postgres:5432/db"),
        ("postgresql+psycopg://u:p@postgres:5432/db", "postgresql+psycopg://u:p@postgres:5432/db"),
        ("sqlite:///:memory:", "sqlite:///:memory:"),
        ("sqlite:////app/data/results.db", "sqlite:////app/data/results.db"),
    ],
)
def test_normalise_database_url(url, expected):
    assert normalise_database_url(url) == expected


def test_storage_uses_the_normalised_url(monkeypatch):
    """Storage must hand SQLAlchemy the explicit driver, whatever .env says."""
    seen = {}

    def fake_create_engine(url, **kwargs):
        seen["url"] = url
        raise RuntimeError("stop before connecting")

    monkeypatch.setattr("darkweb_scanner.storage.create_engine", fake_create_engine)
    from darkweb_scanner.storage import Storage

    with pytest.raises(RuntimeError):
        Storage("postgresql://scanner:secret@postgres:5432/darkweb_scanner")
    assert seen["url"].startswith("postgresql+psycopg2://")
