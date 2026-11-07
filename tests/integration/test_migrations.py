"""
REL-7: the schema is versioned. A new database, a database from release 1.2.0 and one
from before 1.2.0 all end at the same schema, which is the one the models describe.

Runs on SQLite by default and on PostgreSQL when TEST_DATABASE_URL is set (CI).
"""

import os

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from darkweb_scanner import migrations
from darkweb_scanner.storage import Base, Storage

from ._app_fixtures import empty_database


@pytest.fixture
def url(tmp_path):
    """An empty database of its own (the autouse ``db`` fixture is not used here)."""
    pg = os.getenv("TEST_DATABASE_URL")
    if pg:
        empty_database(pg)
        yield pg
        empty_database(pg)
    else:
        yield f"sqlite:///{tmp_path / 'schema.db'}"


def _engine(url):
    return create_engine(url)


def _upgrade(engine, revision):
    with engine.begin() as conn:
        command.upgrade(migrations._config(conn), revision)


def _release_1_2_0(engine, with_marker=False):
    """Build the schema as 1.2.0 left it: every baseline table, no alembic_version."""
    _upgrade(engine, "0001")
    if not with_marker:
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE alembic_version"))


def _differences(engine):
    """What Alembic would still change to make the database match the models."""
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        return compare_metadata(ctx, Base.metadata)


def _columns(engine, table):
    return {c["name"] for c in inspect(engine).get_columns(table)}


def test_a_new_database_is_created_at_the_newest_revision(url):
    storage = Storage(url)
    assert migrations.current(storage.engine) == migrations.head() == "0002"
    assert _differences(storage.engine) == []
    storage.engine.dispose()


def test_the_revisions_alone_build_the_schema_of_the_models(url):
    """Guards against a model change without a revision, and the reverse."""
    engine = _engine(url)
    _upgrade(engine, "head")
    assert _differences(engine) == []
    engine.dispose()


def test_a_1_2_0_database_is_upgraded_and_keeps_its_rows(url):
    engine = _engine(url)
    _release_1_2_0(engine)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, password_hash, totp_enabled, is_admin, must_change_password, oauth_provider)"
                " VALUES ('boss', 'hash', :t, :t, :f, NULL)"
            ),
            {"t": True, "f": False},
        )
        conn.execute(text("INSERT INTO crawl_sessions (status, pages_crawled, hits_found) VALUES ('completed', 3, 1)"))
        conn.execute(
            text("INSERT INTO seen_pastes (source, paste_id, url, had_hits) VALUES ('rentry', 'abc', 'https://x/', :f)"),
            {"f": False},
        )
    engine.dispose()

    storage = Storage(url)  # what the dashboard does at start
    assert migrations.current(storage.engine) == "0002"
    assert _differences(storage.engine) == []
    tables = set(inspect(storage.engine).get_table_names())
    assert not {"seen_pastes", "paste_hits"} & tables
    assert not {"oauth_provider", "oauth_id"} & _columns(storage.engine, "users")
    assert {"heartbeat_at", "owner", "error"} <= _columns(storage.engine, "crawl_sessions")
    user = storage.get_user_by_username("boss")
    assert user.is_admin is True and user.totp_enabled is True and user.password_hash == "hash"
    with storage.engine.connect() as conn:
        assert conn.execute(text("SELECT status, pages_crawled FROM crawl_sessions")).all() == [("completed", 3)]
    storage.engine.dispose()


def test_a_database_from_before_1_2_0_gets_the_missing_tables(url):
    """1.1.1 had no user_security, auth_events or auth_throttle; create_all added them in 1.2.0."""
    engine = _engine(url)
    _release_1_2_0(engine)
    with engine.begin() as conn:
        for table in ("user_security", "auth_events", "auth_throttle"):
            conn.execute(text(f"DROP TABLE {table}"))
        conn.execute(text("INSERT INTO users (username, password_hash) VALUES ('old', 'hash')"))
    engine.dispose()

    storage = Storage(url)
    assert _differences(storage.engine) == []
    assert storage.get_user_by_username("old") is not None
    storage.add_auth_event("login", "old", 1, "127.0.0.1", "test")
    storage.engine.dispose()


def test_starting_twice_changes_nothing(url):
    Storage(url).engine.dispose()
    engine = _engine(url)
    before = sorted(inspect(engine).get_table_names())
    engine.dispose()
    storage = Storage(url)
    assert sorted(inspect(storage.engine).get_table_names()) == before
    assert migrations.migrate(storage.engine) == "0002"
    storage.engine.dispose()


def test_downgrade_gives_back_what_1_2_0_needs_and_upgrade_works_again(url):
    storage = Storage(url)
    uid = storage.create_user("boss", password_hash="hash", is_admin=True)
    migrations.downgrade(storage.engine, "0001")
    assert migrations.current(storage.engine) == "0001"
    assert {"oauth_provider", "oauth_id"} <= _columns(storage.engine, "users")
    assert {"seen_pastes", "paste_hits"} <= set(inspect(storage.engine).get_table_names())
    assert not {"heartbeat_at", "owner", "error"} & _columns(storage.engine, "crawl_sessions")
    with storage.engine.connect() as conn:
        # the statements 1.2.0 runs against these tables still work
        assert conn.execute(text("SELECT oauth_provider, oauth_id FROM users WHERE id = :i"), {"i": uid}).one() == (None, None)
        assert conn.execute(text("SELECT count(*) FROM paste_hits")).scalar() == 0
    storage.engine.dispose()

    storage = Storage(url)
    assert migrations.current(storage.engine) == "0002"
    assert _differences(storage.engine) == []
    assert storage.get_user_by_id(uid).username == "boss"
    storage.engine.dispose()


def test_the_baseline_cannot_be_removed(url):
    storage = Storage(url)
    with pytest.raises(RuntimeError, match="baseline"):
        migrations.downgrade(storage.engine, "base")
    assert migrations.current(storage.engine) == "0002", "a refused downgrade must leave the schema alone"
    storage.engine.dispose()


def test_connections_are_checked_before_use_and_time_out(url, monkeypatch):
    storage = Storage(url)
    assert storage.engine.pool._pre_ping is True
    storage.engine.dispose()

    seen = {}

    def fake_create_engine(database_url, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    monkeypatch.setattr("darkweb_scanner.storage.create_engine", fake_create_engine)
    with pytest.raises(RuntimeError, match="stop here"):
        Storage("postgresql+psycopg2://scanner:x@db.invalid:5432/darkweb_scanner")
    assert seen["pool_pre_ping"] is True
    assert seen["connect_args"] == {"connect_timeout": 10}
