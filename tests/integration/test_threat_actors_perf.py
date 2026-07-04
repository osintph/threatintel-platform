"""
Integration / performance tests for the /api/threat-actors endpoint.

Verifies:
  1. Response shape matches the old per-keyword implementation.
  2. The endpoint issues a bounded (single-digit) number of SQL queries
     regardless of how many keywords the actors define.
"""

from contextlib import contextmanager
from unittest.mock import patch

import pytest
from flask import Flask
from sqlalchemy import event

from darkweb_scanner.storage import Storage, KeywordHitRecord
from darkweb_scanner.dashboard.storage_helper import close_db

_TEST_DB_URL = "sqlite:///:memory:"

# 5 synthetic actors, 10 keywords each — 50 keywords total
_TEST_ACTORS = [
    {
        "name": f"TestActor{i}",
        "slug": f"testactor{i}",
        "aliases": [],
        "origin": "Test",
        "type": "nation-state",
        "status": "active",
        "risk_level": "critical",
        "first_seen": "2020",
        "targeting_sea": True,
        "sectors": ["government"],
        "countries_targeted": ["Philippines"],
        "description": f"Synthetic actor {i}",
        "ttps": [],
        "known_malware": [],
        "keywords": [f"akw_{i}_{j}" for j in range(10)],
    }
    for i in range(5)
]


@contextmanager
def _count_queries(engine):
    """Yield a list that accumulates one entry per SQL statement executed."""
    executed = []

    def listener(conn, cursor, statement, params, context, executemany):
        executed.append(statement)

    event.listen(engine, "before_cursor_execute", listener)
    try:
        yield executed
    finally:
        event.remove(engine, "before_cursor_execute", listener)


@pytest.fixture
def test_storage():
    storage = Storage(_TEST_DB_URL)
    # Seed 20 hits: 4 hits per actor, covering the first 4 keywords of each actor
    with storage.get_session() as session:
        for actor_idx in range(5):
            for hit_idx in range(4):
                kw = f"akw_{actor_idx}_{hit_idx}"
                session.add(
                    KeywordHitRecord(
                        url=f"http://actor{actor_idx}.onion/p{hit_idx}",
                        keyword=kw,
                        category="test",
                        context=f"ctx {kw}",
                        depth=1,
                    )
                )
        session.commit()
    return storage


@pytest.fixture
def app(test_storage):
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-threat-actors-perf-secret"
    flask_app.teardown_appcontext(close_db)

    from darkweb_scanner.dashboard.dashboard_routes import dashboard_bp
    flask_app.register_blueprint(dashboard_bp)

    return flask_app


def _get_response(app, test_storage):
    """Make an authenticated GET /api/threat-actors and return the response."""
    with (
        patch(
            "darkweb_scanner.dashboard.dashboard_routes.get_storage",
            return_value=test_storage,
        ),
        patch(
            "darkweb_scanner.threat_actors.THREAT_ACTORS",
            _TEST_ACTORS,
        ),
        app.test_client() as client,
    ):
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = 1
        return client.get("/api/threat-actors")


def test_response_shape(app, test_storage):
    """Endpoint returns one entry per actor with the expected fields and counts."""
    resp = _get_response(app, test_storage)
    assert resp.status_code == 200

    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) == len(_TEST_ACTORS)

    slugs_returned = {entry["slug"] for entry in data}
    assert slugs_returned == {a["slug"] for a in _TEST_ACTORS}

    for entry in data:
        assert "hit_count" in entry
        assert "recent_hits" in entry
        assert "last_seen" in entry
        assert "is_custom" in entry
        assert isinstance(entry["recent_hits"], list)
        assert entry["is_custom"] is False

    hits_by_slug = {e["slug"]: e for e in data}
    for i in range(5):
        entry = hits_by_slug[f"testactor{i}"]
        assert entry["hit_count"] == 4, f"testactor{i} should have 4 hits"
        assert entry["last_seen"] is not None
        assert len(entry["recent_hits"]) == 4


def test_query_count_bounded(app, test_storage):
    """Endpoint must issue a single-digit number of queries regardless of keyword count.

    With 50 keywords across 5 actors the old N+1 pattern would issue 50+ queries;
    the new batch implementation must stay well under 10.
    """
    with (
        patch(
            "darkweb_scanner.dashboard.dashboard_routes.get_storage",
            return_value=test_storage,
        ),
        patch(
            "darkweb_scanner.threat_actors.THREAT_ACTORS",
            _TEST_ACTORS,
        ),
        app.test_client() as client,
    ):
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = 1

        with _count_queries(test_storage.engine) as queries:
            resp = client.get("/api/threat-actors")

    assert resp.status_code == 200
    assert len(queries) <= 5, (
        f"Expected ≤5 queries for threat-actors endpoint, got {len(queries)}: "
        + "\n".join(q[:80] for q in queries)
    )
