"""
Integration / performance tests for the /api/ransomware/groups endpoint.

Verifies:
  1. Response shape matches the old per-keyword implementation.
  2. The endpoint issues a bounded (single-digit) number of SQL queries
     regardless of how many keywords the groups define.
"""

from contextlib import contextmanager
from unittest.mock import patch

import pytest
from flask import Flask
from sqlalchemy import event

from darkweb_scanner.storage import Storage, KeywordHitRecord
from darkweb_scanner.dashboard.storage_helper import close_db

_TEST_DB_URL = "sqlite:///:memory:"

# 5 synthetic groups, 10 keywords each — 50 keywords total
_TEST_GROUPS = [
    {
        "name": f"TestGroup{i}",
        "slug": f"testgroup{i}",
        "status": "active",
        "origin": "Test",
        "targeting_sea": True,
        "risk_level": "high",
        "description": f"Synthetic group {i}",
        "ttps": [],
        "keywords": [f"kw_{i}_{j}" for j in range(10)],
        "onion_seeds": [],
        "sea_victims": [],
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
    # Seed 20 hits: 4 hits per group, covering the first 4 keywords of each group
    with storage.get_session() as session:
        for group_idx in range(5):
            for hit_idx in range(4):
                kw = f"kw_{group_idx}_{hit_idx}"
                session.add(
                    KeywordHitRecord(
                        url=f"http://example{group_idx}.onion/p{hit_idx}",
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
    flask_app.secret_key = "test-rw-groups-perf-secret"
    flask_app.teardown_appcontext(close_db)

    from darkweb_scanner.dashboard.dashboard_routes import dashboard_bp
    flask_app.register_blueprint(dashboard_bp)

    return flask_app


def _get_response(app, test_storage):
    """Make an authenticated GET /api/ransomware/groups and return the JSON body."""
    with (
        patch(
            "darkweb_scanner.dashboard.dashboard_routes.get_storage",
            return_value=test_storage,
        ),
        patch(
            "darkweb_scanner.ransomware_data.RANSOMWARE_GROUPS",
            _TEST_GROUPS,
        ),
        app.test_client() as client,
    ):
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = 1
        return client.get("/api/ransomware/groups")


def test_response_shape(app, test_storage):
    """Endpoint returns one entry per group with the expected fields and counts."""
    resp = _get_response(app, test_storage)
    assert resp.status_code == 200

    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) == len(_TEST_GROUPS)

    slugs_returned = {entry["slug"] for entry in data}
    assert slugs_returned == {g["slug"] for g in _TEST_GROUPS}

    for entry in data:
        assert "hit_count" in entry
        assert "recent_hits" in entry
        assert "last_seen" in entry
        assert "is_custom" in entry
        assert isinstance(entry["recent_hits"], list)
        # All groups are from static data in this test
        assert entry["is_custom"] is False

    # Groups that have seeded hits must report them
    hits_by_slug = {e["slug"]: e for e in data}
    for i in range(5):
        entry = hits_by_slug[f"testgroup{i}"]
        assert entry["hit_count"] == 4, f"testgroup{i} should have 4 hits"
        assert entry["last_seen"] is not None
        assert len(entry["recent_hits"]) == 4


def test_query_count_bounded(app, test_storage):
    """Endpoint must issue a single-digit number of queries regardless of keyword count.

    With 50 keywords across 5 groups the old N+1 pattern would issue 50+ queries;
    the new batch implementation must stay well under 10.
    """
    with (
        patch(
            "darkweb_scanner.dashboard.dashboard_routes.get_storage",
            return_value=test_storage,
        ),
        patch(
            "darkweb_scanner.ransomware_data.RANSOMWARE_GROUPS",
            _TEST_GROUPS,
        ),
        app.test_client() as client,
    ):
        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = 1

        with _count_queries(test_storage.engine) as queries:
            resp = client.get("/api/ransomware/groups")

    assert resp.status_code == 200
    assert len(queries) <= 5, (
        f"Expected ≤5 queries for ransomware groups endpoint, got {len(queries)}: "
        + "\n".join(q[:80] for q in queries)
    )
