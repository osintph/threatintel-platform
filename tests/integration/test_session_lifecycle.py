"""
Integration tests for the request-scoped SQLAlchemy session lifecycle (COR-05 / PERF-05).

Test 1 — same session within a request, fresh session per new request.
Test 2 — outside Flask context (CLI path) each get_session() call owns its session.
Test 3 — close_db() teardown closes the session even when the request handler raises.
"""

import pytest
from flask import Flask, g

from darkweb_scanner.storage import Storage, _FLASK_SESSION_KEY
from darkweb_scanner.dashboard.storage_helper import close_db

_TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture
def test_storage():
    return Storage(_TEST_DB_URL)


@pytest.fixture
def app(test_storage):
    """Minimal Flask app with close_db wired as teardown_appcontext."""
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-session-lifecycle-secret"
    flask_app.teardown_appcontext(close_db)
    return flask_app


def test_same_session_within_request_fresh_across_requests(test_storage, app):
    """Within a single Flask request both get_session() calls yield the same
    Session object; a subsequent request gets a distinct fresh Session."""
    created = []
    original_factory = test_storage._SessionFactory

    def spy_factory():
        s = original_factory()
        created.append(s)
        return s

    test_storage._SessionFactory = spy_factory
    try:
        # --- Request 1: two get_session() calls must share one Session ---
        with app.test_request_context("/"):
            with test_storage.get_session() as s1:
                pass
            with test_storage.get_session() as s2:
                pass
            assert s1 is s2, "Both calls in one request must return the same session"

        # --- Request 2: fresh context must produce a distinct Session ---
        with app.test_request_context("/"):
            with test_storage.get_session() as s3:
                pass
            assert s3 is not s1, "New request must receive a fresh session"
    finally:
        test_storage._SessionFactory = original_factory

    assert len(created) == 2, "_SessionFactory must be called exactly once per request"


def test_cli_path_owns_and_closes_session(test_storage):
    """Outside a Flask request context each get_session() call creates and
    closes its own Session, preserving the original per-call behaviour."""
    created = []
    closed = []
    original_factory = test_storage._SessionFactory

    def spy_factory():
        s = original_factory()
        original_close = s.close

        def tracked_close():
            closed.append(s)
            original_close()

        s.close = tracked_close
        created.append(s)
        return s

    test_storage._SessionFactory = spy_factory
    try:
        test_storage.get_stats()
        test_storage.get_stats()
    finally:
        test_storage._SessionFactory = original_factory

    assert len(created) == 2, "CLI path must create one session per call"
    assert len(closed) == 2, "CLI path must close each session when the with-block exits"


def test_teardown_closes_session_on_exception(test_storage, app):
    """close_db() closes the request-scoped session even when called with a
    non-None exc argument, simulating teardown after a handler raises."""
    closed = []
    original_factory = test_storage._SessionFactory

    def spy_factory():
        s = original_factory()
        original_close = s.close

        def tracked_close():
            closed.append(s)
            original_close()

        s.close = tracked_close
        return s

    test_storage._SessionFactory = spy_factory
    try:
        with app.test_request_context("/"):
            # Simulate a handler that acquires a DB session then raises
            with test_storage.get_session() as session:
                pass  # session is now stashed in g
            in_g = getattr(g, _FLASK_SESSION_KEY, None)
            assert in_g is session, "Session must be stashed in g before teardown"

            # Invoke teardown with a non-None exc (as Flask would on handler error)
            close_db(RuntimeError("deliberate handler failure"))

        # After the request context exits, teardown_appcontext runs close_db(None)
        # again — but the session was already removed from g, so it is a no-op.
        assert len(closed) == 1, "Session must be closed exactly once by close_db"
    finally:
        test_storage._SessionFactory = original_factory
