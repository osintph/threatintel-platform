"""
Shared storage accessor — avoids circular imports between app.py and route modules.
"""

import threading

from ..storage import Storage, _FLASK_SESSION_KEY

_storage = None
# Guards first-time construction: Storage.__init__ runs create_all, and two
# concurrent requests racing it can collide in Postgres (pg_type_typname_nsp_index
# UniqueViolation) despite checkfirst.
_storage_lock = threading.Lock()


def get_storage() -> Storage:
    global _storage
    if _storage is None:
        with _storage_lock:
            if _storage is None:
                _storage = Storage()
    return _storage


def get_db():
    """Return the request-scoped SQLAlchemy Session for the current Flask request.

    On the first call within a request, creates a new Session bound to the
    existing engine and stashes it in flask.g under ``_FLASK_SESSION_KEY``.
    Subsequent calls within the same request return the cached Session.
    The companion ``close_db`` teardown handler closes it when the request ends.
    """
    from flask import g
    storage = get_storage()
    if not hasattr(g, _FLASK_SESSION_KEY):
        setattr(g, _FLASK_SESSION_KEY, storage._SessionFactory())
    return getattr(g, _FLASK_SESSION_KEY)


def close_db(exc=None):
    """Teardown handler — close (and roll back on error) the request-scoped session.

    Register via ``app.teardown_appcontext(close_db)`` in ``create_app()``.
    ``exc`` is the exception that caused teardown, if any; non-None triggers a
    rollback before close so the connection is returned to the pool cleanly.
    """
    from flask import g
    session = getattr(g, _FLASK_SESSION_KEY, None)
    if session is not None:
        if exc is not None:
            try:
                session.rollback()
            except Exception:
                pass
        session.close()
        try:
            delattr(g, _FLASK_SESSION_KEY)
        except AttributeError:
            pass
