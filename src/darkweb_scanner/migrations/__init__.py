"""
Database schema migrations (Alembic).

Storage() calls migrate() when it is created, so the schema follows the code
and an upgrade needs no separate step:

* an empty database gets the current schema straight from the models and is
  marked with the newest revision;
* any other database is upgraded revision by revision. A database from before
  migrations existed (release 1.2.0 and older) has no alembic_version table;
  for it the baseline revision creates only the tables that are missing.

On PostgreSQL the whole run is one transaction under an advisory lock: a
failed migration leaves the schema as it was, and two processes starting at
the same time do not run it twice.

There is no alembic.ini. To add a revision, see docs/runbook.md ("Database schema").
"""

import logging
from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
_ADVISORY_LOCK_KEY = 728193011  # any fixed number; names this application's migration run


def _config(connection: Optional[Connection] = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(_HERE))
    cfg.attributes["connection"] = connection
    return cfg


def head() -> str:
    """The newest revision the code knows."""
    revision = ScriptDirectory.from_config(_config()).get_current_head()
    assert revision is not None
    return revision


def current(engine: Engine) -> Optional[str]:
    """The revision the database is at; None for a database that was never marked."""
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def _lock(conn: Connection) -> None:
    if conn.dialect.name == "postgresql":
        conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _ADVISORY_LOCK_KEY})


def migrate(engine: Engine) -> str:
    """Bring the database to the newest revision and return that revision."""
    target = head()
    if current(engine) == target:
        return target

    with engine.begin() as conn:
        _lock(conn)
        # Read again under the lock: another process may have just finished the work.
        revision = MigrationContext.configure(conn).get_current_revision()
        if revision == target:
            return target
        cfg = _config(conn)
        if revision is None and not inspect(conn).get_table_names():
            from ..storage import Base

            Base.metadata.create_all(conn)
            command.stamp(cfg, "head")
            logger.info("Database schema created at revision %s", target)
        else:
            command.upgrade(cfg, "head")
            logger.info(
                "Database schema upgraded from %s to revision %s",
                f"revision {revision}" if revision else "an unversioned database (1.2.0 or older)",
                target,
            )
    return target


def downgrade(engine: Engine, revision: str) -> None:
    """Take the schema back to ``revision``. Needed before running an older release."""
    with engine.begin() as conn:
        _lock(conn)
        command.downgrade(_config(conn), revision)
    logger.info("Database schema downgraded to revision %s", revision)
