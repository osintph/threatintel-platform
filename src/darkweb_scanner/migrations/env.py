"""Alembic environment. Driven from darkweb_scanner.migrations, never from the alembic CLI."""

from alembic import context

from darkweb_scanner.storage import Base

target_metadata = Base.metadata


def run_migrations_online() -> None:
    connection = context.config.attributes["connection"]
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite cannot alter a table in place; batch mode rebuilds it.
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


run_migrations_online()
