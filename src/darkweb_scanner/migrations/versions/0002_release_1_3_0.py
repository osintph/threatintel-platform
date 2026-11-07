"""Release 1.3.0: crawl heartbeat, no paste monitor tables, no OAuth columns

Revision ID: 0002
Revises: 0001

* crawl_sessions gains heartbeat_at, owner and error, so that a crawl whose
  process died can be told from one that is running, and a failed crawl says why.
* seen_pastes and paste_hits are dropped: the paste monitor was removed.
* users.oauth_provider and users.oauth_id are dropped: OAuth sign-in was
  removed in 1.2.0.

The downgrade restores the structure (empty tables, empty columns), which is
what the code of 1.2.0 needs to run; it cannot restore the dropped rows.
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _indexes(table: str) -> set[str]:
    return {i["name"] for i in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    have = _columns("crawl_sessions")
    with op.batch_alter_table("crawl_sessions") as batch:
        if "heartbeat_at" not in have:
            batch.add_column(sa.Column("heartbeat_at", sa.DateTime(), nullable=True))
        if "owner" not in have:
            batch.add_column(sa.Column("owner", sa.String(length=100), nullable=True))
        if "error" not in have:
            batch.add_column(sa.Column("error", sa.Text(), nullable=True))

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for name in ("paste_hits", "seen_pastes"):
        if name in tables:
            op.drop_table(name)

    # An install whose users table predates the index simply has nothing to drop.
    if "ix_users_oauth" in _indexes("users"):
        op.drop_index("ix_users_oauth", table_name="users")
    have = _columns("users")
    with op.batch_alter_table("users") as batch:
        for name in ("oauth_provider", "oauth_id"):
            if name in have:
                batch.drop_column(name)


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("oauth_provider", sa.String(length=50), nullable=True))
        batch.add_column(sa.Column("oauth_id", sa.String(length=255), nullable=True))
    op.create_index("ix_users_oauth", "users", ["oauth_provider", "oauth_id"], unique=False)

    op.create_table(
        "seen_pastes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("paste_id", sa.String(length=200), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(), nullable=True),
        sa.Column("had_hits", sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_seen_pastes_fetched", "seen_pastes", ["fetched_at"], unique=False)
    op.create_index("ix_seen_pastes_source_id", "seen_pastes", ["source", "paste_id"], unique=True)
    op.create_table(
        "paste_hits",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("paste_id", sa.String(length=200), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("matched_pattern", sa.String(length=100), nullable=False),
        sa.Column("matched_value", sa.String(length=500), nullable=True),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("found_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_paste_hits_found_at", "paste_hits", ["found_at"], unique=False)
    op.create_index("ix_paste_hits_pattern", "paste_hits", ["matched_pattern"], unique=False)
    op.create_index("ix_paste_hits_source", "paste_hits", ["source"], unique=False)

    with op.batch_alter_table("crawl_sessions") as batch:
        batch.drop_column("error")
        batch.drop_column("owner")
        batch.drop_column("heartbeat_at")
