"""Baseline: the schema of release 1.2.0

Revision ID: 0001
Revises:

Releases up to 1.2.0 created their tables with SQLAlchemy's create_all() and
kept no record of the schema. This revision describes that schema. On a
database that already has some or all of the tables (every existing install)
it creates only the ones that are missing and leaves the others untouched; on
an empty database it creates everything.

Never edit this file: later revisions describe every change since.
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_existing: set[str] = set()
_created: set[str] = set()


def _table(name: str, *columns, **kw) -> None:
    if name in _existing:
        return
    op.create_table(name, *columns, **kw)
    _created.add(name)


def _index(name: str, table: str, columns: list[str], **kw) -> None:
    # Only for a table this run created: an existing table already has its indexes.
    if table in _created:
        op.create_index(name, table, columns, **kw)


def upgrade() -> None:
    _existing.clear()
    _created.clear()
    _existing.update(sa.inspect(op.get_bind()).get_table_names())

    _table("auth_events",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("ts", sa.DateTime(), nullable=False),
    sa.Column("event", sa.String(length=40), nullable=False),
    sa.Column("username", sa.String(length=100), nullable=True),
    sa.Column("user_id", sa.Integer(), nullable=True),
    sa.Column("ip", sa.String(length=45), nullable=True),
    sa.Column("detail", sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_auth_events_ts", "auth_events", ["ts"], unique=False)
    _table("auth_throttle",
    sa.Column("key", sa.String(length=160), nullable=False),
    sa.Column("failures", sa.Integer(), nullable=False),
    sa.Column("window_start", sa.DateTime(), nullable=False),
    sa.Column("locked_until", sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint("key")
    )
    _table("crawl_sessions",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("started_at", sa.DateTime(), nullable=True),
    sa.Column("ended_at", sa.DateTime(), nullable=True),
    sa.Column("seed_urls", sa.Text(), nullable=True),
    sa.Column("pages_crawled", sa.Integer(), nullable=True),
    sa.Column("hits_found", sa.Integer(), nullable=True),
    sa.Column("status", sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _table("crawled_pages",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("session_id", sa.Integer(), nullable=True),
    sa.Column("url", sa.Text(), nullable=False),
    sa.Column("crawled_at", sa.DateTime(), nullable=True),
    sa.Column("status_code", sa.Integer(), nullable=True),
    sa.Column("depth", sa.Integer(), nullable=True),
    sa.Column("had_error", sa.Boolean(), nullable=True),
    sa.Column("error_message", sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_crawled_pages_session", "crawled_pages", ["session_id"], unique=False)
    _index("ix_crawled_pages_url", "crawled_pages", ["url"], unique=False)
    _table("custom_intel",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("intel_type", sa.String(length=50), nullable=False),
    sa.Column("slug", sa.String(length=200), nullable=False),
    sa.Column("data", sa.Text(), nullable=False),
    sa.Column("created_by", sa.String(length=200), nullable=True),
    sa.Column("created_at", sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint("id"),
    sa.UniqueConstraint("slug")
    )
    _index("ix_custom_intel_slug", "custom_intel", ["slug"], unique=False)
    _index("ix_custom_intel_type", "custom_intel", ["intel_type"], unique=False)
    _table("dns_investigations",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("domain", sa.String(length=255), nullable=False),
    sa.Column("created_at", sa.DateTime(), nullable=True),
    sa.Column("status", sa.String(length=50), nullable=True),
    sa.Column("result_json", sa.Text(), nullable=True),
    sa.Column("subdomain_count", sa.Integer(), nullable=True),
    sa.Column("resolved_count", sa.Integer(), nullable=True),
    sa.Column("zone_transfer_success", sa.Boolean(), nullable=True),
    sa.Column("has_spf", sa.Boolean(), nullable=True),
    sa.Column("has_dmarc", sa.Boolean(), nullable=True),
    sa.Column("error", sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_dns_domain_created", "dns_investigations", ["domain", "created_at"], unique=False)
    _index(op.f("ix_dns_investigations_domain"), "dns_investigations", ["domain"], unique=False)
    _table("investigation_targets",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("investigation_id", sa.Integer(), nullable=False),
    sa.Column("value", sa.String(length=512), nullable=False),
    sa.Column("target_type", sa.String(length=50), nullable=False),
    sa.Column("breaches", sa.Text(), nullable=True),
    sa.Column("darkweb_hits", sa.Text(), nullable=True),
    sa.Column("breach_count", sa.Integer(), nullable=True),
    sa.Column("darkweb_count", sa.Integer(), nullable=True),
    sa.Column("error", sa.Text(), nullable=True),
    sa.Column("checked_at", sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index(op.f("ix_investigation_targets_investigation_id"), "investigation_targets", ["investigation_id"], unique=False)
    _table("investigations",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("name", sa.String(length=255), nullable=False),
    sa.Column("created_at", sa.DateTime(), nullable=True),
    sa.Column("completed_at", sa.DateTime(), nullable=True),
    sa.Column("status", sa.String(length=50), nullable=True),
    sa.Column("target_count", sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _table("ip_investigations",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("ip", sa.String(length=64), nullable=False),
    sa.Column("created_at", sa.DateTime(), nullable=True),
    sa.Column("status", sa.String(length=50), nullable=True),
    sa.Column("abuseipdb_data", sa.Text(), nullable=True),
    sa.Column("virustotal_data", sa.Text(), nullable=True),
    sa.Column("abuse_score", sa.Integer(), nullable=True),
    sa.Column("vt_malicious", sa.Integer(), nullable=True),
    sa.Column("country", sa.String(length=10), nullable=True),
    sa.Column("isp", sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index(op.f("ix_ip_investigations_ip"), "ip_investigations", ["ip"], unique=False)
    _table("keyword_hits",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("session_id", sa.Integer(), nullable=True),
    sa.Column("url", sa.Text(), nullable=False),
    sa.Column("keyword", sa.String(length=500), nullable=False),
    sa.Column("category", sa.String(length=200), nullable=False),
    sa.Column("context", sa.Text(), nullable=True),
    sa.Column("position", sa.Integer(), nullable=True),
    sa.Column("depth", sa.Integer(), nullable=True),
    sa.Column("found_at", sa.DateTime(), nullable=True),
    sa.Column("alerted", sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_keyword_hits_category", "keyword_hits", ["category"], unique=False)
    _index("ix_keyword_hits_found_at", "keyword_hits", ["found_at"], unique=False)
    _index("ix_keyword_hits_keyword", "keyword_hits", ["keyword"], unique=False)
    _index("ix_keyword_hits_session", "keyword_hits", ["session_id"], unique=False)
    _table("paste_hits",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("paste_id", sa.String(length=200), nullable=False),
    sa.Column("url", sa.Text(), nullable=False),
    sa.Column("source", sa.String(length=50), nullable=False),
    sa.Column("matched_pattern", sa.String(length=100), nullable=False),
    sa.Column("matched_value", sa.String(length=500), nullable=True),
    sa.Column("context", sa.Text(), nullable=True),
    sa.Column("found_at", sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_paste_hits_found_at", "paste_hits", ["found_at"], unique=False)
    _index("ix_paste_hits_pattern", "paste_hits", ["matched_pattern"], unique=False)
    _index("ix_paste_hits_source", "paste_hits", ["source"], unique=False)
    _table("project_domains",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("project_id", sa.Integer(), nullable=False),
    sa.Column("domain", sa.String(length=500), nullable=False),
    sa.Column("priority", sa.Integer(), nullable=True),
    sa.Column("notes", sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_project_domains_project", "project_domains", ["project_id"], unique=False)
    _table("project_entities",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("project_id", sa.Integer(), nullable=False),
    sa.Column("entity_type", sa.String(length=50), nullable=False),
    sa.Column("value", sa.String(length=500), nullable=False),
    sa.Column("notes", sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_project_entities_project", "project_entities", ["project_id"], unique=False)
    _table("project_hits",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("project_id", sa.Integer(), nullable=False),
    sa.Column("hit_id", sa.Integer(), nullable=False),
    sa.Column("matched_on", sa.String(length=20), nullable=False),
    sa.Column("matched_value", sa.String(length=200), nullable=True),
    sa.Column("created_at", sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_project_hits_hit", "project_hits", ["hit_id"], unique=False)
    _index("ix_project_hits_project", "project_hits", ["project_id"], unique=False)
    _table("project_keywords",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("project_id", sa.Integer(), nullable=False),
    sa.Column("keyword", sa.String(length=200), nullable=False),
    sa.Column("category", sa.String(length=100), nullable=True),
    sa.Column("is_regex", sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_project_keywords_project", "project_keywords", ["project_id"], unique=False)
    _table("projects",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("name", sa.String(length=200), nullable=False),
    sa.Column("description", sa.Text(), nullable=True),
    sa.Column("status", sa.String(length=20), nullable=True),
    sa.Column("owner_id", sa.Integer(), nullable=False),
    sa.Column("created_at", sa.DateTime(), nullable=True),
    sa.Column("updated_at", sa.DateTime(), nullable=True),
    sa.Column("alert_threshold", sa.Integer(), nullable=True),
    sa.Column("color", sa.String(length=7), nullable=True),
    sa.Column("tags", sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_projects_owner", "projects", ["owner_id"], unique=False)
    _index("ix_projects_status", "projects", ["status"], unique=False)
    _table("quick_scan_findings",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("session_id", sa.Integer(), nullable=False),
    sa.Column("source_name", sa.String(length=200), nullable=False),
    sa.Column("url", sa.Text(), nullable=False),
    sa.Column("matched_variant", sa.String(length=512), nullable=False),
    sa.Column("context", sa.Text(), nullable=True),
    sa.Column("high_signal", sa.Boolean(), nullable=True),
    sa.Column("found_at", sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_quick_scan_findings_session", "quick_scan_findings", ["session_id"], unique=False)
    _index("ix_quick_scan_findings_source", "quick_scan_findings", ["source_name"], unique=False)
    _table("quick_scan_sessions",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("user_id", sa.Integer(), nullable=False),
    sa.Column("target_value", sa.String(length=512), nullable=False),
    sa.Column("target_type", sa.String(length=50), nullable=False),
    sa.Column("normalized_variants", sa.Text(), nullable=True),
    sa.Column("sources_used", sa.Text(), nullable=True),
    sa.Column("status", sa.String(length=50), nullable=True),
    sa.Column("started_at", sa.DateTime(), nullable=True),
    sa.Column("completed_at", sa.DateTime(), nullable=True),
    sa.Column("urls_visited", sa.Integer(), nullable=True),
    sa.Column("findings_count", sa.Integer(), nullable=True),
    sa.Column("error_message", sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_quick_scan_sessions_target", "quick_scan_sessions", ["target_value"], unique=False)
    _index("ix_quick_scan_sessions_user", "quick_scan_sessions", ["user_id"], unique=False)
    _table("seen_pastes",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("source", sa.String(length=50), nullable=False),
    sa.Column("paste_id", sa.String(length=200), nullable=False),
    sa.Column("url", sa.Text(), nullable=False),
    sa.Column("fetched_at", sa.DateTime(), nullable=True),
    sa.Column("had_hits", sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    _index("ix_seen_pastes_fetched", "seen_pastes", ["fetched_at"], unique=False)
    _index("ix_seen_pastes_source_id", "seen_pastes", ["source", "paste_id"], unique=True)
    _table("user_security",
    sa.Column("user_id", sa.Integer(), autoincrement=False, nullable=False),
    sa.Column("session_version", sa.Integer(), nullable=False),
    sa.Column("totp_last_step", sa.Integer(), nullable=True),
    sa.Column("pending_totp_secret", sa.String(length=64), nullable=True),
    sa.Column("pending_totp_created", sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint("user_id")
    )
    _table("users",
    sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
    sa.Column("username", sa.String(length=100), nullable=False),
    sa.Column("email", sa.String(length=255), nullable=True),
    sa.Column("password_hash", sa.String(length=255), nullable=True),
    sa.Column("totp_secret", sa.String(length=64), nullable=True),
    sa.Column("totp_enabled", sa.Boolean(), nullable=True),
    sa.Column("oauth_provider", sa.String(length=50), nullable=True),
    sa.Column("oauth_id", sa.String(length=255), nullable=True),
    sa.Column("is_admin", sa.Boolean(), nullable=True),
    sa.Column("must_change_password", sa.Boolean(), nullable=True),
    sa.Column("created_at", sa.DateTime(), nullable=True),
    sa.Column("last_login", sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint("id"),
    sa.UniqueConstraint("email"),
    sa.UniqueConstraint("username")
    )
    _index("ix_users_email", "users", ["email"], unique=False)
    _index("ix_users_oauth", "users", ["oauth_provider", "oauth_id"], unique=False)
    _index("ix_users_username", "users", ["username"], unique=False)


def downgrade() -> None:
    raise RuntimeError("0001 is the baseline; there is nothing older to go back to")
