"""
Storage layer — PostgreSQL (or SQLite in tests) via SQLAlchemy.
Stores users, crawl results, keyword hits, investigations and projects.

The schema is versioned with Alembic (see migrations/): a change to a model
here needs a new revision there.
"""

import json
import logging
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)

# Key used to stash the request-scoped session in flask.g.
# Defined here so storage_helper.py can import it without a circular dep.
_FLASK_SESSION_KEY = "storage_session"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=True)
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    must_change_password = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_login = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_users_username", "username"),
        Index("ix_users_email", "email"),
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class UserSecurity(Base):
    """Per-user security state. Its own table so that adding it needs no ALTER on ``users``."""

    __tablename__ = "user_security"

    user_id = Column(Integer, primary_key=True, autoincrement=False)
    # Stored in the session cookie; a cookie with another value is not a session.
    session_version = Column(Integer, nullable=False)
    # Last 30-second step a code was accepted for; a code works once.
    totp_last_step = Column(Integer, nullable=True)
    # Secret shown during enrolment, kept here until the first code confirms it.
    pending_totp_secret = Column(String(64), nullable=True)
    pending_totp_created = Column(DateTime, nullable=True)


class AuthEvent(Base):
    __tablename__ = "auth_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, default=_utcnow)
    event = Column(String(40), nullable=False)
    username = Column(String(100), nullable=True)
    user_id = Column(Integer, nullable=True)
    ip = Column(String(45), nullable=True)
    detail = Column(String(255), nullable=True)

    __table_args__ = (Index("ix_auth_events_ts", "ts"),)


class AuthThrottle(Base):
    """Failed sign-in attempts per key (``user:<name>``, ``ip:<address>``, ``totp:<user id>``)."""

    __tablename__ = "auth_throttle"

    key = Column(String(160), primary_key=True)
    failures = Column(Integer, nullable=False, default=0)
    window_start = Column(DateTime, nullable=False, default=_utcnow)
    locked_until = Column(DateTime, nullable=True)


class CrawlSession(Base):
    __tablename__ = "crawl_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    ended_at = Column(DateTime, nullable=True)
    seed_urls = Column(Text)  # JSON list
    pages_crawled = Column(Integer, default=0)
    hits_found = Column(Integer, default=0)
    status = Column(String(50), default="running")  # running | completed | stopped | failed | interrupted
    # Written by the process that runs the crawl; a running session whose
    # heartbeat has gone stale belongs to a process that died.
    heartbeat_at = Column(DateTime, nullable=True)
    owner = Column(String(100), nullable=True)  # host:pid of that process
    error = Column(Text, nullable=True)  # why it failed, in plain words


class CrawledPage(Base):
    __tablename__ = "crawled_pages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, nullable=True)
    url = Column(Text, nullable=False)
    crawled_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    status_code = Column(Integer)
    depth = Column(Integer, default=0)
    had_error = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_crawled_pages_url", "url"),
        Index("ix_crawled_pages_session", "session_id"),
    )


class KeywordHitRecord(Base):
    __tablename__ = "keyword_hits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, nullable=True)
    url = Column(Text, nullable=False)
    keyword = Column(String(500), nullable=False)
    category = Column(String(200), nullable=False)
    context = Column(Text)
    position = Column(Integer)
    depth = Column(Integer, default=0)
    found_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    alerted = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_keyword_hits_keyword", "keyword"),
        Index("ix_keyword_hits_category", "category"),
        Index("ix_keyword_hits_found_at", "found_at"),
        Index("ix_keyword_hits_session", "session_id"),
    )




class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="running")  # running | completed
    target_count = Column(Integer, default=0)


class InvestigationTarget(Base):
    __tablename__ = "investigation_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(Integer, nullable=False, index=True)
    value = Column(String(512), nullable=False)
    target_type = Column(String(50), nullable=False)  # email | name | keyword
    breaches = Column(Text, default="[]")   # JSON list of breach dicts
    darkweb_hits = Column(Text, default="[]")  # JSON list of hit dicts
    breach_count = Column(Integer, default=0)
    darkweb_count = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))



class IPInvestigation(Base):
    __tablename__ = "ip_investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    status = Column(String(50), default="running")
    abuseipdb_data = Column(Text, nullable=True)   # JSON
    virustotal_data = Column(Text, nullable=True)  # JSON
    abuse_score = Column(Integer, nullable=True)
    vt_malicious = Column(Integer, nullable=True)
    country = Column(String(10), nullable=True)
    isp = Column(String(255), nullable=True)


class DNSInvestigation(Base):
    __tablename__ = "dns_investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    status = Column(String(50), default="running")  # running | complete | error
    result_json = Column(Text, nullable=True)        # full result dict as JSON
    subdomain_count = Column(Integer, nullable=True)
    resolved_count = Column(Integer, nullable=True)
    zone_transfer_success = Column(Boolean, default=False)
    has_spf = Column(Boolean, default=False)
    has_dmarc = Column(Boolean, default=False)
    error = Column(Text, nullable=True)

    __table_args__ = (Index("ix_dns_domain_created", "domain", "created_at"),)



# ── Projects Models ─────────────────────────────────────────────────────────────

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), default="active")  # active | paused | archived
    owner_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    alert_threshold = Column(Integer, default=1)
    color = Column(String(7), default="#f85149")
    tags = Column(Text, default="[]")  # JSON array

    __table_args__ = (
        Index("ix_projects_owner", "owner_id"),
        Index("ix_projects_status", "status"),
    )


class ProjectKeyword(Base):
    __tablename__ = "project_keywords"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False)
    keyword = Column(String(200), nullable=False)
    category = Column(String(100), default="custom")
    is_regex = Column(Boolean, default=False)

    __table_args__ = (Index("ix_project_keywords_project", "project_id"),)


class ProjectDomain(Base):
    __tablename__ = "project_domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False)
    domain = Column(String(500), nullable=False)
    priority = Column(Integer, default=3)
    notes = Column(Text, nullable=True)

    __table_args__ = (Index("ix_project_domains_project", "project_id"),)


class ProjectEntity(Base):
    __tablename__ = "project_entities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False)
    entity_type = Column(String(50), nullable=False)
    value = Column(String(500), nullable=False)
    notes = Column(Text, nullable=True)

    __table_args__ = (Index("ix_project_entities_project", "project_id"),)


class ProjectHit(Base):
    __tablename__ = "project_hits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False)
    hit_id = Column(Integer, nullable=False)
    matched_on = Column(String(20), nullable=False)  # keyword|domain|entity
    matched_value = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        Index("ix_project_hits_project", "project_id"),
        Index("ix_project_hits_hit", "hit_id"),
    )



# ── Custom Intel Models ─────────────────────────────────────────────────────────

class CustomIntel(Base):
    __tablename__ = "custom_intel"

    id = Column(Integer, primary_key=True, autoincrement=True)
    intel_type = Column(String(50), nullable=False)   # "ransomware" or "threat-actor"
    slug = Column(String(200), nullable=False, unique=True)
    data = Column(Text, nullable=False)               # JSON blob
    created_by = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        Index("ix_custom_intel_type", "intel_type"),
        Index("ix_custom_intel_slug", "slug"),
    )


# ── Quick Scan Models ───────────────────────────────────────────────────────────

class QuickScanSession(Base):
    __tablename__ = "quick_scan_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False)
    target_value = Column(String(512), nullable=False)
    target_type = Column(String(50), nullable=False)  # email | domain | url | company_name
    normalized_variants = Column(Text, default="[]")   # JSON list of strings searched
    sources_used = Column(Text, default="[]")          # JSON list of source names
    status = Column(String(50), default="pending")     # pending|running|completed|failed|cancelled
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    completed_at = Column(DateTime, nullable=True)
    urls_visited = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_quick_scan_sessions_target", "target_value"),
        Index("ix_quick_scan_sessions_user", "user_id"),
    )


class QuickScanFinding(Base):
    __tablename__ = "quick_scan_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, nullable=False)
    source_name = Column(String(200), nullable=False)
    url = Column(Text, nullable=False)
    matched_variant = Column(String(512), nullable=False)
    context = Column(Text)
    high_signal = Column(Boolean, default=False)
    found_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        Index("ix_quick_scan_findings_session", "session_id"),
        Index("ix_quick_scan_findings_source", "source_name"),
    )


def normalise_database_url(url: str) -> str:
    """Name the PostgreSQL driver explicitly.

    SQLAlchemy 2.1 maps a bare ``postgresql://`` URL to psycopg 3. The image
    ships psycopg2, so a bare URL would fail at the first query.
    """
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg2://" + url[len(prefix):]
    return url


class Storage:
    def __init__(self, database_url: Optional[str] = None):
        database_url = database_url or os.getenv("DATABASE_URL", "")
        if not database_url:
            # No fallback: an empty database would reopen first-admin registration.
            raise RuntimeError(
                "DATABASE_URL is not set. Set it in .env (see .env.example), "
                "for example postgresql+psycopg2://scanner:<password>@postgres:5432/darkweb_scanner"
            )
        self.database_url = normalise_database_url(database_url)
        connect_args: dict = {}
        if self.database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        elif self.database_url.startswith("postgresql"):
            # Fail in seconds, not minutes, when PostgreSQL is not answering.
            connect_args["connect_timeout"] = 10

        self.engine = create_engine(
            self.database_url,
            connect_args=connect_args,
            echo=False,
            # Test a pooled connection before use, so a PostgreSQL restart costs
            # one reconnect and not a failed request.
            pool_pre_ping=True,
        )
        self._SessionFactory = sessionmaker(bind=self.engine)
        self._migrate()

    def _migrate(self):
        from . import migrations

        revision = migrations.migrate(self.engine)
        logger.info("Database schema ready (revision %s)", revision)

    @contextmanager
    def get_session(self):
        """Context manager that yields a SQLAlchemy Session.

        Inside a Flask request context: yields the request-scoped session
        stashed in flask.g (creating it on the first call).  The session is
        NOT closed on exit — close_db() teardown handles that at request end.

        Outside Flask (CLI / tests): yields a brand-new Session that is
        closed (and rolled back on error) when the ``with`` block exits,
        preserving the original per-call behaviour.
        """
        try:
            from flask import g, has_request_context
            if has_request_context():
                if not hasattr(g, _FLASK_SESSION_KEY):
                    setattr(g, _FLASK_SESSION_KEY, self._SessionFactory())
                yield getattr(g, _FLASK_SESSION_KEY)
                return
        except ImportError:
            pass
        # CLI / non-Flask path: own the session for the duration of the call
        session = self._SessionFactory()
        try:
            yield session
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # --- Crawl Sessions ---
    # A session with an owner (host:pid) belongs to a crawl. The process that
    # runs the crawl refreshes heartbeat_at; a running session whose heartbeat
    # has gone stale is ended as "interrupted" by whoever notices. A session
    # without an owner (telegram-scan) is written at its start and at its end
    # only, and is not what the dashboard calls the running crawl.

    # Serialises "is a crawl running? then start one" across processes (PostgreSQL).
    _CRAWL_LOCK_KEY = 7130001
    # A running session without an owner that is older than this did not end.
    _UNOWNED_SESSION_MAX_AGE = timedelta(hours=24)

    def create_crawl_session(self, seed_urls: list[str], owner: Optional[str] = None) -> int:
        import json

        with self.get_session() as session:
            record = CrawlSession(
                seed_urls=json.dumps(seed_urls),
                status="running",
                owner=owner,
                heartbeat_at=_utcnow() if owner else None,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.id

    def begin_crawl_session(
        self, seed_urls: list[str], owner: str, stale_after: float
    ) -> Optional[int]:
        """Start a crawl session for ``owner`` unless a crawl is running, in any process.

        Returns the new session id, or None when a crawl is running. Sessions
        whose heartbeat is older than ``stale_after`` seconds are ended first.
        Check and insert are one transaction; on PostgreSQL an advisory lock
        keeps two processes from both passing the check.
        """
        import json

        from sqlalchemy import text

        with self.get_session() as session:
            try:
                if self.engine.dialect.name == "postgresql":
                    session.execute(
                        text("SELECT pg_advisory_xact_lock(:key)"), {"key": self._CRAWL_LOCK_KEY}
                    )
                self._interrupt_stale(session, stale_after, None)
                running = (
                    session.query(CrawlSession.id)
                    .filter(CrawlSession.status == "running", CrawlSession.owner.isnot(None))
                    .first()
                )
                if running is not None:
                    session.commit()
                    return None
                record = CrawlSession(
                    seed_urls=json.dumps(seed_urls),
                    status="running",
                    owner=owner,
                    heartbeat_at=_utcnow(),
                )
                session.add(record)
                session.commit()
                session.refresh(record)
                return record.id
            except Exception:
                session.rollback()
                raise

    def heartbeat_crawl_session(
        self,
        session_id: int,
        pages_crawled: Optional[int] = None,
        hits_found: Optional[int] = None,
    ) -> bool:
        """Refresh the heartbeat (and the counters) of a running session.

        False when the session is no longer running: someone ended it, and
        the crawl that called this should stop.
        """
        values: dict = {"heartbeat_at": _utcnow()}
        if pages_crawled is not None:
            values["pages_crawled"] = pages_crawled
        if hits_found is not None:
            values["hits_found"] = hits_found
        with self.get_session() as session:
            updated = (
                session.query(CrawlSession)
                .filter(CrawlSession.id == session_id, CrawlSession.status == "running")
                .update(values, synchronize_session=False)
            )
            session.commit()
            return updated == 1

    def _interrupt_stale(self, session, stale_after: float, idle_owner: Optional[str]) -> int:
        now = _utcnow()
        cutoff = now - timedelta(seconds=stale_after)
        unowned_cutoff = now - self._UNOWNED_SESSION_MAX_AGE
        changed = 0
        rows = session.query(CrawlSession).filter(CrawlSession.status == "running").all()
        for row in rows:
            still = [CrawlSession.id == row.id, CrawlSession.status == "running"]
            if row.owner is None:
                if row.started_at is not None and row.started_at >= unowned_cutoff:
                    continue
                reason = "No heartbeat was recorded for this session and it did not end within 24 hours."
            elif idle_owner is not None and row.owner == idle_owner:
                reason = "The process that ran this crawl was restarted before the crawl ended."
            else:
                beat = row.heartbeat_at or row.started_at
                if beat is not None and beat >= cutoff:
                    continue
                since = beat.strftime("%Y-%m-%d %H:%M:%S UTC") if beat else "its start"
                reason = (
                    f"No heartbeat from the crawl process ({row.owner}) since {since}: "
                    "it was stopped or it crashed."
                )
                # Not when a heartbeat arrived in the meantime.
                still.append((CrawlSession.heartbeat_at.is_(None)) | (CrawlSession.heartbeat_at < cutoff))
            changed += (
                session.query(CrawlSession)
                .filter(*still)
                .update(
                    {"status": "interrupted", "ended_at": now, "error": reason},
                    synchronize_session=False,
                )
            )
        return changed

    def interrupt_stale_crawl_sessions(
        self, stale_after: float, idle_owner: Optional[str] = None
    ) -> int:
        """End, as "interrupted", the running sessions whose process is gone. Returns how many.

        A session is gone when its heartbeat is older than ``stale_after``
        seconds, or when its owner is ``idle_owner``: the caller's own name,
        passed only while the caller runs no crawl (a restarted process can
        get the host:pid of the one before it).
        """
        with self.get_session() as session:
            try:
                changed = self._interrupt_stale(session, stale_after, idle_owner)
                session.commit()
                return changed
            except Exception:
                session.rollback()
                raise

    def update_crawl_session(
        self,
        session_id: int,
        pages_crawled: int,
        hits_found: int,
        status: str = "completed",
        error: Optional[str] = None,
    ):
        """Write the end of a session: completed, stopped, failed or interrupted."""
        with self.get_session() as session:
            record = session.get(CrawlSession, session_id)
            if record:
                record.pages_crawled = pages_crawled
                record.hits_found = hits_found
                # A crawl that was already ended as interrupted (its heartbeat
                # went stale) keeps that status and its reason.
                if not (record.owner and record.status == "interrupted"):
                    record.ended_at = datetime.now(timezone.utc).replace(tzinfo=None)
                    record.status = status
                    record.error = error
                session.commit()

    def get_last_finished_session(self) -> Optional[dict]:
        """The most recent session that is not running, or None."""
        with self.get_session() as session:
            r = (
                session.query(CrawlSession)
                .filter(CrawlSession.status != "running")
                .order_by(CrawlSession.id.desc())
                .first()
            )
            if r is None:
                return None
            return {
                "id": r.id,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "ended_at": r.ended_at.isoformat() if r.ended_at else None,
                "error": r.error,
            }

    # --- Pages ---

    def save_page(
        self,
        url: str,
        status_code: int,
        depth: int,
        session_id: Optional[int] = None,
        error: Optional[str] = None,
    ):
        with self.get_session() as session:
            record = CrawledPage(
                session_id=session_id,
                url=url,
                status_code=status_code,
                depth=depth,
                had_error=bool(error),
                error_message=error,
            )
            session.add(record)
            session.commit()

    # --- Keyword Hits ---

    def save_hit(
        self,
        url: str,
        keyword: str,
        category: str,
        context: str,
        position: int,
        depth: int,
        session_id: Optional[int] = None,
    ) -> int:
        with self.get_session() as session:
            record = KeywordHitRecord(
                session_id=session_id,
                url=url,
                keyword=keyword,
                category=category,
                context=context,
                position=position,
                depth=depth,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.id

    def mark_alerted(self, hit_id: int):
        with self.get_session() as session:
            record = session.get(KeywordHitRecord, hit_id)
            if record:
                record.alerted = True
                session.commit()

    def get_recent_hits(self, limit: int = 100) -> list[KeywordHitRecord]:
        with self.get_session() as session:
            return (
                session.query(KeywordHitRecord)
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )

    def get_hits_by_keyword(self, keyword: str, limit: int = 50) -> list[KeywordHitRecord]:
        with self.get_session() as session:
            return (
                session.query(KeywordHitRecord)
                .filter(KeywordHitRecord.keyword == keyword)
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )

    def get_hits_by_keywords(
        self, keywords: list[str], limit_per_keyword: int = 5
    ) -> dict[str, list[KeywordHitRecord]]:
        """Fetch up to `limit_per_keyword` most-recent hits for every keyword in
        `keywords` using a single SQL query. Returns a dict keyed by keyword."""
        if not keywords:
            return {}
        with self.get_session() as session:
            rows = (
                session.query(KeywordHitRecord)
                .filter(KeywordHitRecord.keyword.in_(keywords))
                .order_by(KeywordHitRecord.keyword, KeywordHitRecord.found_at.desc())
                .all()
            )
        result: dict[str, list[KeywordHitRecord]] = {}
        for hit in rows:
            bucket = result.setdefault(hit.keyword, [])
            if len(bucket) < limit_per_keyword:
                bucket.append(hit)
        return result

    def get_last_hit_dates_bulk(self, keywords: list[str]) -> dict[str, str]:
        """Return the ISO timestamp of the most-recent hit for each keyword that
        has at least one hit. Keywords with no hits are absent from the result.
        Uses a single GROUP BY query regardless of keyword count."""
        if not keywords:
            return {}
        with self.get_session() as session:
            rows = (
                session.query(
                    KeywordHitRecord.keyword,
                    func.max(KeywordHitRecord.found_at).label("last_hit"),
                )
                .filter(KeywordHitRecord.keyword.in_(keywords))
                .group_by(KeywordHitRecord.keyword)
                .all()
            )
        return {kw: ts.isoformat() for kw, ts in rows if ts}

    def get_stats(self) -> dict:
        with self.get_session() as session:
            total_hits = session.query(func.count(KeywordHitRecord.id)).scalar()
            total_pages = session.query(func.count(CrawledPage.id)).scalar()
            total_sessions = session.query(func.count(CrawlSession.id)).scalar()
            top_keywords = (
                session.query(
                    KeywordHitRecord.keyword, func.count(KeywordHitRecord.id).label("count")
                )
                .group_by(KeywordHitRecord.keyword)
                .order_by(func.count(KeywordHitRecord.id).desc())
                .limit(10)
                .all()
            )
            return {
                "total_hits": total_hits or 0,
                "total_pages": total_pages or 0,
                "total_sessions": total_sessions or 0,
                "top_keywords": [{"keyword": k, "count": c} for k, c in top_keywords],
            }


    # --- Users ---

    def get_user_by_id(self, user_id: int):
        with self.get_session() as session:
            return session.get(User, user_id)

    def get_user_by_username(self, username: str):
        with self.get_session() as session:
            return session.query(User).filter(User.username == username).first()

    def get_user_by_email(self, email: str):
        with self.get_session() as session:
            return session.query(User).filter(User.email == email).first()

    def create_user(self, username: str, password_hash: Optional[str] = None,
                    email: Optional[str] = None, is_admin: bool = False,
                    must_change_password: bool = False):
        with self.get_session() as session:
            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                is_admin=is_admin,
                must_change_password=must_change_password,
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            return user.id

    def set_must_change_password(self, user_id: int, value: bool = False):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.must_change_password = value
                session.commit()

    def update_user_login(self, user_id: int):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.last_login = _utcnow()
                session.commit()

    def enable_totp(self, user_id: int, secret: str, step: Optional[int] = None):
        """Turn the second factor on. ``step`` is the time step of the code that
        confirmed the secret; recording it stops that code being used again."""
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.totp_secret = secret
                user.totp_enabled = True
                sec = self._security_row(session, user_id)
                sec.totp_last_step = step
                sec.pending_totp_secret = None
                sec.pending_totp_created = None
                session.commit()

    def disable_totp(self, user_id: int):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.totp_secret = None
                user.totp_enabled = False
                sec = self._security_row(session, user_id)
                sec.totp_last_step = None
                sec.pending_totp_secret = None
                sec.pending_totp_created = None
                session.commit()

    def count_users(self) -> int:
        with self.get_session() as session:
            return session.query(func.count(User.id)).scalar() or 0

    def count_admins(self) -> int:
        with self.get_session() as session:
            return session.query(func.count(User.id)).filter(User.is_admin.is_(True)).scalar() or 0

    def get_unalerted_hits(self) -> list[KeywordHitRecord]:
        with self.get_session() as session:
            return session.query(KeywordHitRecord).filter(KeywordHitRecord.alerted.is_(False)).all()

    def list_users(self):
        with self.get_session() as session:
            return session.query(User).order_by(User.created_at).all()

    def delete_user(self, user_id: int):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                session.delete(user)
            session.query(UserSecurity).filter(UserSecurity.user_id == user_id).delete()
            session.query(AuthThrottle).filter(AuthThrottle.key == f"totp:{user_id}").delete()
            session.commit()

    def update_user_password(self, user_id: int, password_hash: str):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.password_hash = password_hash
                session.commit()

    # --- Sessions, second factor, throttling, auth events ---

    @staticmethod
    def _security_row(session, user_id: int) -> "UserSecurity":
        sec = session.get(UserSecurity, user_id)
        if sec is None:
            # Random start: a cookie issued to an earlier user with the same id cannot match.
            sec = UserSecurity(user_id=user_id, session_version=secrets.randbelow(2**30) + 1)
            session.add(sec)
            session.flush()
        return sec

    def get_session_version(self, user_id: int) -> Optional[int]:
        """The version a session cookie must carry, or None when the user has never signed in."""
        with self.get_session() as session:
            sec = session.get(UserSecurity, user_id)
            return sec.session_version if sec is not None else None

    def ensure_session_version(self, user_id: int) -> int:
        with self.get_session() as session:
            sec = self._security_row(session, user_id)
            session.commit()
            return sec.session_version

    def bump_session_version(self, user_id: int) -> int:
        """End every session of the user. Returns the new version."""
        with self.get_session() as session:
            sec = self._security_row(session, user_id)
            sec.session_version = (sec.session_version % (2**30)) + 1
            session.commit()
            return sec.session_version

    def accept_totp_step(self, user_id: int, step: int) -> bool:
        """Record ``step`` as used. False when this or a later step was used before (replay)."""
        with self.get_session() as session:
            self._security_row(session, user_id)
            changed = (
                session.query(UserSecurity)
                .filter(
                    UserSecurity.user_id == user_id,
                    (UserSecurity.totp_last_step.is_(None)) | (UserSecurity.totp_last_step < step),
                )
                .update({UserSecurity.totp_last_step: step}, synchronize_session=False)
            )
            session.commit()
            return changed == 1

    def set_pending_totp_secret(self, user_id: int, secret: Optional[str]):
        with self.get_session() as session:
            sec = self._security_row(session, user_id)
            sec.pending_totp_secret = secret
            sec.pending_totp_created = _utcnow() if secret else None
            session.commit()

    def get_pending_totp_secret(self, user_id: int, max_age_seconds: int) -> Optional[str]:
        with self.get_session() as session:
            sec = session.get(UserSecurity, user_id)
            if sec is None or not sec.pending_totp_secret or sec.pending_totp_created is None:
                return None
            if _utcnow() - sec.pending_totp_created > timedelta(seconds=max_age_seconds):
                return None
            return sec.pending_totp_secret

    def throttle_locked_seconds(self, key: str) -> int:
        with self.get_session() as session:
            row = session.get(AuthThrottle, key)
            if row is None or row.locked_until is None:
                return 0
            return max(0, int((row.locked_until - _utcnow()).total_seconds()))

    def throttle_fail(self, key: str, limit: int, window_seconds: int, lock_seconds: int) -> bool:
        """Count one failure for ``key``. True when the key is locked after it."""
        now = _utcnow()
        with self.get_session() as session:
            row = session.query(AuthThrottle).filter(AuthThrottle.key == key).with_for_update().first()
            if row is None:
                row = AuthThrottle(key=key, failures=0, window_start=now)
                session.add(row)
            if now - row.window_start > timedelta(seconds=window_seconds):
                row.failures = 0
                row.window_start = now
            row.failures += 1
            locked = row.failures >= limit
            if locked:
                row.locked_until = now + timedelta(seconds=lock_seconds)
                row.failures = 0
                row.window_start = now
            session.commit()
            return locked

    def throttle_locks(self) -> list[dict]:
        """The sign-in locks in force now: [{"key": ..., "seconds": ...}]."""
        now = _utcnow()
        with self.get_session() as session:
            rows = session.query(AuthThrottle).filter(AuthThrottle.locked_until > now).order_by(AuthThrottle.key).all()
            return [{"key": r.key, "seconds": int((r.locked_until - now).total_seconds())} for r in rows]

    def throttle_clear(self, key: str):
        with self.get_session() as session:
            session.query(AuthThrottle).filter(AuthThrottle.key == key).delete()
            session.commit()

    def add_auth_event(self, event: str, username: str = "", user_id: Optional[int] = None,
                       ip: str = "", detail: str = ""):
        with self.get_session() as session:
            session.add(AuthEvent(
                event=event[:40], username=(username or None), user_id=user_id,
                ip=(ip or None), detail=(detail or None),
            ))
            session.commit()

    def list_auth_events(self, limit: int = 200) -> list[dict]:
        with self.get_session() as session:
            rows = session.query(AuthEvent).order_by(AuthEvent.id.desc()).limit(limit).all()
            return [
                {
                    "ts": r.ts.isoformat() + "Z", "event": r.event, "username": r.username,
                    "user_id": r.user_id, "ip": r.ip, "detail": r.detail,
                }
                for r in rows
            ]

    def prune_auth_state(self, event_days: int = 365):
        """Drop auth events older than ``event_days`` and throttle rows idle for a day."""
        now = _utcnow()
        with self.get_session() as session:
            session.query(AuthEvent).filter(AuthEvent.ts < now - timedelta(days=event_days)).delete()
            session.query(AuthThrottle).filter(
                AuthThrottle.window_start < now - timedelta(days=1),
                (AuthThrottle.locked_until.is_(None)) | (AuthThrottle.locked_until < now),
            ).delete(synchronize_session=False)
            session.commit()

    def count_session_hits(self, session_id: int) -> int:
        with self.get_session() as session:
            return (
                session.query(func.count(KeywordHitRecord.id))
                .filter(KeywordHitRecord.session_id == session_id)
                .scalar() or 0
            )

    def count_session_pages(self, session_id: int) -> int:
        with self.get_session() as session:
            return (
                session.query(func.count(CrawledPage.id))
                .filter(CrawledPage.session_id == session_id)
                .scalar() or 0
            )

    def get_sessions(self, limit: int = 20) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(CrawlSession)
                .order_by(CrawlSession.started_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "ended_at": r.ended_at.isoformat() if r.ended_at else None,
                    "seed_urls": r.seed_urls or "[]",
                    "pages_crawled": r.pages_crawled or 0,
                    "hits_found": r.hits_found or 0,
                    "status": r.status or "completed",
                }
                for r in rows
            ]

    def get_hits_by_session(self, session_id: int, limit: int = 200):
        with self.get_session() as session:
            return (
                session.query(KeywordHitRecord)
                .filter(KeywordHitRecord.session_id == session_id)
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )

    def get_hits_for_report(self, limit: int = 500):
        with self.get_session() as session:
            return (
                session.query(KeywordHitRecord)
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )
    # ── Investigations ──────────────────────────────────────────────────────────

    def create_investigation(self, name: str, targets: list) -> int:
        with self.get_session() as session:
            record = Investigation(
                name=name,
                status="running",
                target_count=len(targets),
            )
            session.add(record)
            session.commit()
            return record.id

    def save_investigation_target(
        self,
        investigation_id: int,
        value: str,
        target_type: str,
        breaches: list,
        darkweb_hits: list,
        error: Optional[str] = None,
    ):
        with self.get_session() as session:
            record = InvestigationTarget(
                investigation_id=investigation_id,
                value=value,
                target_type=target_type,
                breaches=json.dumps(breaches),
                darkweb_hits=json.dumps(darkweb_hits),
                breach_count=len(breaches),
                darkweb_count=len(darkweb_hits),
                error=error,
            )
            session.add(record)
            session.commit()

    def complete_investigation(self, investigation_id: int):
        with self.get_session() as session:
            record = session.get(Investigation, investigation_id)
            if record:
                record.status = "completed"
                record.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                session.commit()

    def fail_investigation(self, investigation_id: int):
        """An investigation that stopped before it finished."""
        with self.get_session() as session:
            record = session.get(Investigation, investigation_id)
            if record:
                record.status = "failed"
                record.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                session.commit()

    def fail_running_investigations(self) -> int:
        """Mark every investigation still "running" as failed. Returns how many.

        For process start: the jobs live in the dashboard process, so none of
        them can still be running then.
        """
        with self.get_session() as session:
            rows = session.query(Investigation).filter(Investigation.status == "running").all()
            for record in rows:
                record.status = "failed"
                record.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            session.commit()
            return len(rows)

    def get_investigations(self, limit: int = 50) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(Investigation)
                .order_by(Investigation.created_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "name": r.name,
                    "status": r.status,
                    "target_count": r.target_count,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                }
                for r in rows
            ]

    def get_investigation_targets(self, investigation_id: int) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(InvestigationTarget)
                .filter(InvestigationTarget.investigation_id == investigation_id)
                .order_by(InvestigationTarget.id.asc())
                .all()
            )
            results = []
            for r in rows:
                try:
                    breaches = json.loads(r.breaches or "[]")
                except Exception:
                    breaches = []
                try:
                    darkweb_hits = json.loads(r.darkweb_hits or "[]")
                except Exception:
                    darkweb_hits = []
                results.append({
                    "id": r.id,
                    "value": r.value,
                    "target_type": r.target_type,
                    "breaches": breaches,
                    "darkweb_hits": darkweb_hits,
                    "breach_count": r.breach_count or 0,
                    "darkweb_count": r.darkweb_count or 0,
                    "error": r.error,
                    "checked_at": r.checked_at.isoformat() if r.checked_at else None,
                })
            return results

    def delete_investigation(self, investigation_id: int):
        with self.get_session() as session:
            session.query(InvestigationTarget).filter(
                InvestigationTarget.investigation_id == investigation_id
            ).delete()
            record = session.get(Investigation, investigation_id)
            if record:
                session.delete(record)
            session.commit()

    def search_hits(self, query: str, limit: int = 50) -> list[dict]:
        """Search existing dark web keyword hits for a given string."""
        with self.get_session() as session:
            rows = (
                session.query(KeywordHitRecord)
                .filter(KeywordHitRecord.context.ilike(f"%{query}%"))
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "url": r.url,
                    "keyword": r.keyword,
                    "category": r.category,
                    "context": r.context,
                    "found_at": r.found_at.isoformat() if r.found_at else None,
                }
                for r in rows
            ]


    # ── IP Investigations ───────────────────────────────────────────────────────

    def save_ip_investigation(self, ip: str, abuseipdb_data: dict, virustotal_data: dict) -> int:
        abuse_score = None
        vt_malicious = None
        country = None
        isp = None
        if abuseipdb_data and not abuseipdb_data.get("error"):
            abuse_score = abuseipdb_data.get("abuse_confidence_score")
            country = abuseipdb_data.get("country_code")
            isp = abuseipdb_data.get("isp")
        if virustotal_data and not virustotal_data.get("error"):
            vt_malicious = virustotal_data.get("analysis_stats", {}).get("malicious", 0)
            if not country:
                country = virustotal_data.get("country")
            if not isp:
                isp = virustotal_data.get("as_owner")
        with self.get_session() as session:
            record = IPInvestigation(
                ip=ip,
                status="completed",
                abuseipdb_data=json.dumps(abuseipdb_data),
                virustotal_data=json.dumps(virustotal_data),
                abuse_score=abuse_score,
                vt_malicious=vt_malicious,
                country=country,
                isp=isp,
            )
            session.add(record)
            session.commit()
            return record.id

    def get_ip_investigations(self, limit: int = 50) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(IPInvestigation)
                .order_by(IPInvestigation.created_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "ip": r.ip,
                    "status": r.status,
                    "abuse_score": r.abuse_score,
                    "vt_malicious": r.vt_malicious,
                    "country": r.country,
                    "isp": r.isp,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ]

    def get_ip_investigation(self, inv_id: int) -> Optional[dict]:
        with self.get_session() as session:
            r = session.get(IPInvestigation, inv_id)
            if not r:
                return None
            try:
                abuse = json.loads(r.abuseipdb_data or "{}")
            except Exception:
                abuse = {}
            try:
                vt = json.loads(r.virustotal_data or "{}")
            except Exception:
                vt = {}
            return {
                "id": r.id,
                "ip": r.ip,
                "status": r.status,
                "abuse_score": r.abuse_score,
                "vt_malicious": r.vt_malicious,
                "country": r.country,
                "isp": r.isp,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "abuseipdb": abuse,
                "virustotal": vt,
            }

    def delete_ip_investigation(self, inv_id: int):
        with self.get_session() as session:
            r = session.get(IPInvestigation, inv_id)
            if r:
                session.delete(r)
                session.commit()

    def update_ip_investigation(self, inv_id: int, virustotal_fields: Optional[dict] = None,
                                status: Optional[str] = None) -> bool:
        """Merge fields into a lookup's saved VirusTotal data and/or set its status.

        Used for the VirusTotal data that arrives after the lookup was saved.
        False when the lookup has been deleted in the meantime.
        """
        with self.get_session() as session:
            r = session.get(IPInvestigation, inv_id)
            if not r:
                return False
            if virustotal_fields:
                try:
                    vt = json.loads(r.virustotal_data or "{}")
                except Exception:
                    vt = {}
                vt.update(virustotal_fields)
                r.virustotal_data = json.dumps(vt)
            if status:
                r.status = status
            session.commit()
            return True

    def close_running_ip_investigations(self, note: str) -> int:
        """Lookups still waiting for their extra VirusTotal data: mark it skipped. Returns how many.

        For process start: the queue that fetches the data lives in the
        dashboard process and is empty then.
        """
        with self.get_session() as session:
            rows = session.query(IPInvestigation).filter(IPInvestigation.status == "running").all()
            for r in rows:
                try:
                    vt = json.loads(r.virustotal_data or "{}")
                except Exception:
                    vt = {}
                vt.update({"extras_status": "skipped", "extras_note": note})
                r.virustotal_data = json.dumps(vt)
                r.status = "completed"
            session.commit()
            return len(rows)


    def get_active_session(self):
        """The running crawl (a running session that has an owner), in whichever process, or None."""
        with self.get_session() as session:
            r = (
                session.query(CrawlSession)
                .filter(CrawlSession.status == "running", CrawlSession.owner.isnot(None))
                .order_by(CrawlSession.started_at.desc())
                .first()
            )
            if r is None:
                return None
            return {
                "id": r.id,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "pages_crawled": r.pages_crawled or 0,
                "hits_found": r.hits_found or 0,
                "status": r.status,
                "owner": r.owner,
                "heartbeat_at": r.heartbeat_at.isoformat() if r.heartbeat_at else None,
            }

    # ── DNS Investigations ──────────────────────────────────────────────────

    def create_dns_investigation(self, domain: str) -> int:
        with self.get_session() as session:
            r = DNSInvestigation(domain=domain, status="running")
            session.add(r)
            session.commit()
            session.refresh(r)
            return r.id

    def complete_dns_investigation(self, inv_id: int, result: dict):
        with self.get_session() as session:
            r = session.get(DNSInvestigation, inv_id)
            if not r:
                return
            email_sec = result.get("email_security", {})
            zt = result.get("zone_transfer", {})
            zt_success = any(v.get("success") for v in zt.values() if isinstance(v, dict))
            r.status = "complete"
            r.result_json = json.dumps(result)
            r.subdomain_count = result.get("subdomain_count", 0)
            r.resolved_count = result.get("resolved_count", 0)
            r.zone_transfer_success = zt_success
            r.has_spf = email_sec.get("spf_valid", False)
            r.has_dmarc = email_sec.get("dmarc_valid", False)
            session.commit()

    def fail_dns_investigation(self, inv_id: int, error: str):
        with self.get_session() as session:
            r = session.get(DNSInvestigation, inv_id)
            if r:
                r.status = "error"
                r.error = error[:500]
                session.commit()

    def fail_running_dns_investigations(self, error: str) -> int:
        """Mark every recon still "running" as failed with ``error``. Returns how many.

        For process start: a recon runs on a thread of the dashboard process,
        so one that was running when the process stopped will never finish.
        """
        with self.get_session() as session:
            rows = session.query(DNSInvestigation).filter(DNSInvestigation.status == "running").all()
            for r in rows:
                r.status = "error"
                r.error = error[:500]
            session.commit()
            return len(rows)

    def get_dns_investigations(self, limit: int = 50) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(DNSInvestigation)
                .order_by(DNSInvestigation.created_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "domain": r.domain,
                    "status": r.status,
                    "subdomain_count": r.subdomain_count,
                    "resolved_count": r.resolved_count,
                    "zone_transfer_success": r.zone_transfer_success,
                    "has_spf": r.has_spf,
                    "has_dmarc": r.has_dmarc,
                    "error": r.error,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ]

    def get_dns_investigation(self, inv_id: int) -> Optional[dict]:
        with self.get_session() as session:
            r = session.get(DNSInvestigation, inv_id)
            if not r:
                return None
            try:
                result = json.loads(r.result_json or "{}")
            except Exception:
                result = {}
            return {
                "id": r.id,
                "domain": r.domain,
                "status": r.status,
                "subdomain_count": r.subdomain_count,
                "resolved_count": r.resolved_count,
                "zone_transfer_success": r.zone_transfer_success,
                "has_spf": r.has_spf,
                "has_dmarc": r.has_dmarc,
                "error": r.error,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "result": result,
            }


    # ── Projects ──────────────────────────────────────────────────────────────────

    def create_project(self, name: str, owner_id: int, description: str = None,
                       color: str = "#f85149", tags: list = None, alert_threshold: int = 1) -> int:
        import json
        with self.get_session() as session:
            p = Project(
                name=name, description=description, owner_id=owner_id,
                color=color, tags=json.dumps(tags or []), alert_threshold=alert_threshold,
            )
            session.add(p)
            session.commit()
            session.refresh(p)
            return p.id

    def _project_to_dict(self, p) -> dict:
        import json
        return {
            "id": p.id, "name": p.name, "description": p.description,
            "status": p.status, "owner_id": p.owner_id,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
            "alert_threshold": p.alert_threshold, "color": p.color,
            "tags": json.loads(p.tags or "[]"),
        }

    def get_project(self, project_id: int) -> dict | None:
        with self.get_session() as session:
            p = session.get(Project, project_id)
            if not p:
                return None
            d = self._project_to_dict(p)
            d["keywords"] = self.get_project_keywords(project_id)
            d["domains"] = self.get_project_domains(project_id)
            d["entities"] = self.get_project_entities(project_id)
            d["hit_count"] = session.query(func.count(ProjectHit.id)).filter(
                ProjectHit.project_id == project_id).scalar() or 0
            return d

    def list_projects(self, owner_id: int = None) -> list[dict]:
        with self.get_session() as session:
            q = session.query(Project)
            if owner_id is not None:
                q = q.filter(Project.owner_id == owner_id)
            projects = q.order_by(Project.created_at.desc()).all()
            result = []
            for p in projects:
                d = self._project_to_dict(p)
                d["hit_count"] = session.query(func.count(ProjectHit.id)).filter(
                    ProjectHit.project_id == p.id).scalar() or 0
                result.append(d)
            return result

    def update_project(self, project_id: int, **kwargs) -> bool:
        import json
        with self.get_session() as session:
            p = session.get(Project, project_id)
            if not p:
                return False
            for k, v in kwargs.items():
                if k == "tags":
                    v = json.dumps(v)
                if hasattr(p, k):
                    setattr(p, k, v)
            p.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            session.commit()
            return True

    def delete_project(self, project_id: int):
        with self.get_session() as session:
            session.query(ProjectKeyword).filter(ProjectKeyword.project_id == project_id).delete()
            session.query(ProjectDomain).filter(ProjectDomain.project_id == project_id).delete()
            session.query(ProjectEntity).filter(ProjectEntity.project_id == project_id).delete()
            session.query(ProjectHit).filter(ProjectHit.project_id == project_id).delete()
            p = session.get(Project, project_id)
            if p:
                session.delete(p)
            session.commit()

    def get_active_projects_with_config(self) -> list:
        with self.get_session() as session:
            projects = session.query(Project).filter(Project.status == "active").all()
            result = []
            for p in projects:
                d = self._project_to_dict(p)
                d["keywords"] = session.query(ProjectKeyword).filter(
                    ProjectKeyword.project_id == p.id).all()
                d["domains"] = session.query(ProjectDomain).filter(
                    ProjectDomain.project_id == p.id).all()
                d["entities"] = session.query(ProjectEntity).filter(
                    ProjectEntity.project_id == p.id).all()
                result.append(d)
            return result

    def add_project_keyword(self, project_id: int, keyword: str,
                            category: str = "custom", is_regex: bool = False) -> int:
        with self.get_session() as session:
            kw = ProjectKeyword(project_id=project_id, keyword=keyword,
                                category=category, is_regex=is_regex)
            session.add(kw)
            session.commit()
            session.refresh(kw)
            return kw.id

    def get_project_keywords(self, project_id: int) -> list[dict]:
        with self.get_session() as session:
            kws = session.query(ProjectKeyword).filter(
                ProjectKeyword.project_id == project_id).all()
            return [{"id": k.id, "keyword": k.keyword, "category": k.category,
                     "is_regex": k.is_regex} for k in kws]

    def delete_project_keyword(self, project_id: int, keyword_id: int) -> bool:
        """Delete the row only when it belongs to ``project_id``. True when a row was removed."""
        with self.get_session() as session:
            removed = (
                session.query(ProjectKeyword)
                .filter(ProjectKeyword.id == keyword_id, ProjectKeyword.project_id == project_id)
                .delete(synchronize_session=False)
            )
            session.commit()
            return removed == 1

    def add_project_domain(self, project_id: int, domain: str,
                           priority: int = 3, notes: str = None) -> int:
        with self.get_session() as session:
            d = ProjectDomain(project_id=project_id, domain=domain,
                              priority=priority, notes=notes)
            session.add(d)
            session.commit()
            session.refresh(d)
            return d.id

    def get_project_domains(self, project_id: int) -> list[dict]:
        with self.get_session() as session:
            domains = session.query(ProjectDomain).filter(
                ProjectDomain.project_id == project_id).all()
            return [{"id": d.id, "domain": d.domain, "priority": d.priority,
                     "notes": d.notes} for d in domains]

    def delete_project_domain(self, project_id: int, domain_id: int) -> bool:
        """Delete the row only when it belongs to ``project_id``. True when a row was removed."""
        with self.get_session() as session:
            removed = (
                session.query(ProjectDomain)
                .filter(ProjectDomain.id == domain_id, ProjectDomain.project_id == project_id)
                .delete(synchronize_session=False)
            )
            session.commit()
            return removed == 1

    def add_project_entity(self, project_id: int, entity_type: str,
                           value: str, notes: str = None) -> int:
        with self.get_session() as session:
            e = ProjectEntity(project_id=project_id, entity_type=entity_type,
                              value=value, notes=notes)
            session.add(e)
            session.commit()
            session.refresh(e)
            return e.id

    def get_project_entities(self, project_id: int) -> list[dict]:
        with self.get_session() as session:
            entities = session.query(ProjectEntity).filter(
                ProjectEntity.project_id == project_id).all()
            return [{"id": e.id, "entity_type": e.entity_type, "value": e.value,
                     "notes": e.notes} for e in entities]

    def delete_project_entity(self, project_id: int, entity_id: int) -> bool:
        """Delete the row only when it belongs to ``project_id``. True when a row was removed."""
        with self.get_session() as session:
            removed = (
                session.query(ProjectEntity)
                .filter(ProjectEntity.id == entity_id, ProjectEntity.project_id == project_id)
                .delete(synchronize_session=False)
            )
            session.commit()
            return removed == 1

    def create_project_hit(self, project_id: int, hit_id: int,
                           matched_on: str, matched_value: str = None):
        with self.get_session() as session:
            existing = session.query(ProjectHit).filter(
                ProjectHit.project_id == project_id,
                ProjectHit.hit_id == hit_id,
            ).first()
            if not existing:
                ph = ProjectHit(project_id=project_id, hit_id=hit_id,
                                matched_on=matched_on, matched_value=matched_value)
                session.add(ph)
                session.commit()

    def get_project_hits(self, project_id: int, limit: int = 100) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(ProjectHit, KeywordHitRecord)
                .join(KeywordHitRecord, ProjectHit.hit_id == KeywordHitRecord.id)
                .filter(ProjectHit.project_id == project_id)
                .order_by(ProjectHit.created_at.desc())
                .limit(limit)
                .all()
            )
            return [{
                "id": ph.id, "hit_id": h.id, "url": h.url,
                "keyword": h.keyword, "category": h.category, "context": h.context,
                "depth": h.depth, "found_at": h.found_at.isoformat() if h.found_at else None,
                "matched_on": ph.matched_on, "matched_value": ph.matched_value,
            } for ph, h in rows]

    def get_project_stats(self, project_id: int) -> dict:
        with self.get_session() as session:
            total_hits = session.query(func.count(ProjectHit.id)).filter(
                ProjectHit.project_id == project_id).scalar() or 0
            top_keywords = (
                session.query(ProjectHit.matched_value, func.count(ProjectHit.id).label("count"))
                .filter(ProjectHit.project_id == project_id, ProjectHit.matched_on == "keyword")
                .group_by(ProjectHit.matched_value)
                .order_by(func.count(ProjectHit.id).desc())
                .limit(10)
                .all()
            )
            return {
                "total_hits": total_hits,
                "top_keywords": [{"keyword": k, "count": c} for k, c in top_keywords],
            }


    def delete_dns_investigation(self, inv_id: int):
        with self.get_session() as session:
            r = session.get(DNSInvestigation, inv_id)
            if r:
                session.delete(r)
                session.commit()


    # --- Custom Intel ---

    def get_custom_intel(self, intel_type: str) -> list:
        import json
        with self.get_session() as session:
            records = (
                session.query(CustomIntel)
                .filter(CustomIntel.intel_type == intel_type)
                .order_by(CustomIntel.created_at.desc())
                .all()
            )
            return [json.loads(r.data) for r in records]

    def add_custom_intel(self, intel_type: str, slug: str, data: dict, created_by: str = None) -> bool:
        import json
        with self.get_session() as session:
            existing = session.query(CustomIntel).filter(CustomIntel.slug == slug).first()
            if existing:
                return False
            record = CustomIntel(
                intel_type=intel_type,
                slug=slug,
                data=json.dumps(data),
                created_by=created_by,
            )
            session.add(record)
            session.commit()
            return True

    def delete_custom_intel(self, slug: str) -> bool:
        with self.get_session() as session:
            record = session.query(CustomIntel).filter(CustomIntel.slug == slug).first()
            if not record:
                return False
            session.delete(record)
            session.commit()
            return True

    def get_last_hit_date(self, keywords: list[str]) -> str | None:
        """Return ISO timestamp of the most recent keyword hit across given keywords."""
        if not keywords:
            return None
        with self.get_session() as session:
            result = (
                session.query(func.max(KeywordHitRecord.found_at))
                .filter(KeywordHitRecord.keyword.in_(keywords))
                .scalar()
            )
            return result.isoformat() if result else None

    # --- Quick Scan Sessions & Findings ---

    def create_quick_scan_session(
        self,
        user_id: int,
        target_value: str,
        target_type: str,
        normalized_variants: list[str],
        sources_used: list[str],
    ) -> int:
        with self.get_session() as session:
            record = QuickScanSession(
                user_id=user_id,
                target_value=target_value,
                target_type=target_type,
                normalized_variants=json.dumps(normalized_variants),
                sources_used=json.dumps(sources_used),
                status="pending",
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.id

    def update_quick_scan_session(self, session_id: int, **kwargs) -> None:
        with self.get_session() as session:
            record = session.get(QuickScanSession, session_id)
            if not record:
                return
            for key, value in kwargs.items():
                if key in ("normalized_variants", "sources_used") and isinstance(value, (list, dict)):
                    value = json.dumps(value)
                setattr(record, key, value)
            session.commit()

    def add_quick_scan_finding(
        self,
        session_id: int,
        source_name: str,
        url: str,
        matched_variant: str,
        context: str,
        high_signal: bool,
    ) -> int:
        with self.get_session() as session:
            record = QuickScanFinding(
                session_id=session_id,
                source_name=source_name,
                url=url,
                matched_variant=matched_variant,
                context=context,
                high_signal=high_signal,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.id

    def get_quick_scan_session(self, session_id: int) -> Optional["QuickScanSession"]:
        with self.get_session() as session:
            record = session.get(QuickScanSession, session_id)
            if record is not None:
                session.expunge(record)
            return record

    def list_quick_scan_sessions(self, user_id: int, limit: int = 50) -> list["QuickScanSession"]:
        with self.get_session() as session:
            records = (
                session.query(QuickScanSession)
                .filter(QuickScanSession.user_id == user_id)
                .order_by(QuickScanSession.id.desc())
                .limit(limit)
                .all()
            )
            for record in records:
                session.expunge(record)
            return records

    def list_quick_scan_findings(
        self, session_id: int, high_signal_only: bool = False
    ) -> list["QuickScanFinding"]:
        with self.get_session() as session:
            query = session.query(QuickScanFinding).filter(
                QuickScanFinding.session_id == session_id
            )
            if high_signal_only:
                query = query.filter(QuickScanFinding.high_signal.is_(True))
            records = query.order_by(QuickScanFinding.id.asc()).all()
            for record in records:
                session.expunge(record)
            return records

    def has_active_quick_scan(self, user_id: int) -> bool:
        with self.get_session() as session:
            record = (
                session.query(QuickScanSession.id)
                .filter(
                    QuickScanSession.user_id == user_id,
                    QuickScanSession.status.in_(("pending", "running")),
                )
                .first()
            )
            return record is not None

    def fail_running_quick_scans(self, error: str) -> int:
        """Mark every Quick Scan still pending or running as failed. Returns how many.

        For process start: a scan runs on a thread of the dashboard process.
        Left as it is, it would also block its user's next scan.
        """
        with self.get_session() as session:
            rows = (
                session.query(QuickScanSession)
                .filter(QuickScanSession.status.in_(("pending", "running")))
                .all()
            )
            for record in rows:
                record.status = "failed"
                record.error_message = error[:500]
                record.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            session.commit()
            return len(rows)
