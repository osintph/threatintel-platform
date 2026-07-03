"""
Storage layer — SQLite (default) or PostgreSQL via SQLAlchemy.
Stores crawl results, keyword hits, and crawl session metadata.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=True)  # None for OAuth-only users
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    oauth_provider = Column(String(50), nullable=True)  # "google" | "github" | None
    oauth_id = Column(String(255), nullable=True)
    is_admin = Column(Boolean, default=False)
    must_change_password = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_login = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_users_username", "username"),
        Index("ix_users_email", "email"),
        Index("ix_users_oauth", "oauth_provider", "oauth_id"),
    )


class CrawlSession(Base):
    __tablename__ = "crawl_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    ended_at = Column(DateTime, nullable=True)
    seed_urls = Column(Text)  # JSON list
    pages_crawled = Column(Integer, default=0)
    hits_found = Column(Integer, default=0)
    status = Column(String(50), default="running")  # running | completed | failed


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



# ── Paste Monitor Models ────────────────────────────────────────────────────────

class SeenPaste(Base):
    __tablename__ = "seen_pastes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String(50), nullable=False)       # pastebin|rentry|pastesio|controlc|ghostbin
    paste_id = Column(String(200), nullable=False)
    url = Column(Text, nullable=False)
    fetched_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    had_hits = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_seen_pastes_source_id", "source", "paste_id", unique=True),
        Index("ix_seen_pastes_fetched", "fetched_at"),
    )


class PasteHit(Base):
    __tablename__ = "paste_hits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    paste_id = Column(String(200), nullable=False)
    url = Column(Text, nullable=False)
    source = Column(String(50), nullable=False)
    matched_pattern = Column(String(100), nullable=False)  # pattern name e.g. ph_mobile
    matched_value = Column(String(500), nullable=True)     # the actual matched string
    context = Column(Text, nullable=True)
    found_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        Index("ix_paste_hits_found_at", "found_at"),
        Index("ix_paste_hits_source", "source"),
        Index("ix_paste_hits_pattern", "matched_pattern"),
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


class Storage:
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or os.getenv(
            "DATABASE_URL", "sqlite:////app/data/results.db"
        )
        connect_args = {}
        if self.database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

        self.engine = create_engine(
            self.database_url,
            connect_args=connect_args,
            echo=False,
        )
        self._SessionFactory = sessionmaker(bind=self.engine)
        self._create_tables()

    def _create_tables(self):
        Base.metadata.create_all(self.engine)
        logger.info("Database tables ready")

    def get_session(self) -> Session:
        return self._SessionFactory()

    # --- Crawl Sessions ---

    def create_crawl_session(self, seed_urls: list[str]) -> int:
        import json

        with self.get_session() as session:
            record = CrawlSession(seed_urls=json.dumps(seed_urls))
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.id

    def update_crawl_session(
        self, session_id: int, pages_crawled: int, hits_found: int, status: str = "completed"
    ):
        with self.get_session() as session:
            record = session.get(CrawlSession, session_id)
            if record:
                record.ended_at = datetime.now(timezone.utc).replace(tzinfo=None)
                record.pages_crawled = pages_crawled
                record.hits_found = hits_found
                record.status = status
                session.commit()

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

    def get_user_by_oauth(self, provider: str, oauth_id: str):
        with self.get_session() as session:
            return session.query(User).filter(
                User.oauth_provider == provider,
                User.oauth_id == oauth_id
            ).first()

    def create_user(self, username: str, password_hash: str = None,
                    email: str = None, oauth_provider: str = None,
                    oauth_id: str = None, is_admin: bool = False,
                    must_change_password: bool = False):
        with self.get_session() as session:
            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                oauth_provider=oauth_provider,
                oauth_id=oauth_id,
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
                user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
                session.commit()

    def enable_totp(self, user_id: int, secret: str):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.totp_secret = secret
                user.totp_enabled = True
                session.commit()

    def disable_totp(self, user_id: int):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.totp_secret = None
                user.totp_enabled = False
                session.commit()

    def count_users(self) -> int:
        with self.get_session() as session:
            return session.query(func.count(User.id)).scalar() or 0

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
                session.commit()

    def update_user_password(self, user_id: int, password_hash: str):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.password_hash = password_hash
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


    def get_active_session(self):
        with self.get_session() as session:
            r = (
                session.query(CrawlSession)
                .filter(CrawlSession.status == "running")
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

    def delete_project_keyword(self, keyword_id: int):
        with self.get_session() as session:
            kw = session.get(ProjectKeyword, keyword_id)
            if kw:
                session.delete(kw)
                session.commit()

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

    def delete_project_domain(self, domain_id: int):
        with self.get_session() as session:
            d = session.get(ProjectDomain, domain_id)
            if d:
                session.delete(d)
                session.commit()

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

    def delete_project_entity(self, entity_id: int):
        with self.get_session() as session:
            e = session.get(ProjectEntity, entity_id)
            if e:
                session.delete(e)
                session.commit()

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


    # ── Paste Monitor ─────────────────────────────────────────────────────────────

    def is_paste_seen(self, source: str, paste_id: str) -> bool:
        with self.get_session() as session:
            return session.query(SeenPaste).filter(
                SeenPaste.source == source,
                SeenPaste.paste_id == paste_id,
            ).first() is not None

    def mark_paste_seen(self, source: str, paste_id: str, url: str, had_hits: bool = False):
        with self.get_session() as session:
            existing = session.query(SeenPaste).filter(
                SeenPaste.source == source,
                SeenPaste.paste_id == paste_id,
            ).first()
            if not existing:
                session.add(SeenPaste(source=source, paste_id=paste_id,
                                      url=url, had_hits=had_hits))
                session.commit()

    def save_paste_hit(self, paste_id: str, url: str, source: str,
                       matched_pattern: str, matched_value: str = None,
                       context: str = None) -> int:
        with self.get_session() as session:
            h = PasteHit(paste_id=paste_id, url=url, source=source,
                         matched_pattern=matched_pattern,
                         matched_value=matched_value, context=context)
            session.add(h)
            session.commit()
            session.refresh(h)
            return h.id

    def get_recent_paste_hits(self, limit: int = 100, source: str = None,
                               pattern: str = None) -> list[dict]:
        with self.get_session() as session:
            q = session.query(PasteHit)
            if source:
                q = q.filter(PasteHit.source == source)
            if pattern:
                q = q.filter(PasteHit.matched_pattern == pattern)
            hits = q.order_by(PasteHit.found_at.desc()).limit(limit).all()
            return [{
                "id": h.id, "paste_id": h.paste_id, "url": h.url,
                "source": h.source, "matched_pattern": h.matched_pattern,
                "matched_value": h.matched_value, "context": h.context,
                "found_at": h.found_at.isoformat() if h.found_at else None,
            } for h in hits]

    def get_paste_stats(self) -> dict:
        with self.get_session() as session:
            total_hits = session.query(func.count(PasteHit.id)).scalar() or 0
            total_scanned = session.query(func.count(SeenPaste.id)).scalar() or 0
            total_with_hits = session.query(func.count(SeenPaste.id)).filter(
                SeenPaste.had_hits.is_(True)).scalar() or 0
            by_pattern = (
                session.query(PasteHit.matched_pattern,
                              func.count(PasteHit.id).label("count"))
                .group_by(PasteHit.matched_pattern)
                .order_by(func.count(PasteHit.id).desc())
                .all()
            )
            by_source = (
                session.query(PasteHit.source,
                              func.count(PasteHit.id).label("count"))
                .group_by(PasteHit.source)
                .order_by(func.count(PasteHit.id).desc())
                .all()
            )
            return {
                "total_hits": total_hits,
                "total_scanned": total_scanned,
                "total_with_hits": total_with_hits,
                "by_pattern": [{"pattern": p, "count": c} for p, c in by_pattern],
                "by_source": [{"source": s, "count": c} for s, c in by_source],
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
