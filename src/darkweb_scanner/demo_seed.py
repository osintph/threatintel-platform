"""
Fake data for the demo instance (docker-compose profile "demo").

    make demo-seed

Refuses to run unless DEMO_MODE=1 is set and the database is the demo one,
checked on the URL before connecting and on the connection afterwards. Each run
replaces the demo data, with dates spread over the 90 days before the run.

Everything is invented: organisations and handles, .example domains, addresses
from the documentation ranges, v3 onion addresses that are valid in form only,
masked passwords. Hits name only the invented groups below, never a real
ransomware group.

/register works only while there are no users, so analyst accounts are added
only once an administrator exists. Quick Scan shows a user only their own
sessions; they belong to the first administrator. Run this again after creating
that account.
"""

import base64
import hashlib
import json
import os
import random
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping, Optional

import bcrypt
import pyotp
import yaml
from sqlalchemy import text
from sqlalchemy.engine import make_url

from .storage import (
    AuthEvent,
    CrawledPage,
    CrawlSession,
    CustomIntel,
    DNSInvestigation,
    Investigation,
    InvestigationTarget,
    IPInvestigation,
    KeywordHitRecord,
    Project,
    ProjectDomain,
    ProjectEntity,
    ProjectHit,
    ProjectKeyword,
    QuickScanFinding,
    QuickScanSession,
    Storage,
    User,
    normalise_database_url,
)

DEMO_DB_HOST = "demo-postgres"
DEMO_DB_NAME = "darkweb_scanner_demo"
SPREAD_DAYS = 90
SESSION_COUNT = 25
HIT_COUNT = 300

ANALYSTS = (
    ("analyst.rivera", "Senior analyst"),
    ("analyst.ocampo", "Analyst"),
    ("analyst.magsino", "Analyst"),
    ("lead.villareal", "Team lead"),
)

# ── Fiction: organisations, sites, groups ─────────────────────────────────────

CLIENTS = (
    {
        "key": "bank", "name": "Bangko Talampas", "sector": "banking", "domain": "bangkotalampas.example",
        "color": "#f85149", "brand": "TalampasOnline", "subs": ["ebanking", "cards", "swift-gw", "atm-mgmt"],
        "people": ["Corazon Abellana", "Emilio Tanglao"], "email_policy": "strict",
    },
    {
        "key": "bpo", "name": "Kawayan Contact Partners", "sector": "BPO", "domain": "kawayancontact.example",
        "color": "#d29922", "brand": "KawayanConnect", "subs": ["agents", "citrix", "wfm", "dialer"],
        "people": ["Ramil Sayson", "Jocelyn Bautro"], "email_policy": "weak",
    },
    {
        "key": "hospital", "name": "Dalisay Crest Medical Group", "sector": "healthcare", "domain": "dalisaycrest.example",
        "color": "#3fb950", "brand": "CrestCare", "subs": ["emr", "pacs", "lab", "billing"],
        "people": ["Dr. Amparo Lualhati", "Nestor Dimalanta"], "email_policy": "weak",
    },
    {
        "key": "retail", "name": "Tindahan Aurelia", "sector": "retail", "domain": "tindahanaurelia.example",
        "color": "#bc8cff", "brand": "AureliaRewards", "subs": ["shop", "pos", "loyalty", "checkout"],
        "people": ["Milagros Evangelio", "Paolo Sunga"], "email_policy": "strict",
    },
    {
        "key": "logistics", "name": "Banwa Freightlines", "sector": "logistics", "domain": "banwafreight.example",
        "color": "#58a6ff", "brand": "BanwaTrack", "subs": ["track", "tms", "edi", "drivers"],
        "people": ["Rogelio Macaraeg", "Teresita Quiambao"], "email_policy": "missing",
    },
    {
        "key": "school", "name": "Colegio de Sta. Ilaya", "sector": "education", "domain": "colegiostailaya.example",
        "color": "#39c5cf", "brand": "IlayaPortal", "subs": ["lms", "enrol", "registrar", "alumni"],
        "people": ["Sr. Felicidad Arcangel", "Dante Pineda"], "email_policy": "missing",
    },
)

SITES = (
    ("Kubli Forum", "forum"), ("Sindikato Board", "forum"), ("Tahimik Access", "forum"),
    ("Dagat Itim Market", "market"), ("Anino Exchange", "market"), ("Liwayway Carders", "market"),
    ("Bakas Logs", "logs"), ("Pugad Leaks", "leak"),
)

HANDLES = (
    "kalabaw_x", "n4gb4b4ka", "tiktik404", "pilandok_", "sirena.zip", "duwende99", "bungisngis",
    "maliksi_rdp", "lakambini0x", "tamaraw_ops", "agimat_seller", "balete_root",
)

GROUPS = (
    {
        "name": "Alimpuyo Locker", "slug": "alimpuyo-locker", "keyword": "alimpuyo locker", "origin": "Unknown (invented)",
        "first_seen": "2025-03", "risk_level": "critical", "status": "active",
        "description": "Invented double-extortion crew for this demo. Posts a countdown and a file tree for each victim.",
        "ttps": ["Bought VPN access", "Credential dumping", "Backup deletion", "Data theft before encryption"],
        "victims": ["hospital", "logistics"],
    },
    {
        "name": "Daluyong Crew", "slug": "daluyong-crew", "keyword": "daluyong crew", "origin": "Unknown (invented)",
        "first_seen": "2025-11", "risk_level": "high", "status": "active",
        "description": "Invented affiliate programme for this demo, aimed at mid-size Southeast Asian companies.",
        "ttps": ["Exposed RDP", "Stealer log reuse", "Scheduled-task deployment"],
        "victims": ["bpo", "retail"],
    },
    {
        "name": "Hilakbot Team", "slug": "hilakbot-team", "keyword": "hilakbot team", "origin": "Unknown (invented)",
        "first_seen": "2026-05", "risk_level": "medium", "status": "active",
        "description": "Invented data-extortion group for this demo. Steals and publishes; does not encrypt.",
        "ttps": ["Cloud storage theft", "Extortion e-mail to staff"],
        "victims": ["school"],
    },
)

ACTORS = (
    {
        "name": "Bayan-Sulo Brigade", "slug": "bayan-sulo-brigade", "keyword": "bayan-sulo brigade", "type": "hacktivist",
        "origin": "Unknown (invented)", "first_seen": "2024-08", "risk_level": "medium", "status": "active",
        "aliases": ["BSB", "Sulo Cell"], "sectors": ["Education", "Government", "Healthcare"],
        "known_malware": ["SuloDefacer"], "ttps": ["Website defacement", "Small floods", "Leak claims on Telegram"],
        "description": "Invented hacktivist collective for this demo. Claims are often exaggerated.",
    },
    {
        "name": "Silong Cell", "slug": "silong-cell", "keyword": "silong cell", "type": "cybercriminal",
        "origin": "Unknown (invented)", "first_seen": "2023-02", "risk_level": "high", "status": "active",
        "aliases": ["silong_ops"], "sectors": ["Banking", "BPO", "Retail"],
        "known_malware": ["Salot Stealer", "BukoLoader"], "ttps": ["Malvertising", "Stealer logs", "Selling initial access"],
        "description": "Invented access broker for this demo. Resells corporate logins taken from stealer logs.",
    },
    {
        "name": "Balintataw Group", "slug": "balintataw-group", "keyword": "balintataw group", "type": "espionage",
        "origin": "Unknown (invented)", "first_seen": "2022-10", "risk_level": "critical", "status": "active",
        "aliases": ["Pupil Team"], "sectors": ["Logistics", "Healthcare"],
        "known_malware": ["TikbalangRAT"], "ttps": ["Spear-phishing", "DLL side-loading", "Long dwell time"],
        "description": "Invented espionage cluster for this demo, interested in shipping and medical records.",
    },
)

BREACHES = (
    ("KapePoints", "2025-06-14", "Invented loyalty app breach used only in this demo.", ["Email addresses", "Passwords", "Phone numbers"], True),
    ("SariSariHub", "2024-11-02", "Invented marketplace breach used only in this demo.", ["Email addresses", "Names", "Physical addresses"], True),
    ("LakbayTickets", "2026-02-20", "Invented travel booking breach used only in this demo.", ["Email addresses", "Passwords", "Dates of birth"], False),
    ("PinoyJobsBoard", "2023-09-09", "Invented job site breach used only in this demo.", ["Email addresses", "Employment details", "Names"], True),
)

ENGINES = ("AlonScan", "BantayAV", "KalasagIQ", "TanodShield", "Sentinela-PH", "Muog Labs")
ISPS = ("Hilaga Hosting", "Timog Datacenter Co", "Kanluran Transit", "Silangan VPS")
ISSUERS = ("O=Invented Demo CA, CN=Demo Issuing R3", "O=Example Trust Services, CN=Example DV G2")

# ── Templates: one per kind of post ───────────────────────────────────────────
# kind: (category, site type, generic keyword, only these clients, weight, template)

KINDS = {
    "credentials": (
        "credential_leak", "forum", "email:pass", None, 26,
        "[{site}] {handle} posted: FRESH DUMP {org} staff portal, {n} lines email:pass.\n"
        "Sample:\n{email}:{pw}\n{email2}:{pw2}\n{email3}:{pw3}\n"
        "sha256 {hash}. 8 credits to unlock, no resale.",
    ),
    "combo": (
        "credential_leak", "forum", "combo list", None, 18,
        "{handle}: PH corporate combo list, {month} edition. {n} lines, heavy on {domain}, 62% valid at last check.\n"
        "{email}:{pw} | {email2}:{pw2}\nLink in hidden content, reply to unlock.",
    ),
    "vpn_access": (
        "initial_access", "forum", "vpn access", None, 14,
        "[SELLING] VPN access: {org} ({sector}, Philippines, about PHP {rev}B revenue).\n"
        "SSL VPN, domain user, {hosts} hosts in AD, EDR on servers only. Gateway {ip}.\n"
        "Start ${price}, step $100, blitz ${blitz}. Escrow accepted. Contact {handle}, tox only.",
    ),
    "rdp_access": (
        "initial_access", "forum", "rdp access", None, 10,
        "[WTS] RDP access, local admin on a {org} server ({domain}), {hosts} machines visible, no MFA on the jump host.\n"
        "Host {ip}, sold once. ${price}, deal through the {site} guarantor. PM {handle}.",
    ),
    "ransomware": (
        "ransomware", "leak", None, None, 12,
        "{group} LEAK SITE: NEW VICTIM\n{org} ({domain})\n"
        "Time until publication: {d}d {h}h {m}m\nData taken: {gb} GB\n"
        "/finance/{year}_payroll.xlsx\n/hr/employees_full.csv\n/legal/contracts/\n/backups/sql/{db}.bak\n"
        "Proof pack: 40 files. Talk to us through the chat portal before the timer ends.",
    ),
    "patient_db": (
        "data_sale", "market", "patient database", {"hospital"}, 8,
        "[WTS] {org} patient database: {n} records (name, DOB, masked insurance no., diagnosis, billing).\n"
        "Extract date {date}. ${price}, one buyer only, escrow via {site}, 20-row sample on request.\n"
        "Seller {handle}, rep 4.8, 112 deals.",
    ),
    "stealer": (
        "stealer_logs", "logs", "stealer logs", None, 16,
        "[Salot Stealer logs] batch {batch} | host DESKTOP-{host} | country PH | IP {ip}\n"
        "URL: https://portal.{domain}/login\nUSER: {email}\nPASS: {pw}\ncookies: {hosts} | autofill: {gb}",
    ),
    "carding": (
        "carding", "market", "fullz", {"bank", "retail"}, 8,
        "{site} update: {org} checkout skim, {n} cards, fullz with billing address, exp 2027+.\n"
        "4***-****-****-{last4} CVV *** | 5***-****-****-{last42} CVV ***\n${price2} each, bulk discount from 50. Seller {handle}.",
    ),
    "insider": (
        "insider_threat", "forum", "insider", None, 5,
        "Looking for an insider at {org}. Active employee with helpdesk or VPN rights.\n"
        "Paying PHP {price}0 a month, more for domain admin. Everything through {site} PM, ask for {handle}.",
    ),
    "actor_chatter": (
        "threat_actor", "forum", None, None, 6,
        "{handle}: {actor} is asking around for anything on {org} ({domain}).\n"
        "They pay well for staff lists and VPN logins. Second time this quarter. Be careful who you sell to.",
    ),
    "hacktivist": (
        "hacktivism", "forum", None, {"school", "hospital", "logistics"}, 5,
        "{actor} CLAIM: we took down {domain} and hold {gb} GB from {org}. Our demands were ignored.\n"
        "Proof screenshots attached. Spread the word. #OpSulo",
    ),
}

MONTHS = ("January", "March", "May", "July", "September", "November")

# ── Refusing the wrong database ───────────────────────────────────────────────


def refuse_reason(database_url: str, env: Mapping[str, str]) -> Optional[str]:
    """Why this must not run against ``database_url``, or None when it is the demo database."""
    if env.get("DEMO_MODE") != "1":
        return "DEMO_MODE=1 is not set, so this is not the demo instance."
    if not database_url:
        return "DATABASE_URL is not set."
    try:
        url = make_url(normalise_database_url(database_url))
    except Exception:
        return "DATABASE_URL could not be read."
    if url.host != DEMO_DB_HOST:
        return f"the database host is not {DEMO_DB_HOST}."
    if url.database != DEMO_DB_NAME:
        return f"the database name is not {DEMO_DB_NAME}."
    return None


# ── Generators ────────────────────────────────────────────────────────────────


def _onion(rng: random.Random) -> str:
    """A v3 onion address, valid in form (key, checksum, version); no such service exists."""
    key = rng.randbytes(32)
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2]
    return base64.b32encode(key + checksum + version).decode().lower() + ".onion"


def _doc_ip(rng: random.Random) -> str:
    return f"{rng.choice(('192.0.2', '198.51.100', '203.0.113'))}.{rng.randint(1, 254)}"


def _masked(rng: random.Random) -> str:
    word = rng.choice(("Pa", "Ma", "Ka", "Sa", "Ta", "We", "Qw", "Ad"))
    return f"{word}****{rng.randint(10, 99)}"


def _hex(rng: random.Random, length: int) -> str:
    return rng.randbytes(length // 2).hex()


def _person_email(rng: random.Random, domain: str) -> str:
    first = rng.choice(("jdelacruz", "mreyes", "asantos", "rbautista", "lgarcia", "cmendoza", "pvillanueva", "kaquino"))
    return f"{first}{rng.randint(1, 99)}@{domain}"


def _when(rng: random.Random, now: datetime, oldest_days: float, newest_days: float = 0.0) -> datetime:
    return now - timedelta(seconds=rng.uniform(newest_days * 86400, oldest_days * 86400))


def _client_keywords(client: dict) -> list[str]:
    return [client["name"], client["brand"], client["domain"]]


def _allowed_kinds(client: dict) -> list[str]:
    return [k for k, spec in KINDS.items() if spec[3] is None or client["key"] in spec[3]]


def _post(rng: random.Random, kind: str, client: dict, onions: dict) -> dict:
    """One keyword hit: keyword, category, context and URL."""
    category, site_type, generic, _, _, template = KINDS[kind]
    site = rng.choice([name for name, t in SITES if t == site_type])
    group = rng.choice([g for g in GROUPS if client["key"] in g["victims"]] or GROUPS[:1])
    actor = rng.choice(ACTORS[1:]) if kind == "actor_chatter" else ACTORS[0]
    fields = {
        "site": site, "handle": rng.choice(HANDLES), "org": client["name"], "domain": client["domain"],
        "sector": client["sector"], "n": f"{rng.randint(4, 480) * 100:,}", "hash": _hex(rng, 64),
        "email": _person_email(rng, client["domain"]), "pw": _masked(rng),
        "email2": _person_email(rng, client["domain"]), "pw2": _masked(rng),
        "email3": _person_email(rng, client["domain"]), "pw3": _masked(rng),
        "month": rng.choice(MONTHS), "rev": rng.randint(2, 40), "hosts": rng.randint(40, 2200),
        "ip": _doc_ip(rng), "price": rng.randint(8, 95) * 100, "blitz": rng.randint(10, 18) * 1000,
        "price2": rng.randint(9, 45), "group": group["name"], "actor": actor["name"],
        "d": rng.randint(1, 9), "h": rng.randint(0, 23), "m": rng.randint(0, 59), "gb": rng.randint(12, 840),
        "year": rng.choice((2025, 2026)), "db": f"{client['key']}_core", "date": f"2026-{rng.randint(5, 10):02d}-{rng.randint(1, 28):02d}",
        "batch": rng.randint(1000, 9999), "host": _hex(rng, 6).upper(),
        "last4": rng.randint(1000, 9999), "last42": rng.randint(1000, 9999),
    }
    context = template.format(**fields)
    if kind == "ransomware":
        keyword = group["keyword"]
    elif kind in ("hacktivist", "actor_chatter"):
        keyword = actor["keyword"]
    elif generic is None or rng.random() < 0.72:
        keyword = rng.choice([k for k in _client_keywords(client) if k.lower() in context.lower()] or [client["domain"]])
    else:
        keyword = generic
    slug = rng.choice(("thread", "listing", "post", "view"))
    url = f"http://{onions[site]}/{slug}/{rng.randint(10000, 99999)}"
    return {"keyword": keyword, "category": category, "context": context, "url": url, "kind": kind, "client": client}


def _hits(rng: random.Random, onions: dict) -> list[dict]:
    """HIT_COUNT posts: at least one of every kind for each client it applies to."""
    posts = [_post(rng, kind, client, onions) for client in CLIENTS for kind in _allowed_kinds(client)]
    while len(posts) < HIT_COUNT:
        client = rng.choice(CLIENTS)
        allowed = _allowed_kinds(client)
        kind = rng.choices(allowed, weights=[KINDS[k][4] for k in allowed])[0]
        posts.append(_post(rng, kind, client, onions))
    return posts[:HIT_COUNT]


def _sessions(rng: random.Random, now: datetime, posts: list[dict], onions: dict) -> list[dict]:
    """SESSION_COUNT crawls spread over SPREAD_DAYS, the posts shared out among them."""
    # 89.5 days is the oldest start, so a whole session stays inside the window.
    starts = sorted(
        (now - timedelta(days=0.2 + (SPREAD_DAYS - 0.5 - 0.2) * i / (SESSION_COUNT - 1) + rng.uniform(-0.1, 0.1)))
        for i in range(SESSION_COUNT)
    )
    sessions = [{"started_at": s, "posts": []} for s in starts]
    for i, post in enumerate(posts):
        sessions[i % SESSION_COUNT if i < SESSION_COUNT else rng.randrange(SESSION_COUNT)]["posts"].append(post)

    for i, s in enumerate(sessions):
        minutes = rng.randint(25, 140)
        s["status"], s["error"] = "completed", None
        if i == 3:
            s["status"] = "stopped"
        elif i == 11:
            s["status"], s["error"] = "failed", "Tor did not answer within the time limit."
        elif i == 17:
            s["status"], s["error"] = "interrupted", "The process that ran this crawl was restarted before the crawl ended."
        s["ended_at"] = s["started_at"] + timedelta(minutes=minutes)
        s["minutes"] = minutes
        s["seeds"] = rng.sample([f"http://{o}/" for o in onions.values()], k=rng.randint(3, len(onions)))
        for post in s["posts"]:
            post["found_at"] = s["started_at"] + timedelta(seconds=rng.uniform(30, minutes * 60 - 30))
    return sessions


# ── Writers ───────────────────────────────────────────────────────────────────


def _wipe(db) -> None:
    """Remove the previous demo data. Accounts other than the seeded analysts stay."""
    for model in (
        CrawledPage, KeywordHitRecord, CrawlSession, InvestigationTarget, Investigation, IPInvestigation,
        DNSInvestigation, ProjectHit, ProjectEntity, ProjectDomain, ProjectKeyword, Project, CustomIntel,
        QuickScanFinding, QuickScanSession,
    ):
        db.query(model).delete(synchronize_session=False)
    names = [name for name, _ in ANALYSTS]
    db.query(AuthEvent).filter(AuthEvent.username.in_(names)).delete(synchronize_session=False)
    db.query(User).filter(User.username.in_(names)).delete(synchronize_session=False)
    db.commit()


def _write_analysts(db, rng: random.Random, now: datetime) -> int:
    """Accounts nobody can sign in to (random password and second factor), with sign-in history."""
    domain = "osintdemo.example"
    for name, _role in ANALYSTS:
        created = _when(rng, now, SPREAD_DAYS, 70)
        hashed = bcrypt.hashpw(secrets.token_hex(24).encode(), bcrypt.gensalt()).decode()
        user = User(
            username=name, email=f"{name}@{domain}", password_hash=hashed, totp_secret=pyotp.random_base32(),
            totp_enabled=True, is_admin=False, created_at=created,
        )
        db.add(user)
        db.flush()
        address = _doc_ip(rng)
        db.add(AuthEvent(ts=created, event="user_created", username=name, user_id=user.id, ip=_doc_ip(rng), detail="by administrator"))
        last = created
        for _ in range(rng.randint(14, 34)):
            ts = _when(rng, now, (now - created).days or 1)
            roll = rng.random()
            if roll < 0.78:
                db.add(AuthEvent(ts=ts, event="login_ok", username=name, user_id=user.id, ip=address, detail="password and TOTP"))
                last = max(last, ts)
            elif roll < 0.9:
                db.add(AuthEvent(ts=ts, event="login_failed", username=name, user_id=user.id, ip=_doc_ip(rng), detail="wrong password"))
            elif roll < 0.96:
                db.add(AuthEvent(ts=ts, event="mfa_failed", username=name, user_id=user.id, ip=address, detail="wrong code"))
            else:
                db.add(AuthEvent(ts=ts, event="logout", username=name, user_id=user.id, ip=address))
        user.last_login = last
    db.commit()
    return len(ANALYSTS)


def _write_crawls(db, rng: random.Random, sessions: list[dict], onions: dict) -> None:
    for s in sessions:
        record = CrawlSession(
            started_at=s["started_at"], ended_at=s["ended_at"], seed_urls=json.dumps(s["seeds"]),
            status=s["status"], error=s["error"], owner="demo-seed:1", heartbeat_at=s["ended_at"],
            hits_found=len(s["posts"]),
        )
        db.add(record)
        db.flush()
        pages = []
        for post in s["posts"]:
            hit = KeywordHitRecord(
                session_id=record.id, url=post["url"], keyword=post["keyword"], category=post["category"],
                context=post["context"], position=rng.randint(40, 9000), depth=rng.randint(0, 3),
                found_at=post["found_at"], alerted=rng.random() < 0.35,
            )
            db.add(hit)
            db.flush()
            post["hit_id"] = hit.id
            pages.append(CrawledPage(session_id=record.id, url=post["url"], crawled_at=post["found_at"], status_code=200, depth=hit.depth))
        for _ in range(rng.randint(24, 110)):
            site_onion = rng.choice(list(onions.values()))
            failed = rng.random() < 0.08
            pages.append(CrawledPage(
                session_id=record.id, url=f"http://{site_onion}/page/{rng.randint(1, 400)}",
                crawled_at=s["started_at"] + timedelta(seconds=rng.uniform(5, s["minutes"] * 60)),
                status_code=rng.choice((403, 503)) if failed else 200, depth=rng.randint(0, 3),
                had_error=failed, error_message="upstream closed the connection" if failed else None,
            ))
        record.pages_crawled = len(pages)
        db.add_all(pages)
    db.commit()


def _write_projects(db, rng: random.Random, now: datetime, posts: list[dict], owner_id: int) -> None:
    for client in CLIENTS:
        created = _when(rng, now, SPREAD_DAYS, 80)
        project = Project(
            name=client["name"], description=f"Invented {client['sector']} client used only in this demo.",
            status="active", owner_id=owner_id, created_at=created, updated_at=_when(rng, now, 3),
            alert_threshold=rng.randint(1, 5), color=client["color"], tags=json.dumps([client["sector"], "demo", "PH"]),
        )
        db.add(project)
        db.flush()
        for word, category in ((client["name"], "brand"), (client["brand"], "product"), (client["domain"], "domain")):
            db.add(ProjectKeyword(project_id=project.id, keyword=word, category=category))
        for i, host in enumerate([client["domain"]] + [f"{s}.{client['domain']}" for s in client["subs"]]):
            db.add(ProjectDomain(project_id=project.id, domain=host, priority=min(i + 1, 5), notes="Monitored asset"))
        db.add(ProjectEntity(project_id=project.id, entity_type="organization", value=client["name"], notes="Legal name"))
        db.add(ProjectEntity(project_id=project.id, entity_type="brand", value=client["brand"], notes="Customer-facing product"))
        db.add(ProjectEntity(project_id=project.id, entity_type="email", value=f"ciso@{client['domain']}", notes="Security contact"))
        db.add(ProjectEntity(project_id=project.id, entity_type="ip", value=_doc_ip(rng), notes="VPN gateway"))
        for person in client["people"]:
            db.add(ProjectEntity(project_id=project.id, entity_type="person", value=person, notes="Named executive"))
        for post in posts:
            if post["client"] is not client:
                continue
            keyword = next((k for k in _client_keywords(client) if k == post["keyword"]), client["name"] if client["name"] in post["context"] else None)
            if keyword:
                db.add(ProjectHit(project_id=project.id, hit_id=post["hit_id"], matched_on="keyword", matched_value=keyword, created_at=post["found_at"]))
            if client["domain"] in post["context"]:
                db.add(ProjectHit(project_id=project.id, hit_id=post["hit_id"], matched_on="domain", matched_value=client["domain"], created_at=post["found_at"]))
            elif not keyword:
                db.add(ProjectHit(project_id=project.id, hit_id=post["hit_id"], matched_on="entity", matched_value=client["name"], created_at=post["found_at"]))
    db.commit()


def _write_investigations(db, storage: Storage, rng: random.Random, now: datetime) -> None:
    plans = []
    for client in CLIENTS:
        plans.append((f"{client['name']}: exposure review", [
            (f"ciso@{client['domain']}", "email"), (f"it.admin@{client['domain']}", "email"),
            (client["name"], "name"), (client["brand"], "keyword"),
        ]))
    plans.append(("Access broker follow-up", [("maliksi_rdp", "keyword"), ("vpn access", "keyword"), (f"helpdesk@{CLIENTS[1]['domain']}", "email")]))
    plans.append(("Leak site watch", [("alimpuyo locker", "keyword"), ("daluyong crew", "keyword")]))
    for name, targets in plans:
        created = _when(rng, now, SPREAD_DAYS - 2)
        record = Investigation(name=name, status="completed", created_at=created, completed_at=created + timedelta(seconds=rng.randint(20, 300)), target_count=len(targets))
        db.add(record)
        db.flush()
        for value, target_type in targets:
            breaches = []
            if target_type == "email":
                for b_name, b_date, description, classes, verified in rng.sample(BREACHES, k=rng.randint(1, 3)):
                    breaches.append({
                        "breach_name": b_name, "breach_date": b_date, "description": description,
                        "data_classes": classes, "is_verified": verified, "is_sensitive": False,
                    })
            hits = storage.search_hits(value)
            db.add(InvestigationTarget(
                investigation_id=record.id, value=value, target_type=target_type, breaches=json.dumps(breaches),
                darkweb_hits=json.dumps(hits), breach_count=len(breaches), darkweb_count=len(hits), checked_at=created,
            ))
    db.commit()


def _ip_lookup(rng: random.Random, now: datetime, ip: str, malicious: bool) -> tuple[dict, dict]:
    isp = rng.choice(ISPS)
    code, name = rng.choice((("PH", "Philippines"), ("SG", "Singapore"), ("NL", "Netherlands"), ("VN", "Vietnam")))
    score = rng.randint(55, 100) if malicious else rng.randint(0, 12)
    host = f"host-{ip.replace('.', '-')}.{isp.split()[0].lower()}.example"
    reports = [{
        "categories": rng.sample(("Brute-Force", "SSH", "Web App Attack", "Port Scan", "Hacking"), k=2),
        "reporter_country": rng.choice(("PH", "SG", "US", "DE")),
        "comment": rng.choice(("Repeated VPN login failures", "SSH brute force from this address", "Scanning for exposed RDP", "Probing /wp-login and /owa")),
    } for _ in range(rng.randint(2, 5) if malicious else 0)]
    abuse = {
        "ip": ip, "abuse_confidence_score": score, "country_code": code, "country_name": name, "isp": isp,
        "domain": f"{isp.split()[0].lower()}.example", "usage_type": rng.choice(("Data Center/Web Hosting/Transit", "Fixed Line ISP")),
        "is_tor": malicious and rng.random() < 0.25, "total_reports": len(reports) * rng.randint(3, 40), "num_distinct_users": len(reports) * 2,
        "last_reported_at": _when(rng, now, 20).isoformat() if malicious else None, "hostnames": [host], "reports": reports,
    }
    bad = rng.randint(4, 14) if malicious else 0
    suspicious = rng.randint(0, 3) if malicious else 0
    harmless = rng.randint(55, 66)
    undetected = 92 - bad - suspicious - harmless
    flagged = rng.sample(ENGINES, k=min(bad, len(ENGINES)))
    asn = rng.randint(64496, 64511)
    vt = {
        "ip": ip, "asn": asn, "as_owner": isp, "country": code, "continent": "AS" if code != "NL" else "EU",
        "network": ip.rsplit(".", 1)[0] + ".0/24", "regional_internet_registry": "APNIC" if code != "NL" else "RIPE NCC",
        "reputation": -rng.randint(5, 60) if malicious else 0, "jarm": _hex(rng, 62),
        "tags": ["vpn", "scanner"] if malicious else [], "last_analysis_date": _when(rng, now, 10).isoformat(),
        "analysis_stats": {"malicious": bad, "suspicious": suspicious, "harmless": harmless, "undetected": undetected},
        "total_engines": 92, "malicious_engines": [{"engine": e, "category": "malicious", "result": "malware site"} for e in flagged],
        "ssl_certificate": {"subject_cn": host, "issuer_org": "Invented Demo CA", "valid_from": "2026-03-01", "valid_to": "2027-03-01"},
        "resolutions": [{"hostname": f"{rng.choice(('cdn', 'login', 'files'))}{i}.{isp.split()[0].lower()}.example", "date": int(_when(rng, now, 80).timestamp())} for i in range(rng.randint(2, 7))],
    }
    return abuse, vt


def _write_ip_lookups(db, rng: random.Random, now: datetime) -> None:
    for i in range(14):
        ip = _doc_ip(rng)
        abuse, vt = _ip_lookup(rng, now, ip, malicious=i % 3 != 2)
        db.add(IPInvestigation(
            ip=ip, status="completed", created_at=_when(rng, now, SPREAD_DAYS - 1), abuseipdb_data=json.dumps(abuse),
            virustotal_data=json.dumps(vt), abuse_score=abuse["abuse_confidence_score"], vt_malicious=vt["analysis_stats"]["malicious"],
            country=abuse["country_code"], isp=abuse["isp"],
        ))
    db.commit()


def _email_security(domain: str, policy: str, ip: str) -> dict:
    spf_strict, dmarc_strict = f"v=spf1 ip4:{ip} mx -all", f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"
    if policy == "strict":
        return {"spf": spf_strict, "spf_valid": True, "dmarc": dmarc_strict, "dmarc_valid": True, "dkim_selectors_found": ["default", "s1"], "issues": []}
    if policy == "weak":
        return {
            "spf": f"v=spf1 ip4:{ip} ~all", "spf_valid": True, "dmarc": f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}",
            "dmarc_valid": True, "dkim_selectors_found": ["default"], "issues": ["SPF ends in ~all (soft fail).", "DMARC policy is p=none: nothing is enforced."],
        }
    return {"spf": None, "spf_valid": False, "dmarc": None, "dmarc_valid": False, "dkim_selectors_found": [], "issues": ["No SPF record: anyone can spoof this domain.", "No DMARC record."]}


def _dns_result(rng: random.Random, client: dict, created: datetime) -> dict:
    domain = client["domain"]
    base = rng.choice(("192.0.2", "198.51.100", "203.0.113"))
    ips = [f"{base}.{10 + i * 7}" for i in range(6)]
    geo = {}
    for ip in ips:
        org = rng.choice(ISPS)
        asn = rng.randint(64496, 64511)
        geo[ip] = {
            "status": "success", "country": "Philippines", "countryCode": "PH", "regionName": "Metro Manila",
            "city": rng.choice(("Makati", "Taguig", "Quezon City", "Pasig")), "org": org, "as": f"AS{asn} {org}", "isp": org, "query": ip,
        }
    names = ["www", "mail", "vpn", "portal", "sso", "api", "staging", "dev", "owa", "ftp", "hr", "payroll"] + client["subs"]
    hosts = [f"{n}.{domain}" for n in names]
    resolved, bruteforce, passive, services = [], [], [], {}
    for i, host in enumerate(hosts):
        ip = ips[i % len(ips)]
        item = {"subdomain": host, "ips": [ip], "geo": geo[ip]}
        if i % 5 == 4:
            bruteforce.append({**item, "source": "bruteforce"})
        else:
            resolved.append(item)
        not_before = created - timedelta(days=rng.randint(30, 700))
        for renewal in range(rng.randint(1, 3)):
            start = not_before + timedelta(days=90 * renewal)
            passive.append({
                "subdomain": host, "issuer": rng.choice(ISSUERS), "not_before": start.strftime("%Y-%m-%dT%H:%M:%S"),
                "not_after": (start + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S"), "cert_id": rng.randint(10**9, 9 * 10**9),
            })
        services[host] = {
            "server": rng.choice(("nginx", "Apache", "IIS", "unknown")), "tech": rng.sample(("PHP", "jQuery", "Bootstrap", "ASP.NET", "WordPress"), k=2),
            "status_code": rng.choice((200, 200, 200, 301, 403)), "title": f"{client['name']} {host.split('.')[0]}",
        }
    zone_open = client["key"] == "school"
    zone = {
        f"ns1.{domain}": {"success": zone_open, **({"record_count": len(hosts), "records": [{"name": h, "type": "A", "value": ips[0]} for h in hosts[:30]]} if zone_open else {"error": "Transfer refused or failed"})},
        f"ns2.{domain}": {"success": False, "error": "Transfer refused or failed"},
    }
    ports = {}
    for ip in ips[:3]:
        table = ((22, "ssh"), (25, "smtp"), (80, "http"), (443, "https"), (445, "smb"), (3389, "rdp"), (8443, "https-alt"))
        ports[ip] = [{"port": p, "service": s, "status": rng.choice(("open", "open", "closed", "filtered"))} for p, s in table]
    paths = (("/admin/", 401, ""), ("/.git/config", 200, ""), ("/login", 200, ""), ("/backup/", 403, ""), ("/old", 301, "/archive/"), ("/phpinfo.php", 200, ""))
    dir_enum = {f"portal.{domain}": [{"path": p, "url": f"https://portal.{domain}{p}", "status_code": c, "content_length": str(rng.randint(180, 9000)), "redirect_to": r} for p, c, r in paths]}
    return {
        "domain": domain, "started_at": created.isoformat(), "completed_at": (created + timedelta(minutes=rng.randint(2, 9))).isoformat(),
        "dns_records": {
            "A": ips[:2], "MX": [f"10 mx1.{domain}", f"20 mx2.{domain}"], "NS": [f"ns1.{domain}", f"ns2.{domain}"],
            "TXT": [f"site-verification={_hex(rng, 32)}"], "SOA": [f"ns1.{domain} hostmaster.{domain} 2026100101 7200 3600 1209600 300"],
        },
        "zone_transfer": zone, "subdomains_passive": passive, "subdomains_resolved": resolved, "subdomains_bruteforce": bruteforce,
        "email_security": _email_security(domain, client["email_policy"], ips[0]), "ip_geo": geo, "geo_source": "demo data",
        "ptr_records": {ip: f"host-{ip.replace('.', '-')}.{domain}" for ip in ips[:2]}, "services": services, "port_scan": ports, "dir_enum": dir_enum,
        "errors": [], "subdomain_count": len(hosts), "resolved_count": len(resolved),
    }


def _write_dns(db, rng: random.Random, now: datetime) -> None:
    for client in CLIENTS:
        created = _when(rng, now, SPREAD_DAYS - 1)
        result = _dns_result(rng, client, created)
        email = result["email_security"]
        db.add(DNSInvestigation(
            domain=client["domain"], created_at=created, status="complete", result_json=json.dumps(result),
            subdomain_count=result["subdomain_count"], resolved_count=result["resolved_count"],
            zone_transfer_success=any(v.get("success") for v in result["zone_transfer"].values()),
            has_spf=email["spf_valid"], has_dmarc=email["dmarc_valid"],
        ))
    db.commit()


def _write_quick_scans(db, rng: random.Random, now: datetime, posts: list[dict], owner_id: int) -> None:
    urgent = {"credentials", "ransomware", "patient_db", "stealer", "vpn_access", "rdp_access"}
    for i, client in enumerate(CLIENTS + CLIENTS[:2]):
        target, target_type = (client["domain"], "domain") if i % 2 == 0 else (client["name"], "company_name")
        started = _when(rng, now, SPREAD_DAYS - 1)
        mine = [p for p in posts if p["client"] is client]
        found = rng.sample(mine, k=min(len(mine), rng.randint(6, 14)))
        record = QuickScanSession(
            user_id=owner_id, target_value=target, target_type=target_type,
            normalized_variants=json.dumps([client["name"], client["domain"], client["brand"]]),
            sources_used=json.dumps([name for name, _ in SITES]), status="completed", started_at=started,
            completed_at=started + timedelta(minutes=rng.randint(3, 14)), urls_visited=rng.randint(30, 120), findings_count=len(found),
        )
        db.add(record)
        db.flush()
        for post in found:
            site = post["context"].split("]")[0].lstrip("[") if post["context"].startswith("[") else SITES[0][0]
            db.add(QuickScanFinding(
                session_id=record.id, source_name=site if site in dict(SITES) else SITES[0][0], url=post["url"],
                matched_variant=next((k for k in _client_keywords(client) if k in post["context"]), client["name"]),
                context=post["context"], high_signal=post["kind"] in urgent, found_at=started + timedelta(seconds=rng.randint(20, 170)),
            ))
    db.commit()


def _write_custom_intel(db, rng: random.Random, now: datetime, onions: dict) -> None:
    names = {c["key"]: c["name"] for c in CLIENTS}
    for group in GROUPS:
        entry = {
            "name": group["name"], "slug": group["slug"], "status": group["status"], "origin": group["origin"],
            "first_seen": group["first_seen"], "targeting_sea": True, "risk_level": group["risk_level"],
            "description": group["description"], "ttps": group["ttps"], "keywords": [group["keyword"]],
            "onion_seeds": [f"http://{onions['Pugad Leaks']}/{group['slug']}"], "sea_victims": [names[k] for k in group["victims"]],
        }
        db.add(CustomIntel(intel_type="ransomware", slug=group["slug"], data=json.dumps(entry), created_by="demo-seed", created_at=_when(rng, now, SPREAD_DAYS - 1)))
    for actor in ACTORS:
        entry = {
            "name": actor["name"], "slug": actor["slug"], "type": actor["type"], "status": actor["status"], "origin": actor["origin"],
            "first_seen": actor["first_seen"], "targeting_sea": True, "risk_level": actor["risk_level"], "description": actor["description"],
            "aliases": actor["aliases"], "sectors": actor["sectors"], "countries_targeted": ["Philippines"], "ttps": actor["ttps"],
            "known_malware": actor["known_malware"], "keywords": [actor["keyword"]],
        }
        db.add(CustomIntel(intel_type="threat-actor", slug=actor["slug"], data=json.dumps(entry), created_by="demo-seed", created_at=_when(rng, now, SPREAD_DAYS - 1)))
    db.commit()


def crtsh_entries(storage: Storage, domain: str) -> list[dict]:
    """The certificates seeded for ``domain``, in the form crt.sh answers with."""
    with storage._SessionFactory() as db:
        record = (
            db.query(DNSInvestigation)
            .filter(DNSInvestigation.domain == domain)
            .order_by(DNSInvestigation.created_at.desc())
            .first()
        )
        result = json.loads(record.result_json or "{}") if record else {}
    return [
        {
            "id": cert["cert_id"],
            "serial_number": hashlib.sha256(str(cert["cert_id"]).encode()).hexdigest()[:32],
            "issuer_name": cert["issuer"],
            "not_before": cert["not_before"],
            "not_after": cert["not_after"],
            "name_value": f"{cert['subdomain']}\n{domain}",
        }
        for cert in result.get("subdomains_passive", [])
    ]


def write_files(data_dir: Path, onions: dict) -> None:
    """The Keywords and Seeds tabs read files, not the database."""
    data_dir.mkdir(parents=True, exist_ok=True)
    keywords = {
        "brand_monitoring": [word for client in CLIENTS for word in _client_keywords(client)],
        "threat_intel": sorted({spec[2] for spec in KINDS.values() if spec[2]}),
        "tracked_groups": [g["keyword"] for g in GROUPS] + [a["keyword"] for a in ACTORS],
    }
    (data_dir / "keywords.yaml").write_text(yaml.safe_dump({"keywords": keywords}, sort_keys=False))
    (data_dir / "seeds.txt").write_text("".join(f"http://{onion}/\n" for onion in onions.values()))


def seed(storage: Storage, now: Optional[datetime] = None) -> tuple[dict, dict]:
    """Replace the demo data. Returns (row counts, onion address of each site)."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    rng = random.Random(20261109)  # the same data each run; only the dates move
    onions = {name: _onion(rng) for name, _ in SITES}
    posts = _hits(rng, onions)
    sessions = _sessions(rng, now, posts, onions)

    with storage._SessionFactory() as db:
        _wipe(db)
        first_admin = db.query(User).filter(User.is_admin.is_(True)).order_by(User.id).first()
        # With no user yet: id 1 is the one the first account will get.
        owner_id = first_admin.id if first_admin else 1
        analysts = _write_analysts(db, rng, now) if first_admin else 0
        _write_crawls(db, rng, sessions, onions)
        _write_projects(db, rng, now, posts, owner_id)
        _write_investigations(db, storage, rng, now)
        _write_ip_lookups(db, rng, now)
        _write_dns(db, rng, now)
        _write_quick_scans(db, rng, now, posts, owner_id)
        _write_custom_intel(db, rng, now, onions)
    return (
        {"sessions": len(sessions), "hits": len(posts), "projects": len(CLIENTS), "analysts": analysts, "admin_exists": bool(first_admin)},
        onions,
    )


def main() -> int:
    database_url = os.getenv("DATABASE_URL", "")
    reason = refuse_reason(database_url, os.environ)
    if reason:
        print(f"demo-seed refused: {reason}", file=sys.stderr)
        return 2
    storage = Storage(database_url)
    with storage.engine.connect() as connection:
        connected_to = connection.execute(text("SELECT current_database()")).scalar()
    if connected_to != DEMO_DB_NAME:
        print(f"demo-seed refused: connected to {connected_to}, not {DEMO_DB_NAME}.", file=sys.stderr)
        return 2

    summary, onions = seed(storage)
    write_files(Path(os.getenv("DATA_DIR", "/app/data")), onions)
    print(f"Demo data written: {summary['sessions']} crawl sessions, {summary['hits']} hits, {summary['projects']} projects, {summary['analysts']} analysts.")
    if not summary["admin_exists"]:
        print("No administrator yet. Create one at /register, then run make demo-seed again to add the analysts and hand over Quick Scan.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

