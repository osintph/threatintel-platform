"""The demo seed: never the production database, always fiction, every row has a detail view."""

import base64
import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timedelta, timezone

import pytest

from darkweb_scanner import demo_seed
from darkweb_scanner.ransomware_data import RANSOMWARE_GROUPS
from darkweb_scanner.storage import (
    AuthEvent,
    CrawlSession,
    CustomIntel,
    DNSInvestigation,
    InvestigationTarget,
    IPInvestigation,
    KeywordHitRecord,
    Project,
    ProjectHit,
    QuickScanFinding,
    QuickScanSession,
    Storage,
    User,
)
from darkweb_scanner.threat_actors import THREAT_ACTORS

DEMO_URL = "postgresql+psycopg2://scanner_demo:pw@demo-postgres:5432/darkweb_scanner_demo"
NOW = datetime(2026, 11, 9, 12, 0, 0)
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@pytest.mark.parametrize(
    "url,env",
    [
        (DEMO_URL, {}),
        (DEMO_URL, {"DEMO_MODE": "0"}),
        ("", {"DEMO_MODE": "1"}),
        ("not a url", {"DEMO_MODE": "1"}),
        ("postgresql+psycopg2://scanner:pw@postgres:5432/darkweb_scanner", {"DEMO_MODE": "1"}),
        ("postgresql+psycopg2://scanner:pw@postgres:5432/darkweb_scanner_demo", {"DEMO_MODE": "1"}),
        ("postgresql+psycopg2://scanner:pw@demo-postgres:5432/darkweb_scanner", {"DEMO_MODE": "1"}),
        ("sqlite:///results.db", {"DEMO_MODE": "1"}),
    ],
)
def test_refuses_anything_but_the_demo_database(url, env):
    assert demo_seed.refuse_reason(url, env)


def test_accepts_the_demo_database():
    assert demo_seed.refuse_reason(DEMO_URL, {"DEMO_MODE": "1"}) is None


def test_main_refuses_production_before_connecting(monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://scanner:pw@postgres:5432/darkweb_scanner")
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setattr(demo_seed, "Storage", lambda *_: pytest.fail("connected to the database"))
    assert demo_seed.main() == 2
    assert "refused" in capsys.readouterr().err


@pytest.fixture
def storage(tmp_path):
    return Storage(f"sqlite:///{tmp_path / 'demo.db'}")


def rows(storage, model):
    with storage._SessionFactory() as db:
        return db.query(model).all()


def add_admin(storage):
    return storage.create_user(username="firstadmin", password_hash="x", is_admin=True)


def everything(storage):
    """All text the seed wrote, as one string."""
    parts = [(h.url, h.keyword, h.context) for h in rows(storage, KeywordHitRecord)]
    parts += [(s.seed_urls,) for s in rows(storage, CrawlSession)]
    parts += [(t.value, t.breaches, t.darkweb_hits) for t in rows(storage, InvestigationTarget)]
    parts += [(i.ip, i.abuseipdb_data, i.virustotal_data) for i in rows(storage, IPInvestigation)]
    parts += [(d.domain, d.result_json) for d in rows(storage, DNSInvestigation)]
    parts += [(f.url, f.context) for f in rows(storage, QuickScanFinding)]
    parts += [(c.data,) for c in rows(storage, CustomIntel)]
    return "\n".join(str(p) for group in parts for p in group)


def test_counts_and_dates(storage):
    add_admin(storage)
    demo_seed.seed(storage, NOW)
    sessions = rows(storage, CrawlSession)
    hits = rows(storage, KeywordHitRecord)
    assert len(sessions) == 25
    assert len(hits) == 300
    oldest = NOW - timedelta(days=90)
    assert all(oldest <= h.found_at <= NOW for h in hits)
    assert all(oldest <= s.started_at <= NOW for s in sessions)
    assert min(s.started_at for s in sessions) < NOW - timedelta(days=80)
    assert max(s.started_at for s in sessions) > NOW - timedelta(days=2)
    for s in sessions:
        assert s.hits_found == len([h for h in hits if h.session_id == s.id])
        assert s.hits_found > 0
        assert s.status != "running"


def test_every_post_type_is_present(storage):
    demo_seed.seed(storage, NOW)
    text = everything(storage)
    for needle in ("Time until publication", "patient database", "Salot Stealer logs", "4***-****", "Looking for an insider", "CLAIM:", "VPN access", "combo list"):
        assert needle in text, needle
    assert "/finance/" in text


def test_no_users_are_created_before_the_first_admin(storage):
    summary, _ = demo_seed.seed(storage, NOW)
    assert storage.count_users() == 0  # /register stays open
    assert summary["analysts"] == 0
    assert all(s.user_id == 1 for s in rows(storage, QuickScanSession))


def test_second_run_adds_analysts_and_hands_quick_scan_to_the_admin(storage):
    demo_seed.seed(storage, NOW)
    admin = add_admin(storage)
    summary, _ = demo_seed.seed(storage, NOW)
    assert summary["analysts"] == len(demo_seed.ANALYSTS)
    assert storage.get_user_by_id(admin) is not None
    assert all(s.user_id == admin for s in rows(storage, QuickScanSession))
    assert all(p.owner_id == admin for p in rows(storage, Project))
    assert len(rows(storage, KeywordHitRecord)) == 300  # replaced, not added to
    assert len(rows(storage, AuthEvent)) > 20
    assert all(u.last_login for u in rows(storage, User) if u.id != admin)


def test_analysts_cannot_sign_in_with_a_known_password(storage):
    add_admin(storage)
    demo_seed.seed(storage, NOW)
    hashes = {u.password_hash for u in rows(storage, User) if u.username.startswith(("analyst", "lead"))}
    assert len(hashes) == len(demo_seed.ANALYSTS)
    assert all(h.startswith("$2") for h in hashes)


def test_projects_have_data_and_hits(storage):
    add_admin(storage)
    demo_seed.seed(storage, NOW)
    projects = storage.list_projects()
    assert len(projects) == 6
    for p in projects:
        stats = storage.get_project_stats(p["id"])
        assert stats["total_hits"] > 0 and stats["top_keywords"]
        assert storage.get_project_hits(p["id"])
    assert len(rows(storage, ProjectHit)) >= 300


def test_detail_views_are_populated(storage):
    add_admin(storage)
    demo_seed.seed(storage, NOW)
    investigations = storage.get_investigations(limit=50)
    assert len(investigations) >= 8
    targets = rows(storage, InvestigationTarget)
    assert any(t.breach_count > 0 for t in targets) and any(t.darkweb_count > 0 for t in targets)
    for ip in storage.get_ip_investigations():
        full = storage.get_ip_investigation(ip["id"])
        assert full["abuseipdb"]["ip"] == full["ip"] == full["virustotal"]["ip"]
    assert len(rows(storage, DNSInvestigation)) == 6
    for dns in rows(storage, DNSInvestigation):
        result = json.loads(dns.result_json)
        for key in ("dns_records", "subdomains_resolved", "subdomains_bruteforce", "subdomains_passive", "port_scan", "dir_enum", "email_security", "services"):
            assert result[key], key
    assert any(not d.has_dmarc for d in rows(storage, DNSInvestigation)) and any(d.has_dmarc for d in rows(storage, DNSInvestigation))
    for session in rows(storage, QuickScanSession):
        assert session.findings_count == len(storage.list_quick_scan_findings(session.id)) > 0
    assert any(f.high_signal for f in rows(storage, QuickScanFinding))


def test_fiction_network_identifiers(storage):
    add_admin(storage)
    demo_seed.seed(storage, NOW)
    text = everything(storage)
    for quad in set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)):
        assert any(ipaddress.ip_address(quad) in net for net in DOC_NETS), quad
    onions = set(re.findall(r"\b[a-z2-7]+\.onion\b", text))
    assert onions
    for onion in onions:
        raw = base64.b32decode(onion[:-6].upper())
        assert len(raw) == 35 and raw[-1] == 3
        assert raw[32:34] == hashlib.sha3_256(b".onion checksum" + raw[:32] + b"\x03").digest()[:2]
    for domain in set(re.findall(r"@([a-z0-9.-]+\.[a-z]{2,})", text)):
        assert domain.endswith(".example"), domain
    for url_host in set(re.findall(r"https?://([a-z0-9.-]+)", text)):
        assert url_host.endswith((".example", ".onion")), url_host


def test_passwords_are_masked(storage):
    add_admin(storage)
    demo_seed.seed(storage, NOW)
    for hit in rows(storage, KeywordHitRecord):
        for line in hit.context.splitlines():
            for _, password in re.findall(r"([\w.]+@[\w.-]+):(\S+)", line):
                assert re.fullmatch(r"[A-Za-z]{2}\*{4}\d{2}", password), line
            if line.startswith("PASS:"):
                assert re.fullmatch(r"PASS: [A-Za-z]{2}\*{4}\d{2}", line), line


def test_real_groups_get_no_hits_and_are_not_named(storage):
    add_admin(storage)
    demo_seed.seed(storage, NOW)
    real_keywords = {k.lower() for entry in list(RANSOMWARE_GROUPS) + list(THREAT_ACTORS) for k in entry.get("keywords", [])}
    hits = rows(storage, KeywordHitRecord)
    assert not {h.keyword.lower() for h in hits} & real_keywords
    real_names = {entry["name"].lower() for entry in list(RANSOMWARE_GROUPS) + list(THREAT_ACTORS)}
    for hit in hits:
        context = hit.context.lower()
        assert not [n for n in real_names if re.search(rf"\b{re.escape(n)}\b", context)], hit.context
    custom = {c.slug for c in rows(storage, CustomIntel)}
    assert not custom & {entry["slug"] for entry in list(RANSOMWARE_GROUPS) + list(THREAT_ACTORS)}


def test_every_custom_group_and_actor_has_hits(storage):
    demo_seed.seed(storage, NOW)
    found = {h.keyword for h in rows(storage, KeywordHitRecord)}
    for entry in demo_seed.GROUPS + demo_seed.ACTORS:
        assert entry["keyword"] in found, entry["name"]


def test_keyword_appears_in_its_hit(storage):
    demo_seed.seed(storage, NOW)
    for hit in rows(storage, KeywordHitRecord):
        assert hit.keyword.lower() in hit.context.lower(), hit.keyword


def test_write_files(tmp_path):
    demo_seed.write_files(tmp_path, {"Kubli Forum": "abc.onion"})
    assert "http://abc.onion/" in (tmp_path / "seeds.txt").read_text()
    assert "brand_monitoring" in (tmp_path / "keywords.yaml").read_text()


def test_seed_uses_the_current_time_by_default(storage):
    before = datetime.now(timezone.utc).replace(tzinfo=None)
    demo_seed.seed(storage)
    assert max(h.found_at for h in rows(storage, KeywordHitRecord)) > before - timedelta(days=2)


# ── Certificate history: seeded in demo mode only ─────────────────────────────


@pytest.fixture
def signed_in(storage, monkeypatch, tmp_path):
    from darkweb_scanner.dashboard import storage_helper
    from darkweb_scanner.dashboard.app import create_app

    monkeypatch.setenv("DASHBOARD_SECRET_KEY", "x" * 40)
    monkeypatch.setenv("DASHBOARD_ALLOW_HTTP", "1")
    monkeypatch.setattr(storage_helper, "_storage", storage)
    admin = add_admin(storage)
    storage.enable_totp(admin, "JBSWY3DPEHPK3PXP")
    demo_seed.seed(storage, NOW)
    client = create_app().test_client()
    with client.session_transaction() as s:
        s.update(user_id=admin, username="firstadmin", sv=storage.ensure_session_version(admin), iat=int(time.time()))
    return client


DOMAIN = demo_seed.CLIENTS[0]["domain"]


def live_lookups(monkeypatch):
    from darkweb_scanner.dashboard import dashboard_routes

    calls = []

    def fake(key, url, **kwargs):
        calls.append(url)
        return {"status": 200, "body": b"[]"}

    monkeypatch.setattr(dashboard_routes, "_cached_fetch", fake)
    return calls


def test_demo_mode_serves_seeded_certificates_without_crtsh(signed_in, monkeypatch):
    calls = live_lookups(monkeypatch)
    monkeypatch.setenv("DEMO_MODE", "1")
    data = signed_in.get(f"/api/dns/certs/{DOMAIN}").get_json()
    assert not calls
    assert data["total"] > 0 and data["certs"] and data["issuers"]
    assert f"www.{DOMAIN}" in data["all_sans"]
    assert all(c["not_before_ts"] and c["serial"] and c["issuer_org"] for c in data["certs"])
    assert data["total"] == data["active"] + data["expired"]


def test_without_demo_mode_the_lookup_stays_live(signed_in, monkeypatch):
    calls = live_lookups(monkeypatch)
    monkeypatch.delenv("DEMO_MODE", raising=False)
    data = signed_in.get(f"/api/dns/certs/{DOMAIN}").get_json()
    assert len(calls) == 1 and "crt.sh" in calls[0]
    assert data["total"] == 0


def test_demo_mode_keeps_the_live_lookup_for_other_domains(signed_in, monkeypatch):
    calls = live_lookups(monkeypatch)
    monkeypatch.setenv("DEMO_MODE", "1")
    signed_in.get("/api/dns/certs/osintph.info")
    assert len(calls) == 1


def test_demo_mode_unknown_example_domain_is_empty(signed_in, monkeypatch):
    calls = live_lookups(monkeypatch)
    monkeypatch.setenv("DEMO_MODE", "1")
    data = signed_in.get("/api/dns/certs/nobody.example").get_json()
    assert not calls and data["total"] == 0
