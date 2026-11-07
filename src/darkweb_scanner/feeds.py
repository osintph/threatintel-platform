"""
Threat intelligence feed aggregator.
Pulls from OTX, CISA KEV, RSS sources, and abuse.ch feeds.
API keys are read from environment — never hardcoded.

Each upstream request is one cached fetch (UPSTREAM_CACHE_SECONDS, default
300; the last good answer is served when a source is down). fetch_all_feeds()
runs all of them side by side on the shared pool with one time limit, so a
digest preview costs about as long as the slowest source, not the sum.

The API requests go through safe_fetch(): HTTPS, listed hosts, and no redirect
ever carries the OTX key to another host. RSS feeds are public files on hosts
that move them around, so they are fetched with fetch_public_redirects():
no key, HTTPS only, every hop checked.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote, urlencode

from .dashboard import jobs
from .dashboard.http_client import fetch_public_redirects, safe_fetch
from .dashboard.upstream_cache import TTLCache, default_ttl

logger = logging.getLogger(__name__)

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
REQUEST_TIMEOUT = 15
# For fetch_all_feeds(): every source, side by side.
ALL_FEEDS_TIMEOUT = 45
JSON_MAX_BYTES = 16 * 1024 * 1024
RSS_MAX_BYTES = 4 * 1024 * 1024

_cache = TTLCache("feeds", ttl=default_ttl(), max_entries=64, wait_timeout=20)


class FeedError(Exception):
    """A source did not give a usable answer."""

SEA_COUNTRIES = ["philippines", "thailand", "indonesia", "malaysia", "vietnam",
                  "singapore", "myanmar", "cambodia", "laos", "brunei"]
SEA_KEYWORDS = SEA_COUNTRIES + [
    "ph ", "phl", "asean", "sea ", "south east asia", "southeast asia",
    "manila", "jakarta", "bangkok", "kuala lumpur", "phcert", "cert-ph",
    "lockbit", "ransomhub", "dragonforce", "akira", "apt40", "apt41",
    "mustang panda", "lazarus", "volt typhoon", "earth lusca",
]


def _is_sea_relevant(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in SEA_KEYWORDS)


def _safe_get(url: str, headers: dict = None, params: dict = None, timeout: int = REQUEST_TIMEOUT,
              follow: bool = False) -> Optional[dict]:
    """GET JSON from a listed host, through the cache. None when the source gives no answer.

    ``follow`` is for sources without a key: safe_fetch() then follows a
    redirect, but only to a listed host and without the caller's headers.
    """
    if params:
        url = f"{url}?{urlencode(params)}"

    def fetch():
        result = safe_fetch(url, headers=headers or {}, timeout=timeout,
                            allow_redirects=follow, max_bytes=JSON_MAX_BYTES)
        if result["status"] != 200:
            raise FeedError(f"HTTP {result['status']} for {url}")
        return json.loads(result["body"])

    return _cache.get(("GET", url), fetch)


# ── OTX AlienVault ─────────────────────────────────────────────────────────────

def _otx_subscribed() -> Optional[dict]:
    """Subscribed feed (personalised to account tags)."""
    if not OTX_API_KEY:
        return None
    return _safe_get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        params={"limit": 50, "modified_since": (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2)).strftime("%Y-%m-%dT00:00:00")},
    )


def _otx_sea_search() -> Optional[dict]:
    """SEA-specific search."""
    if not OTX_API_KEY:
        return None
    return _safe_get(
        "https://otx.alienvault.com/api/v1/search/pulses",
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        params={"q": "Philippines OR Indonesia OR Malaysia OR Thailand OR Vietnam OR ASEAN", "limit": 20},
    )


def fetch_otx_pulses(limit: int = 20) -> list[dict]:
    """Fetch recent OTX threat pulses, prioritising SEA-relevant ones."""
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set — skipping OTX feed")
        return []
    got = jobs.call_all({"subscribed": _otx_subscribed, "sea": _otx_sea_search}, timeout=2 * REQUEST_TIMEOUT)
    return _build_otx_pulses(got["subscribed"], got["sea"], limit)


def _build_otx_pulses(data: Optional[dict], sea_data: Optional[dict], limit: int) -> list[dict]:
    results = []

    if data:
        for p in data.get("results", []):
            results.append({
                "source": "AlienVault OTX",
                "title": p.get("name", ""),
                "description": (p.get("description") or "")[:400],
                "tags": p.get("tags", []),
                "tlp": p.get("tlp", "white"),
                "industries": p.get("industries", []),
                "targeted_countries": p.get("targeted_countries", []),
                "ioc_count": p.get("indicators_count", 0),
                "author": p.get("author", {}).get("username", ""),
                "url": f"https://otx.alienvault.com/pulse/{quote(str(p.get('id', '')), safe='')}",
                "published": p.get("modified", ""),
                "sea_relevant": _is_sea_relevant(
                    p.get("name", "") + " " + p.get("description", "") + " " + " ".join(p.get("targeted_countries", []))
                ),
            })

    if sea_data:
        existing_titles = {r["title"] for r in results}
        for p in sea_data.get("results", []):
            if p.get("name") not in existing_titles:
                results.append({
                    "source": "AlienVault OTX",
                    "title": p.get("name", ""),
                    "description": (p.get("description") or "")[:400],
                    "tags": p.get("tags", []),
                    "tlp": p.get("tlp", "white"),
                    "industries": p.get("industries", []),
                    "targeted_countries": p.get("targeted_countries", []),
                    "ioc_count": p.get("indicators_count", 0),
                    "author": p.get("author", {}).get("username", ""),
                    "url": f"https://otx.alienvault.com/pulse/{quote(str(p.get('id', '')), safe='')}",
                    "published": p.get("modified", ""),
                    "sea_relevant": True,
                })

    # Sort: SEA-relevant first, then by date
    results.sort(key=lambda x: (not x["sea_relevant"], x["published"]), reverse=False)
    results.sort(key=lambda x: not x["sea_relevant"])
    return results[:limit]


def fetch_otx_iocs(pulse_id: str) -> list[dict]:
    """Fetch IOCs for a specific OTX pulse."""
    if not OTX_API_KEY:
        return []
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    data = _safe_get(
        f"https://otx.alienvault.com/api/v1/pulses/{quote(str(pulse_id), safe='')}/indicators",
        headers=headers,
        params={"limit": 50},
    )
    if not data:
        return []
    return [
        {"type": i.get("type"), "value": i.get("indicator"), "description": i.get("description", "")}
        for i in data.get("results", [])
    ]


# ── CISA KEV ──────────────────────────────────────────────────────────────────

def _cisa_kev() -> Optional[dict]:
    return _safe_get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", follow=True
    )


def fetch_cisa_kev(days_back: int = 7) -> list[dict]:
    """Fetch recent CISA Known Exploited Vulnerabilities."""
    return _build_cisa_kev(_cisa_kev(), days_back)


def _build_cisa_kev(data: Optional[dict], days_back: int) -> list[dict]:
    if not data:
        return []
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)
    results = []
    for v in data.get("vulnerabilities", []):
        try:
            added = datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d")
        except Exception:
            continue
        if added >= cutoff:
            results.append({
                "source": "CISA KEV",
                "cve": v.get("cveID", ""),
                "title": v.get("vulnerabilityName", ""),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "description": v.get("shortDescription", "")[:300],
                "action": v.get("requiredAction", ""),
                "due_date": v.get("dueDate", ""),
                "added": v.get("dateAdded", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{quote(str(v.get('cveID', '')), safe='')}",
            })
    results.sort(key=lambda x: x["added"], reverse=True)
    return results[:15]


# ── Abuse.ch feeds ─────────────────────────────────────────────────────────────

def _urlhaus_recent() -> Optional[dict]:
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    body = urlencode({"limit": 100}).encode()

    def fetch():
        result = safe_fetch(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=body,
            timeout=REQUEST_TIMEOUT,
            max_bytes=JSON_MAX_BYTES,
        )
        if result["status"] != 200:
            raise FeedError(f"HTTP {result['status']} for {url}")
        return json.loads(result["body"])

    return _cache.get(("POST", url, body), fetch)


def fetch_urlhaus_recent(limit: int = 10) -> list[dict]:
    """Fetch recent malicious URLs from URLhaus."""
    return _build_urlhaus(_urlhaus_recent(), limit)


def _build_urlhaus(data: Optional[dict], limit: int) -> list[dict]:
    if not isinstance(data, dict):
        return []

    results = []
    for u in data.get("urls", []):
        tags = u.get("tags") or []
        tag_str = " ".join(tags).lower()
        host = (u.get("host") or "").lower()
        results.append({
            "source": "URLhaus",
            "url": u.get("url", ""),
            "host": u.get("host", ""),
            "status": u.get("url_status", ""),
            "threat": u.get("threat", ""),
            "tags": tags,
            "added": u.get("date_added", ""),
            "sea_relevant": _is_sea_relevant(tag_str + " " + host),
        })

    # Prioritise SEA-relevant
    results.sort(key=lambda x: not x["sea_relevant"])
    return results[:limit]


def _feodo_blocklist():
    return _safe_get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")


def fetch_feodo_c2s(limit: int = 10) -> list[dict]:
    """Fetch recent Feodo Tracker C2 botnet IPs."""
    return _build_feodo(_feodo_blocklist(), limit)


def _build_feodo(data, limit: int) -> list[dict]:
    if not data:
        return []
    results = []
    for entry in (data if isinstance(data, list) else [])[:limit]:
        results.append({
            "source": "Feodo Tracker",
            "ip": entry.get("ip_address", ""),
            "port": entry.get("port", ""),
            "malware": entry.get("malware", ""),
            "country": entry.get("country", ""),
            "first_seen": entry.get("first_seen", ""),
            "last_online": entry.get("last_online", ""),
            "sea_relevant": entry.get("country", "").upper() in ["PH", "TH", "ID", "MY", "VN", "SG", "MM"],
        })
    return results


# ── RSS feeds ──────────────────────────────────────────────────────────────────

RSS_SOURCES = [
    {"name": "Bleeping Computer", "url": "https://www.bleepingcomputer.com/feed/", "priority": "high"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "priority": "high"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "priority": "medium"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "priority": "high"},
    {"name": "Recorded Future Blog", "url": "https://www.recordedfuture.com/feed", "priority": "medium"},
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "priority": "critical"},
    {"name": "Security Online", "url": "https://securityonline.info/feed/", "priority": "high"},
    {"name": "Cyber Security News", "url": "https://cybersecuritynews.com/feed/", "priority": "high"},
    {"name": "The Cyber Express", "url": "https://thecyberexpress.com/feed/", "priority": "medium"},
    {"name": "Ransomware.live", "url": "https://www.ransomware.live/feed.xml", "priority": "critical"},
    {"name": "Threatpost", "url": "https://threatpost.com/feed/", "priority": "medium"},
    {"name": "Schneier on Security", "url": "https://www.schneier.com/feed/atom/", "priority": "medium"},
    {"name": "NVD CVE Recent", "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz", "priority": "high"},
    {"name": "Google Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "priority": "medium"},
    {"name": "Mandiant Blog", "url": "https://www.mandiant.com/resources/blog/rss.xml", "priority": "high"},
]


def _rss_bytes(source: dict) -> Optional[bytes]:
    """The body of one RSS source, through the cache. None when the source gives no answer."""
    url = source["url"]

    def fetch():
        result = fetch_public_redirects(
            url,
            headers={"User-Agent": "OSINTPH-ThreatFeed/1.0"},
            timeout=REQUEST_TIMEOUT,
            max_bytes=RSS_MAX_BYTES,
        )
        if result["status"] != 200:
            raise FeedError(f"HTTP {result['status']} for {url}")
        return result["body"]

    return _cache.get(("RSS", url), fetch)


def fetch_rss_items(days_back: int = 1, limit_per_source: int = 5) -> list[dict]:
    """Fetch recent items from cybersecurity RSS feeds."""
    bodies = jobs.fan_out(_rss_bytes, RSS_SOURCES, parallel=8, timeout=ALL_FEEDS_TIMEOUT)
    return _build_rss_items(bodies, limit_per_source)


def _build_rss_items(bodies: list, limit_per_source: int) -> list[dict]:
    """Items from the fetched bodies, one per entry of RSS_SOURCES (None: not fetched)."""
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        return []

    all_items = []

    for source, content in zip(RSS_SOURCES, bodies):
        if not content:
            continue
        try:
            root = ET.fromstring(content)

            ns = ""
            items = root.findall(".//item")
            if not items:
                items = root.findall(".//{http://www.w3.org/2005/Atom}entry")
                ns = "{http://www.w3.org/2005/Atom}"

            count = 0
            for item in items:
                if count >= limit_per_source:
                    break

                title_el = item.find(f"{ns}title")
                link_el = item.find(f"{ns}link") or item.find(f"{ns}id")
                desc_el = item.find(f"{ns}description") or item.find(f"{ns}summary")

                title = (title_el.text or "") if title_el is not None else ""
                link = (link_el.text or link_el.get("href", "")) if link_el is not None else ""
                desc = (desc_el.text or "") if desc_el is not None else ""
                # Strip HTML tags from description
                import re
                desc = re.sub(r"<[^>]+>", "", desc)[:400]

                sea_rel = _is_sea_relevant(title + " " + desc)

                all_items.append({
                    "source": source["name"],
                    "priority": source["priority"],
                    "title": title.strip(),
                    "url": link.strip(),
                    "description": desc.strip(),
                    "sea_relevant": sea_rel,
                })
                count += 1

        except Exception as e:
            logger.warning(f"RSS fetch failed for {source['name']}: {e}")
            continue

    # Sort: SEA-relevant + critical priority first
    priority_order = {"critical": 0, "high": 1, "medium": 2}
    all_items.sort(key=lambda x: (not x["sea_relevant"], priority_order.get(x["priority"], 3)))
    return all_items


# ── Master fetch ───────────────────────────────────────────────────────────────

def fetch_all_feeds() -> dict:
    """Fetch all feeds and return structured data for digest building.

    Every source is one entry of one fan-out, with ALL_FEEDS_TIMEOUT for the
    lot: a source that is slow or down leaves its section short, it does not
    hold up the others.
    """
    logger.info("Fetching all threat intel feeds…")
    calls = [_otx_subscribed, _otx_sea_search, _cisa_kev, _urlhaus_recent, _feodo_blocklist]
    calls += [lambda source=source: _rss_bytes(source) for source in RSS_SOURCES]
    got = jobs.fan_out(lambda call: call(), calls, parallel=10, timeout=ALL_FEEDS_TIMEOUT)
    otx_subscribed, otx_sea, kev, urlhaus, feodo = got[:5]
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set — skipping OTX feed")
    return {
        "otx_pulses": _build_otx_pulses(otx_subscribed, otx_sea, limit=15),
        "cisa_kev": _build_cisa_kev(kev, days_back=7),
        "urlhaus": _build_urlhaus(urlhaus, limit=8),
        "feodo": _build_feodo(feodo, limit=8),
        "rss": _build_rss_items(got[5:], limit_per_source=4),
        "fetched_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }
