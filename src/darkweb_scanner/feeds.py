"""
Threat intelligence feed aggregator.
Pulls from OTX, CISA KEV, RSS sources, and abuse.ch feeds.
API keys are read from environment — never hardcoded.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
import requests

logger = logging.getLogger(__name__)

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
REQUEST_TIMEOUT = 15

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


def _safe_get(url: str, headers: dict = None, params: dict = None, timeout: int = REQUEST_TIMEOUT) -> Optional[dict]:
    try:
        r = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning(f"Feed fetch failed {url}: {e}")
        return None


# ── OTX AlienVault ─────────────────────────────────────────────────────────────

def fetch_otx_pulses(limit: int = 20) -> list[dict]:
    """Fetch recent OTX threat pulses, prioritising SEA-relevant ones."""
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set — skipping OTX feed")
        return []

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    results = []

    # Subscribed feed (personalised to account tags)
    data = _safe_get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers=headers,
        params={"limit": 50, "modified_since": (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2)).strftime("%Y-%m-%dT00:00:00")},
    )
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
                "url": f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
                "published": p.get("modified", ""),
                "sea_relevant": _is_sea_relevant(
                    p.get("name", "") + " " + p.get("description", "") + " " + " ".join(p.get("targeted_countries", []))
                ),
            })

    # Also fetch SEA-specific search
    sea_data = _safe_get(
        "https://otx.alienvault.com/api/v1/search/pulses",
        headers=headers,
        params={"q": "Philippines OR Indonesia OR Malaysia OR Thailand OR Vietnam OR ASEAN", "limit": 20},
    )
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
                    "url": f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
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
        f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators",
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

def fetch_cisa_kev(days_back: int = 7) -> list[dict]:
    """Fetch recent CISA Known Exploited Vulnerabilities."""
    data = _safe_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
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
                "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID', '')}",
            })
    results.sort(key=lambda x: x["added"], reverse=True)
    return results[:15]


# ── Abuse.ch feeds ─────────────────────────────────────────────────────────────

def fetch_urlhaus_recent(limit: int = 10) -> list[dict]:
    """Fetch recent malicious URLs from URLhaus."""
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": 100},
            timeout=REQUEST_TIMEOUT,
        )
        data = r.json()
    except Exception as e:
        logger.warning(f"URLhaus fetch failed: {e}")
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


def fetch_feodo_c2s(limit: int = 10) -> list[dict]:
    """Fetch recent Feodo Tracker C2 botnet IPs."""
    data = _safe_get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
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


def fetch_rss_items(days_back: int = 1, limit_per_source: int = 5) -> list[dict]:
    """Fetch recent items from cybersecurity RSS feeds."""
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        return []

    all_items = []

    for source in RSS_SOURCES:
        try:
            r = requests.get(source["url"], timeout=REQUEST_TIMEOUT,
                             headers={"User-Agent": "OSINTPH-ThreatFeed/1.0"})
            root = ET.fromstring(r.content)

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
    """Fetch all feeds and return structured data for digest building."""
    logger.info("Fetching all threat intel feeds…")
    return {
        "otx_pulses": fetch_otx_pulses(limit=15),
        "cisa_kev": fetch_cisa_kev(days_back=7),
        "urlhaus": fetch_urlhaus_recent(limit=8),
        "feodo": fetch_feodo_c2s(limit=8),
        "rss": fetch_rss_items(days_back=1, limit_per_source=4),
        "fetched_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }
