"""
ransomware_live.py — Ransomware.live PRO API client.
Place at: src/darkweb_scanner/ransomware_live.py

API key from: https://my.ransomware.live
Set in .env: RANSOMWARE_LIVE_API_KEY=your_key

Every request goes through safe_fetch(): HTTPS, the two API hosts only, no
redirects, so the key header is sent to the API host and nowhere else. Answers
are cached in the process (UPSTREAM_CACHE_SECONDS, default 300): the home page
asks for the same data on every load, and when the service is down the last
good answer is served. Calls that are independent of each other run side by
side on the shared pool.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote, urlencode

from .dashboard import jobs
from .dashboard.http_client import safe_fetch
from .dashboard.upstream_cache import TTLCache, default_ttl

logger = logging.getLogger(__name__)

RW_PRO_BASE    = "https://api-pro.ransomware.live"
RW_V2_BASE     = "https://api.ransomware.live/v2"
API_KEY        = os.getenv("RANSOMWARE_LIVE_API_KEY", "")
TIMEOUT        = 20
# For a call that is made of several requests run side by side.
GROUP_TIMEOUT  = 30
MAX_BYTES      = 16 * 1024 * 1024

SEA_ISO2 = {"PH", "TH", "ID", "MY", "VN", "SG", "MM", "KH", "LA", "BN", "TL"}
SEA_NAMES = {
    "PH": "Philippines", "TH": "Thailand",  "ID": "Indonesia",
    "MY": "Malaysia",    "VN": "Vietnam",   "SG": "Singapore",
    "MM": "Myanmar",     "KH": "Cambodia",  "LA": "Laos",
    "BN": "Brunei",      "TL": "Timor-Leste",
}

_cache = TTLCache("ransomware.live", ttl=default_ttl(), max_entries=256)


class UpstreamError(Exception):
    """The API did not give a usable answer."""


def has_pro_key() -> bool:
    return bool(API_KEY)


def _pro_headers() -> dict:
    return {"X-API-KEY": API_KEY, "Accept": "application/json", "User-Agent": "OSINTPH/1.0"}


def _v2_headers() -> dict:
    return {"Accept": "application/json", "User-Agent": "OSINTPH/1.0"}


def _path(*segments) -> Optional[str]:
    """An API path from segments, each one percent-encoded. None when a segment cannot be one."""
    parts = []
    for segment in segments:
        segment = str(segment if segment is not None else "").strip()
        if segment in ("", ".", ".."):
            return None
        parts.append(quote(segment, safe=""))
    return "/" + "/".join(parts)


def _get(path: Optional[str], pro: bool = True, params: dict = None, text: bool = False):
    """GET one API path. Parsed JSON (or the text), or None when there is no answer.

    The key is sent only when there is one and ``pro`` asks for it; otherwise
    the public v2 API is used.
    """
    if path is None:
        return None
    use_pro = bool(pro and API_KEY)
    base    = RW_PRO_BASE if use_pro else RW_V2_BASE
    headers = _pro_headers() if use_pro else _v2_headers()
    query   = urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url     = f"{base}{path}" + (f"?{query}" if query else "")

    def fetch():
        result = safe_fetch(url, headers=headers, timeout=TIMEOUT, max_bytes=MAX_BYTES)
        if result["status"] != 200:
            raise UpstreamError(f"HTTP {result['status']} for {url}")
        if text:
            return result["body"].decode("utf-8", errors="replace")
        return json.loads(result["body"])

    return _cache.get((url, text), fetch)


def _rows(data, keys: tuple) -> list:
    """The list in an answer that is a list, or a dict that wraps one."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


# ── Validate / Stats ───────────────────────────────────────────────────────────

def validate_key() -> dict:
    if not API_KEY:
        return {"valid": False, "message": "No API key configured"}
    url = f"{RW_PRO_BASE}/validate"

    def fetch():
        result = safe_fetch(url, headers=_pro_headers(), timeout=10, max_bytes=MAX_BYTES)
        status = result["status"]
        if status == 200:
            return {"valid": True, "message": "API key is valid", "data": json.loads(result["body"])}
        if status in (401, 403):
            return {"valid": False, "message": f"HTTP {status}"}
        raise UpstreamError(f"HTTP {status} for {url}")

    return _cache.get(
        ("validate",), fetch, default={"valid": False, "message": "ransomware.live did not answer"}
    )


def get_stats() -> Optional[dict]:
    """GET /stats — victims, groups, press counts + last_update."""
    return _get("/stats")


# ── Groups ─────────────────────────────────────────────────────────────────────

def get_all_groups() -> list:
    """
    GET /groups
    Returns list of all ransomware groups with victim counts.
    Fields: name, victims (int)
    """
    return _rows(_get("/groups"), ("data", "groups", "results"))


def get_group(group_name: str) -> Optional[dict]:
    """
    GET /groups/{groupname}
    Full group detail: TTPs, tools, victim count, activity period,
    ransomnotes, negotiations.
    """
    return _get(_path("groups", group_name))


# ── Victims ────────────────────────────────────────────────────────────────────

def get_recent_victims(limit: int = 40) -> list:
    """GET /victims/recent"""
    return _rows(_get("/victims/recent"), ("data", "victims", "results"))[:limit]


def get_victims(
    group: str = None,
    country: str = None,
    sector: str = None,
    year: int = None,
    month: int = None,
    query: str = None,
    limit: int = 100,
) -> list:
    """GET /victims/ with optional filters."""
    params = {}
    if group:
        params["group"] = group
    if country:
        params["country"] = country
    if sector:
        params["sector"] = sector
    if year:
        params["year"] = year
    if month:
        params["month"] = month
    if query:
        params["query"] = query

    return _rows(_get("/victims/", params=params), ("data", "victims", "results"))[:limit]


def get_victim_by_id(victim_id: str) -> Optional[dict]:
    """GET /victim/{victim_id}"""
    return _get(_path("victim", victim_id))


def search_victims(keyword: str, limit: int = 50) -> list:
    """GET /victims/search?query=keyword"""
    data = _get("/victims/search", params={"query": keyword})
    return _rows(data, ("data", "victims", "results"))[:limit]


def _per_sea_country(fetch_one) -> list:
    """[(iso2, rows)] for every SEA country, fetched side by side. A country that fails gives []."""
    countries = sorted(SEA_ISO2)
    rows = jobs.fan_out(fetch_one, countries, parallel=len(countries), timeout=GROUP_TIMEOUT)
    return [(iso2, found or []) for iso2, found in zip(countries, rows)]


def get_sea_victims(limit: int = 200) -> list:
    """Fetch victims for all SEA countries combined."""
    seen  = set()
    out   = []
    for iso2, victims in _per_sea_country(lambda c: get_victims(country=c, limit=500)):
        for v in victims:
            vid = v.get("id") or (str(v.get("victim","")) + str(v.get("attackdate","")))
            if vid not in seen:
                seen.add(vid)
                v["_sea_country"] = SEA_NAMES.get(iso2, iso2)
                out.append(v)
    out.sort(key=lambda x: x.get("attackdate", ""), reverse=True)
    return out[:limit]


# ── IOCs ───────────────────────────────────────────────────────────────────────

def get_ioc_groups(ioc_type: str = None) -> list:
    """GET /iocs — groups that have IOCs, with type counts."""
    params = {}
    if ioc_type:
        params["type"] = ioc_type
    data = _get("/iocs", params=params)
    return data if isinstance(data, list) else []


def get_group_iocs(group_name: str, ioc_type: str = None) -> list:
    """GET /iocs/{group} — IOCs for a specific group."""
    params = {}
    if ioc_type:
        params["type"] = ioc_type
    data = _get(_path("iocs", group_name), params=params)
    return data if isinstance(data, list) else []


# ── Negotiations ───────────────────────────────────────────────────────────────

def get_negotiation_groups() -> list:
    """GET /negotiations — groups with chat logs + counts."""
    data = _get("/negotiations")
    return data if isinstance(data, list) else []


def get_group_negotiations(group_name: str) -> list:
    """GET /negotiations/{group} — chat metadata for a group."""
    data = _get(_path("negotiations", group_name))
    return data if isinstance(data, list) else []


def get_negotiation_chat(group_name: str, chat_id: str) -> Optional[dict]:
    """GET /negotiations/{group}/{chat_id} — full chat transcript."""
    return _get(_path("negotiations", group_name, chat_id))


# ── Press ──────────────────────────────────────────────────────────────────────

def _press(path: str, country: str = None, year: str = None, month: str = None) -> list:
    params = {}
    if country:
        params["country"] = country
    if year:
        params["year"] = year
    if month:
        params["month"] = month
    return _rows(_get(path, params=params), ("results", "data", "items", "press"))


def get_press_recent(country: str = None, year: str = None, month: str = None) -> list:
    """GET /press/recent — response wrapped in {results:[...]}"""
    return _press("/press/recent", country, year, month)


def get_press_all(country: str = None, year: str = None, month: str = None) -> list:
    """GET /press/all — response wrapped in {results:[...]}"""
    return _press("/press/all", country, year, month)


def get_sea_press(limit: int = 30) -> list:
    seen = set()
    out  = []
    for iso2, items in _per_sea_country(lambda c: get_press_recent(country=c)):
        for item in items:
            key = item.get("url") or item.get("title", "")
            if key not in seen:
                seen.add(key)
                item["_sea_country"] = SEA_NAMES.get(iso2, iso2)
                out.append(item)
    out.sort(key=lambda x: x.get("date", ""), reverse=True)
    return out[:limit]


# ── Ransom Notes ───────────────────────────────────────────────────────────────

def get_ransomnote_groups() -> list:
    """GET /ransomnotes"""
    data = _get("/ransomnotes")
    return data if isinstance(data, list) else []


def get_group_ransomnotes(group_name: str) -> list:
    """GET /ransomnotes/{group}"""
    data = _get(_path("ransomnotes", group_name))
    return data if isinstance(data, list) else []


def get_ransomnote_content(group_name: str, note_name: str) -> Optional[str]:
    """GET /ransomnotes/{group}/{note_name} — raw text."""
    return _get(_path("ransomnotes", group_name, note_name), text=True)


# ── YARA ───────────────────────────────────────────────────────────────────────

def get_yara_groups() -> list:
    """GET /yara"""
    data = _get("/yara")
    return data if isinstance(data, list) else []


def get_group_yara(group_name: str) -> Optional[str]:
    """GET /yara/{group} — raw YARA text."""
    return _get(_path("yara", group_name), text=True)


# ── 8-K Filings ────────────────────────────────────────────────────────────────

def get_8k_filings(ticker: str = None, year: str = None, month: str = None) -> list:
    """GET /8k — SEC cybersecurity disclosures."""
    params = {}
    if ticker:
        params["ticker"] = ticker
    if year:
        params["year"] = year
    if month:
        params["month"] = month
    data = _get("/8k", params=params)
    return data if isinstance(data, list) else []


# ── CSIRT ──────────────────────────────────────────────────────────────────────

def get_csirt(country_code: str) -> Optional[dict]:
    """GET /csirt/{country}"""
    return _get(_path("csirt", str(country_code or "").upper()))


def get_sea_csirts() -> dict:
    return {iso2: data for iso2, data in _per_sea_country(get_csirt) if data}


# ── Sectors ────────────────────────────────────────────────────────────────────

def list_sectors() -> list:
    """GET /listsectors"""
    data = _get("/listsectors")
    return data if isinstance(data, list) else []


# ── Composite helpers ──────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def build_group_profile(group_name: str) -> dict:
    """Full profile for one group — used by ransomware tab detail modal."""
    got = jobs.call_all({
        "group":        lambda: get_group(group_name),
        "victims":      lambda: get_victims(group=group_name, limit=100),
        "iocs":         lambda: get_group_iocs(group_name),
        "negotiations": lambda: get_group_negotiations(group_name),
        "ransomnotes":  lambda: get_group_ransomnotes(group_name),
        "yara":         lambda: get_group_yara(group_name),
    }, timeout=GROUP_TIMEOUT)
    victims = got["victims"] or []
    return {
        "group":        got["group"],
        "recent_victims": victims[:20],
        "iocs":         got["iocs"] or [],
        "negotiations": got["negotiations"] or [],
        "ransomnotes":  got["ransomnotes"] or [],
        "yara":         got["yara"],
        "sea_victims":  [v for v in victims
                         if (v.get("country") or "").upper() in SEA_ISO2],
        "fetched_at":   _now(),
    }


def get_home_dashboard_data() -> dict:
    """Single call for Home tab."""
    got = jobs.call_all({
        "recent": lambda: get_recent_victims(limit=20),
        "stats":  get_stats,
        "press":  get_press_recent,
    }, timeout=GROUP_TIMEOUT)
    recent = got["recent"] or []
    return {
        "stats":         got["stats"],
        "recent_victims": recent,
        "sea_victims":   [v for v in recent if (v.get("country") or "").upper() in SEA_ISO2],
        "press_recent":  (got["press"] or [])[:10],
        "has_pro_key":   has_pro_key(),
        "fetched_at":    _now(),
    }


def get_ransomware_tab_data() -> dict:
    """Single call for Ransomware tab."""
    got = jobs.call_all({
        "live_groups":        get_all_groups,
        "stats":              get_stats,
        "ioc_groups":         get_ioc_groups,
        "negotiation_groups": get_negotiation_groups,
        "ransomnote_groups":  get_ransomnote_groups,
        "yara_groups":        get_yara_groups,
    }, timeout=GROUP_TIMEOUT)
    return {
        "live_groups":         got["live_groups"] or [],
        "stats":               got["stats"],
        "ioc_groups":          got["ioc_groups"] or [],
        "negotiation_groups":  got["negotiation_groups"] or [],
        "ransomnote_groups":   got["ransomnote_groups"] or [],
        "yara_groups":         got["yara_groups"] or [],
        "has_pro_key":         has_pro_key(),
        "fetched_at":          _now(),
    }
