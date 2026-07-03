"""
ransomware_live.py — Ransomware.live PRO API client.
Place at: src/darkweb_scanner/ransomware_live.py

API key from: https://my.ransomware.live
Set in .env: RANSOMWARE_LIVE_API_KEY=your_key
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional
import requests

logger = logging.getLogger(__name__)

RW_PRO_BASE    = "https://api-pro.ransomware.live"
RW_V2_BASE     = "https://api.ransomware.live/v2"
API_KEY        = os.getenv("RANSOMWARE_LIVE_API_KEY", "")
TIMEOUT        = 20

SEA_ISO2 = {"PH", "TH", "ID", "MY", "VN", "SG", "MM", "KH", "LA", "BN", "TL"}
SEA_NAMES = {
    "PH": "Philippines", "TH": "Thailand",  "ID": "Indonesia",
    "MY": "Malaysia",    "VN": "Vietnam",   "SG": "Singapore",
    "MM": "Myanmar",     "KH": "Cambodia",  "LA": "Laos",
    "BN": "Brunei",      "TL": "Timor-Leste",
}


def has_pro_key() -> bool:
    return bool(API_KEY)


def _pro_headers() -> dict:
    return {"X-API-KEY": API_KEY, "Accept": "application/json", "User-Agent": "OSINTPH/1.0"}


def _v2_headers() -> dict:
    return {"Accept": "application/json", "User-Agent": "OSINTPH/1.0"}


def _get(path: str, pro: bool = True, params: dict = None):
    base    = RW_PRO_BASE if (pro and API_KEY) else RW_V2_BASE
    headers = _pro_headers() if (pro and API_KEY) else _v2_headers()
    url     = f"{base}{path}"
    try:
        r = requests.get(url, headers=headers, params=params or {}, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning(f"RW.live GET {url} failed: {e}")
        return None


# ── Validate / Stats ───────────────────────────────────────────────────────────

def validate_key() -> dict:
    if not API_KEY:
        return {"valid": False, "message": "No API key configured"}
    try:
        r = requests.get(f"{RW_PRO_BASE}/validate", headers=_pro_headers(), timeout=10)
        if r.status_code == 200:
            return {"valid": True, "message": "API key is valid", "data": r.json()}
        return {"valid": False, "message": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"valid": False, "message": str(e)}


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
    data = _get("/groups")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # might be wrapped
        for key in ("data", "groups", "results"):
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


def get_group(group_name: str) -> Optional[dict]:
    """
    GET /groups/{groupname}
    Full group detail: TTPs, tools, victim count, activity period,
    ransomnotes, negotiations.
    """
    return _get(f"/groups/{group_name}")


# ── Victims ────────────────────────────────────────────────────────────────────

def get_recent_victims(limit: int = 40) -> list:
    """GET /victims/recent"""
    data = _get("/victims/recent")
    if isinstance(data, list):
        return data[:limit]
    if isinstance(data, dict):
        for key in ("data", "victims", "results"):
            if key in data and isinstance(data[key], list):
                return data[key][:limit]
    return []


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

    data = _get("/victims/", params=params)
    if isinstance(data, list):
        return data[:limit]
    if isinstance(data, dict):
        for key in ("data", "victims", "results"):
            if key in data and isinstance(data[key], list):
                return data[key][:limit]
    return []


def get_victim_by_id(victim_id: str) -> Optional[dict]:
    """GET /victim/{victim_id}"""
    return _get(f"/victim/{victim_id}")


def search_victims(keyword: str, limit: int = 50) -> list:
    """GET /victims/search?query=keyword"""
    data = _get("/victims/search", params={"query": keyword})
    if isinstance(data, list):
        return data[:limit]
    if isinstance(data, dict):
        for key in ("data", "victims", "results"):
            if key in data and isinstance(data[key], list):
                return data[key][:limit]
    return []


def get_sea_victims(limit: int = 200) -> list:
    """Fetch victims for all SEA countries combined."""
    seen  = set()
    out   = []
    for iso2 in SEA_ISO2:
        for v in get_victims(country=iso2, limit=500):
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
    data = _get(f"/iocs/{group_name}", params=params)
    return data if isinstance(data, list) else []


# ── Negotiations ───────────────────────────────────────────────────────────────

def get_negotiation_groups() -> list:
    """GET /negotiations — groups with chat logs + counts."""
    data = _get("/negotiations")
    return data if isinstance(data, list) else []


def get_group_negotiations(group_name: str) -> list:
    """GET /negotiations/{group} — chat metadata for a group."""
    data = _get(f"/negotiations/{group_name}")
    return data if isinstance(data, list) else []


def get_negotiation_chat(group_name: str, chat_id: str) -> Optional[dict]:
    """GET /negotiations/{group}/{chat_id} — full chat transcript."""
    return _get(f"/negotiations/{group_name}/{chat_id}")


# ── Press ──────────────────────────────────────────────────────────────────────

def get_press_recent(country: str = None, year: str = None, month: str = None) -> list:
    """GET /press/recent — response wrapped in {results:[...]}"""
    params = {}
    if country:
        params["country"] = country
    if year:
        params["year"] = year
    if month:
        params["month"] = month
    data = _get("/press/recent", params=params)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "data", "items", "press"):
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


def get_press_all(country: str = None, year: str = None, month: str = None) -> list:
    """GET /press/all — response wrapped in {results:[...]}"""
    params = {}
    if country:
        params["country"] = country
    if year:
        params["year"] = year
    if month:
        params["month"] = month
    data = _get("/press/all", params=params)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "data", "items", "press"):
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


def get_sea_press(limit: int = 30) -> list:
    seen = set()
    out  = []
    for iso2 in SEA_ISO2:
        for item in get_press_recent(country=iso2):
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
    data = _get(f"/ransomnotes/{group_name}")
    return data if isinstance(data, list) else []


def get_ransomnote_content(group_name: str, note_name: str) -> Optional[str]:
    """GET /ransomnotes/{group}/{note_name} — raw text."""
    try:
        r = requests.get(
            f"{RW_PRO_BASE}/ransomnotes/{group_name}/{note_name}",
            headers=_pro_headers(), timeout=TIMEOUT,
        )
        r.raise_for_status()
        return r.text
    except Exception as e:
        logger.warning(f"Ransom note fetch failed: {e}")
        return None


# ── YARA ───────────────────────────────────────────────────────────────────────

def get_yara_groups() -> list:
    """GET /yara"""
    data = _get("/yara")
    return data if isinstance(data, list) else []


def get_group_yara(group_name: str) -> Optional[str]:
    """GET /yara/{group} — raw YARA text."""
    try:
        base    = RW_PRO_BASE if API_KEY else RW_V2_BASE
        headers = _pro_headers() if API_KEY else _v2_headers()
        r = requests.get(f"{base}/yara/{group_name}", headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        logger.warning(f"YARA fetch failed for {group_name}: {e}")
        return None


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
    return _get(f"/csirt/{country_code.upper()}")


def get_sea_csirts() -> dict:
    out = {}
    for iso2 in SEA_ISO2:
        data = get_csirt(iso2)
        if data:
            out[iso2] = data
    return out


# ── Sectors ────────────────────────────────────────────────────────────────────

def list_sectors() -> list:
    """GET /listsectors"""
    data = _get("/listsectors")
    return data if isinstance(data, list) else []


# ── Composite helpers ──────────────────────────────────────────────────────────

def build_group_profile(group_name: str) -> dict:
    """Full profile for one group — used by ransomware tab detail modal."""
    return {
        "group":        get_group(group_name),
        "recent_victims": get_victims(group=group_name, limit=20),
        "iocs":         get_group_iocs(group_name),
        "negotiations": get_group_negotiations(group_name),
        "ransomnotes":  get_group_ransomnotes(group_name),
        "yara":         get_group_yara(group_name),
        "sea_victims":  [v for v in get_victims(group=group_name, limit=100)
                         if (v.get("country") or "").upper() in SEA_ISO2],
        "fetched_at":   datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }


def get_home_dashboard_data() -> dict:
    """Single call for Home tab."""
    recent  = get_recent_victims(limit=20)
    return {
        "stats":         get_stats(),
        "recent_victims": recent,
        "sea_victims":   [v for v in recent if (v.get("country") or "").upper() in SEA_ISO2],
        "press_recent":  get_press_recent()[:10],
        "has_pro_key":   has_pro_key(),
        "fetched_at":    datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }


def get_ransomware_tab_data() -> dict:
    """Single call for Ransomware tab."""
    return {
        "live_groups":         get_all_groups(),
        "stats":               get_stats(),
        "ioc_groups":          get_ioc_groups(),
        "negotiation_groups":  get_negotiation_groups(),
        "ransomnote_groups":   get_ransomnote_groups(),
        "yara_groups":         get_yara_groups(),
        "has_pro_key":         has_pro_key(),
        "fetched_at":          datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }
