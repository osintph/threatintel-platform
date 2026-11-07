"""
IP Investigation — AbuseIPDB + VirusTotal enrichment.

A lookup answers at once with the AbuseIPDB check and the main VirusTotal
report, fetched side by side. Nothing here sleeps in the caller's thread.

VirusTotal's free quota is 4 requests a minute (VIRUSTOTAL_PER_MINUTE). The two
extra VirusTotal calls of a lookup (historical resolutions, communicating
files) used to be spaced with two 16-second sleeps inside the request. They
now run on one background queue that takes its turns from the same per-minute
count as the main report, and the saved record is updated when they finish:
``virustotal.extras_status`` goes from "pending" to "complete" (or "failed",
or "skipped" when the queue is full). When the minute's count is used up, the
main report is not requested and the lookup says so.

Requests go through safe_fetch(): HTTPS, the two API hosts only, no redirects,
so a key header is never sent anywhere else.
"""

import ipaddress
import json
import logging
import os
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import quote, urlencode

from .dashboard import jobs
from .dashboard.http_client import SafeFetchError, safe_fetch
from .dashboard.upstream_cache import TTLCache

logger = logging.getLogger(__name__)

ABUSE_CATEGORIES = {
    1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS Attack",
    5:"FTP Brute-Force",6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",
    9:"Open Proxy",10:"Web Spam",11:"Email Spam",12:"Blog Spam",
    13:"VPN IP",14:"Port Scan",15:"Hacking",16:"SQL Injection",
    17:"Spoofing",18:"Brute Force",19:"Bad Web Bot",20:"Exploited Host",
    21:"Web App Attack",22:"SSH",23:"IoT Targeted",
}

VT_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15
MAX_BYTES = 8 * 1024 * 1024

VT_RATE_LIMITED = "VirusTotal rate limit reached. Try again in a minute."

# Every VirusTotal request of this process is counted here, in and out of requests.
VT_WINDOW = jobs.RateWindow(jobs.env_int("VIRUSTOTAL_PER_MINUTE", 4, high=1000), per=60.0)
# One lookup's extra calls per entry; at 4 a minute, 20 entries are about ten minutes of work.
_vt_extras = jobs.PacedQueue("virustotal", VT_WINDOW, max_pending=20)

# The same address asked again within ten minutes costs no new upstream call.
# Only good answers are kept, and never served past their time.
_cache = TTLCache("ip-lookup", ttl=600, stale_for=0, error_ttl=30, max_entries=500)


class _NoAnswer(Exception):
    """Carries a check's error result out of the cache's fetch function."""


def _valid_ip(ip: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None


def _get_json(url: str, headers: dict):
    """(status, parsed JSON or None). Raises SafeFetchError when the request cannot be made."""
    result = safe_fetch(url, headers=headers, timeout=REQUEST_TIMEOUT, max_bytes=MAX_BYTES)
    try:
        return result["status"], json.loads(result["body"])
    except ValueError:
        return result["status"], None


def _cached(kind: str, ip: str, check: Callable[[], dict]) -> dict:
    """check() through the cache. A result with an error is returned but not kept."""
    seen: dict = {}

    def fetch():
        seen["result"] = check()
        if seen["result"].get("error"):
            raise _NoAnswer(seen["result"]["error"])
        return seen["result"]

    cached = _cache.get((kind, ip), fetch)
    if cached is not None:
        return cached
    return seen.get("result") or {"error": f"{kind} did not answer a moment ago. Try again in a minute."}


def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Full AbuseIPDB check with verbose reports."""
    ip = _valid_ip(ip)
    if not ip:
        return {"error": "Invalid IP address"}
    return _cached("AbuseIPDB", ip, lambda: _abuseipdb(ip, api_key))


def _abuseipdb(ip: str, api_key: str) -> dict:
    query = urlencode({"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"})
    try:
        status, body = _get_json(
            f"https://api.abuseipdb.com/api/v2/check?{query}",
            {"Key": api_key, "Accept": "application/json"},
        )
    except SafeFetchError as e:
        logger.warning("AbuseIPDB request failed: %s", e)
        return {"error": "AbuseIPDB could not be reached"}
    if status == 401:
        return {"error": "Invalid AbuseIPDB API key"}
    if status == 429:
        return {"error": "AbuseIPDB rate limit — retry later"}
    if status != 200 or not isinstance(body, dict):
        return {"error": f"AbuseIPDB HTTP {status}"}

    d = body.get("data", {})
    reports = []
    for r in (d.get("reports") or [])[:20]:
        cats = [ABUSE_CATEGORIES.get(c, f"Cat {c}") for c in (r.get("categories") or [])]
        reports.append({
            "reported_at": r.get("reportedAt"),
            "comment": (r.get("comment") or "")[:300],
            "categories": cats,
            "reporter_country": r.get("reporterCountryName"),
        })
    return {
        "ip": d.get("ipAddress"),
        "is_public": d.get("isPublic"),
        "ip_version": d.get("ipVersion"),
        "is_whitelisted": d.get("isWhitelisted"),
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "country_code": d.get("countryCode"),
        "country_name": d.get("countryName"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "hostnames": d.get("hostnames") or [],
        "is_tor": d.get("isTor", False),
        "total_reports": d.get("totalReports", 0),
        "num_distinct_users": d.get("numDistinctUsers", 0),
        "last_reported_at": d.get("lastReportedAt"),
        "reports": reports,
    }


def _vt_headers(api_key: str) -> dict:
    return {"x-apikey": api_key, "Accept": "application/json"}


def _vt_url(ip: str, part: str = "", **params) -> str:
    # A colon is a legal character in a path segment; IPv6 addresses keep theirs.
    url = f"{VT_BASE}/ip_addresses/{quote(ip, safe=':')}"
    if part:
        url += f"/{part}"
    return url + (f"?{urlencode(params)}" if params else "")


def check_virustotal(ip: str, api_key: str) -> dict:
    """The main VirusTotal IP report. One request, no waiting.

    ``resolutions`` and ``communicating_files`` are empty here; see
    queue_virustotal_extras().
    """
    ip = _valid_ip(ip)
    if not ip:
        return {"error": "Invalid IP address"}
    return _cached("VirusTotal", ip, lambda: _virustotal(ip, api_key))


def _virustotal(ip: str, api_key: str) -> dict:
    if not VT_WINDOW.try_take():
        return {"error": VT_RATE_LIMITED}
    try:
        status, main_data = _get_json(_vt_url(ip), _vt_headers(api_key))
    except SafeFetchError as e:
        logger.warning("VirusTotal request failed: %s", e)
        return {"error": "VirusTotal could not be reached"}
    if status == 401:
        return {"error": "Invalid VirusTotal API key"}
    if status == 404:
        return {"error": "IP not found in VirusTotal"}
    if status == 429:
        return {"error": "VirusTotal rate limit hit"}
    if status != 200 or not isinstance(main_data, dict):
        return {"error": f"VirusTotal HTTP {status}"}

    attrs = main_data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    engine_results = attrs.get("last_analysis_results", {})
    malicious_engines = [
        {"engine": name, "result": info.get("result"), "category": info.get("category")}
        for name, info in engine_results.items()
        if info.get("category") in ("malicious", "suspicious")
    ]

    ssl_cert = attrs.get("last_https_certificate", {})
    ssl_info = None
    if ssl_cert:
        subject = ssl_cert.get("subject", {})
        issuer = ssl_cert.get("issuer", {})
        validity = ssl_cert.get("validity", {})
        ssl_info = {
            "subject_cn": subject.get("CN"),
            "subject_org": subject.get("O"),
            "issuer_cn": issuer.get("CN"),
            "issuer_org": issuer.get("O"),
            "valid_from": validity.get("not_before"),
            "valid_to": validity.get("not_after"),
            "serial": ssl_cert.get("serial_number"),
        }

    last_analysis = attrs.get("last_analysis_date")
    if last_analysis:
        try:
            last_analysis = datetime.fromtimestamp(last_analysis, tz=timezone.utc).isoformat()
        except Exception:
            pass

    whois_date = attrs.get("whois_date")
    if whois_date:
        try:
            whois_date = datetime.fromtimestamp(whois_date, tz=timezone.utc).isoformat()
        except Exception:
            pass

    return {
        "ip": ip,
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "continent": attrs.get("continent"),
        "country": attrs.get("country"),
        "network": attrs.get("network"),
        "regional_internet_registry": attrs.get("regional_internet_registry"),
        "reputation": attrs.get("reputation", 0),
        "jarm": attrs.get("jarm"),
        "tags": attrs.get("tags") or [],
        "total_votes": attrs.get("total_votes", {}),
        "last_analysis_date": last_analysis,
        "analysis_stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
        },
        "malicious_engines": malicious_engines,
        "total_engines": len(engine_results),
        "ssl_certificate": ssl_info,
        "whois": (attrs.get("whois") or "")[:3000] or None,
        "whois_date": whois_date,
        "resolutions": [],
        "communicating_files": [],
    }


# ── The two rate-limited extra calls ───────────────────────────────────────────


def _vt_rows(ip: str, api_key: str, part: str, limit: int) -> Optional[list]:
    """The ``data`` list of one extra VirusTotal call, or None when it gave no answer."""
    try:
        status, body = _get_json(_vt_url(ip, part, limit=limit), _vt_headers(api_key))
    except SafeFetchError as e:
        logger.warning("VirusTotal %s request failed: %s", part, e)
        return None
    if status != 200 or not isinstance(body, dict):
        logger.warning("VirusTotal %s: HTTP %s", part, status)
        return None
    return body.get("data") or []


def fetch_virustotal_extras(ip: str, api_key: str, second_turn: Callable[[], bool]) -> dict:
    """Resolutions and communicating files: two VirusTotal requests.

    The caller has taken the turn for the first request; ``second_turn()``
    waits for the turn of the second one. Runs on the extras queue, never in a
    request. Returns the fields to merge into the saved ``virustotal`` record.
    """
    fields: dict = {"resolutions": [], "communicating_files": []}
    resolutions = _vt_rows(ip, api_key, "resolutions", 20)
    for item in resolutions or []:
        ra = item.get("attributes", {})
        fields["resolutions"].append({
            "hostname": ra.get("host_name"),
            "date": ra.get("date"),
            "resolver": ra.get("resolver"),
        })
    files = _vt_rows(ip, api_key, "communicating_files", 10) if second_turn() else None
    for item in files or []:
        fa = item.get("attributes", {})
        fa_stats = fa.get("last_analysis_stats", {})
        fields["communicating_files"].append({
            "sha256": item.get("id"),
            "name": fa.get("meaningful_name") or fa.get("name", "unknown"),
            "type": fa.get("type_description"),
            "size": fa.get("size"),
            "malicious": fa_stats.get("malicious", 0),
            "suspicious": fa_stats.get("suspicious", 0),
        })
    if resolutions is None or files is None:
        fields["extras_status"] = "failed"
        fields["extras_note"] = "VirusTotal did not answer for all of the extra data."
    else:
        fields["extras_status"] = "complete"
    return fields


def queue_virustotal_extras(ip: str, api_key: str, save: Callable[[dict], None]) -> str:
    """Queue the extra VirusTotal calls of one lookup. Never waits.

    ``save(fields)`` gets the fields to merge into the saved record. Returns

      "pending"   queued; save() is called later, once, from the queue's thread
      "complete"  the data was fetched in the last ten minutes; save() has been called
      "skipped"   the queue is full; save() is not called and the caller marks the record
    """
    key = ("VirusTotal extras", ip)
    known = _cache.peek(key)
    if known is not None:
        save(known)
        return "complete"

    def run():
        try:
            fields = fetch_virustotal_extras(ip, api_key, VT_WINDOW.wait_take)
        except Exception:
            logger.exception("VirusTotal extras for %s failed", ip)
            fields = {"extras_status": "failed", "extras_note": "The extra data could not be fetched."}
        if fields.get("extras_status") == "complete":
            _cache.get(key, lambda: fields)  # keeps it for the next lookup of this address
        save(fields)

    return "pending" if _vt_extras.submit(run) else "skipped"


def investigate_ip(ip: str, abuseipdb_key: str = "", virustotal_key: str = "") -> dict:
    """AbuseIPDB and the main VirusTotal report, side by side. Answers at once.

    When the VirusTotal report is there, it carries extras_status "pending":
    the caller saves the record and hands it to queue_virustotal_extras().
    """
    abuse_key = abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY", "")
    vt_key = virustotal_key or os.getenv("VIRUSTOTAL_API_KEY", "")

    calls = {}
    if abuse_key:
        calls["abuseipdb"] = lambda: check_abuseipdb(ip, abuse_key)
    if vt_key:
        calls["virustotal"] = lambda: check_virustotal(ip, vt_key)
    got = jobs.call_all(calls, timeout=2 * REQUEST_TIMEOUT) if calls else {}

    results: dict = {"ip": ip}
    if abuse_key:
        results["abuseipdb"] = got.get("abuseipdb") or {"error": "AbuseIPDB did not answer in time"}
    else:
        results["abuseipdb"] = {"error": "ABUSEIPDB_API_KEY not configured"}

    if vt_key:
        results["virustotal"] = got.get("virustotal") or {"error": "VirusTotal did not answer in time"}
        if not results["virustotal"].get("error"):
            results["virustotal"]["extras_status"] = "pending"
    else:
        results["virustotal"] = {"error": "VIRUSTOTAL_API_KEY not configured"}

    return results
