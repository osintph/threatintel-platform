"""
IP Investigation — AbuseIPDB + VirusTotal synchronous enrichment.
Uses requests instead of aiohttp to avoid event loop conflicts with Flask.
"""

import logging
import os
import time
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

ABUSE_CATEGORIES = {
    1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS Attack",
    5:"FTP Brute-Force",6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",
    9:"Open Proxy",10:"Web Spam",11:"Email Spam",12:"Blog Spam",
    13:"VPN IP",14:"Port Scan",15:"Hacking",16:"SQL Injection",
    17:"Spoofing",18:"Brute Force",19:"Bad Web Bot",20:"Exploited Host",
    21:"Web App Attack",22:"SSH",23:"IoT Targeted",
}


def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Full AbuseIPDB check with verbose reports."""
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"},
            timeout=15,
        )
        if resp.status_code == 401:
            return {"error": "Invalid AbuseIPDB API key"}
        if resp.status_code == 429:
            return {"error": "AbuseIPDB rate limit — retry later"}
        if resp.status_code != 200:
            return {"error": f"AbuseIPDB HTTP {resp.status_code}"}

        d = resp.json().get("data", {})
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
    except requests.RequestException as e:
        return {"error": f"Network error: {e}"}


def check_virustotal(ip: str, api_key: str) -> dict:
    """Full VirusTotal IP check — main report + resolutions + communicating files."""
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    base = "https://www.virustotal.com/api/v3"

    # ── Main IP report ──
    try:
        resp = requests.get(f"{base}/ip_addresses/{ip}", headers=headers, timeout=15)
        if resp.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        if resp.status_code == 404:
            return {"error": "IP not found in VirusTotal"}
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit hit"}
        if resp.status_code != 200:
            return {"error": f"VirusTotal HTTP {resp.status_code}"}
        main_data = resp.json()
    except requests.RequestException as e:
        return {"error": f"Network error: {e}"}

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

    result = {
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

    # ── Resolutions (rate limit: 4 req/min = 15s between calls) ──
    time.sleep(16)
    try:
        resp = requests.get(
            f"{base}/ip_addresses/{ip}/resolutions",
            headers=headers, params={"limit": "20"}, timeout=15,
        )
        if resp.status_code == 200:
            for item in (resp.json().get("data") or []):
                ra = item.get("attributes", {})
                result["resolutions"].append({
                    "hostname": ra.get("host_name"),
                    "date": ra.get("date"),
                    "resolver": ra.get("resolver"),
                })
    except Exception:
        pass

    # ── Communicating files ──
    time.sleep(16)
    try:
        resp = requests.get(
            f"{base}/ip_addresses/{ip}/communicating_files",
            headers=headers, params={"limit": "10"}, timeout=15,
        )
        if resp.status_code == 200:
            for item in (resp.json().get("data") or []):
                fa = item.get("attributes", {})
                fa_stats = fa.get("last_analysis_stats", {})
                result["communicating_files"].append({
                    "sha256": item.get("id"),
                    "name": fa.get("meaningful_name") or fa.get("name", "unknown"),
                    "type": fa.get("type_description"),
                    "size": fa.get("size"),
                    "malicious": fa_stats.get("malicious", 0),
                    "suspicious": fa_stats.get("suspicious", 0),
                })
    except Exception:
        pass

    return result


def investigate_ip(ip: str, abuseipdb_key: str = "", virustotal_key: str = "") -> dict:
    """Run full IP investigation — AbuseIPDB then VirusTotal."""
    abuse_key = abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY", "")
    vt_key = virustotal_key or os.getenv("VIRUSTOTAL_API_KEY", "")

    results: dict = {"ip": ip, "abuseipdb": None, "virustotal": None}

    if abuse_key:
        results["abuseipdb"] = check_abuseipdb(ip, abuse_key)
    else:
        results["abuseipdb"] = {"error": "ABUSEIPDB_API_KEY not configured"}

    if vt_key:
        results["virustotal"] = check_virustotal(ip, vt_key)
    else:
        results["virustotal"] = {"error": "VIRUSTOTAL_API_KEY not configured"}

    return results
