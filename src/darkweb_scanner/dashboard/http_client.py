"""
Hardened outbound HTTP client for dashboard proxy routes.

Provides safe_fetch() — a replacement for the insecure _fetch_url() helper
and all direct urllib.request.urlopen() calls in dashboard routes. Enforces:

  1. HTTPS-only: plain HTTP is rejected.
  2. Host allowlist: only hosts in ALLOWED_EXTERNAL_HOSTS may be contacted.
  3. IP blocklist: all resolved IPs are checked against RFC 1918,
     loopback (127/8), link-local (169.254/16), and IPv6 equivalents.
  4. TLS verification enabled (verify=True, the requests library default).
  5. Redirects disabled by default; opt-in with allow_redirects=True (max 3
     hops; each hop re-validates host and IP before following).

The Tor SOCKS5 crawler path (crawler.py, tor_client.py) is intentionally
excluded — it contacts .onion addresses through a local Tor daemon, where
the allowlist and IP-blocklist models do not apply.
"""

import ipaddress
import json as _json
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests as _requests

ALLOWED_EXTERNAL_HOSTS: frozenset = frozenset({
    # Abuse.ch threat-intel feeds
    "threatfox-api.abuse.ch",
    "urlhaus-api.abuse.ch",
    "feodotracker.abuse.ch",
    "mb-api.abuse.ch",
    # External threat intelligence
    "otx.alienvault.com",
    "api.abuseipdb.com",
    "www.virustotal.com",
    "api.virustotal.com",
    "haveibeenpwned.com",
    "api.greynoise.io",
    "urlscan.io",
    "api.urlscan.io",
    "api.securitytrails.com",
    # OSINT / certificate transparency / DNS
    "crt.sh",
    "api.hackertarget.com",
    "ip-api.com",
    "api.shodan.io",
    "search.censys.io",
    "api.censys.io",
    "mxtoolbox.com",
    "api.dnsdumpster.com",
    "rdap.org",
    # Registry-specific RDAP servers (rdap.org redirects to these)
    "rdap.verisign.com",
    "rdap.publicinterestregistry.org",
    "rdap.identitydigital.services",
    "rdap.markmonitor.com",
    "rdap.nic.google",
    "rdap.centralnic.com",
    "rdap.nominet.uk",
    "rdap.afilias.net",
    "rdap.arin.net",
    "rdap.db.ripe.net",
    "rdap.apnic.net",
    "rdap.lacnic.net",
    "rdap.afrinic.net",
    # Developer / social platforms
    "api.github.com",
    "raw.githubusercontent.com",
    "www.reddit.com",
    "discordlookup.mesalytic.moe",
    "www.tiktok.com",
    # Data enrichment
    "whiteintel.io",
    # Mail infrastructure
    "api.mailgun.net",
})

# Supplementary networks not fully covered by ipaddress stdlib classifiers on all
# Python versions. The stdlib is_private/is_reserved/is_loopback/is_link_local
# checks run first; these catch anything that slips through.
_BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    # Ranges the stdlib is_private misses on older Python versions:
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),    # IETF protocol assignments (RFC 6890)
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking (RFC 2544)
    ipaddress.ip_network("64:ff9b::/96"),    # NAT64 (RFC 6052)
]


class SafeFetchError(Exception):
    """Raised when safe_fetch blocks a request due to security policy."""


def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable address — fail closed
    # Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) before classifying so that
    # ::ffff:127.0.0.1 and ::ffff:169.254.169.254 are correctly blocked.
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        return True
    return any(ip in net for net in _BLOCKED_NETS)


def _resolve_and_check(hostname: str) -> None:
    """Resolve hostname and raise SafeFetchError if any resolved IP is private."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SafeFetchError(
            f"DNS resolution failed for {hostname!r}: {exc}"
        ) from exc
    for info in infos:
        addr = info[4][0]
        if _is_private_ip(addr):
            raise SafeFetchError(
                f"Blocked: {hostname!r} resolves to a private/loopback address {addr!r}"
            )


def resolve_and_check_target(host: str) -> list:
    """Resolve host to IPs, validate each with the private-IP check, return public IPs.

    Raises SafeFetchError if any resolved IP is private, loopback, or otherwise blocked.
    Used by dns_crawler to apply the same SSRF guard to its recon paths.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SafeFetchError(
            f"DNS resolution failed for {host!r}: {exc}"
        ) from exc
    seen: set = set()
    public_ips: list = []
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        if _is_private_ip(addr):
            raise SafeFetchError(
                f"Blocked: {host!r} resolves to a private/loopback address {addr!r}"
            )
        public_ips.append(addr)
    return public_ips


def check_host_ssrf(hostname: str) -> None:
    """IP-blocklist check without allowlist enforcement.

    Use when the set of target hosts is too large for a static allowlist
    (e.g. the WhatsMyName corpus of 200+ sites). Raises SafeFetchError if the
    hostname resolves to any private or loopback address.
    """
    _resolve_and_check(hostname)


def _validate_url(url: str) -> None:
    """Enforce HTTPS, allowlist membership, and IP blocklist. Raises SafeFetchError."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SafeFetchError(
            f"Blocked: only HTTPS is permitted, got scheme {parsed.scheme!r}"
        )
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_EXTERNAL_HOSTS:
        raise SafeFetchError(
            f"Blocked: {host!r} is not in ALLOWED_EXTERNAL_HOSTS"
        )
    _resolve_and_check(host)


def safe_fetch(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict] = None,
    data: Optional[bytes] = None,
    json_data: Optional[dict] = None,
    timeout: int = 15,
    allow_redirects: bool = False,
) -> dict:
    """Hardened HTTP fetch with HTTPS enforcement, host allowlist, and IP blocklist.

    Returns {"status": int, "headers": dict, "body": bytes, "url": str}.
    Raises SafeFetchError for any policy violation or network/TLS error.

    The Tor SOCKS5 crawler path is explicitly excluded; do not route .onion
    traffic through this function.
    """
    _validate_url(url)

    _hdrs = {"User-Agent": "OSINTPH/1.0", "Accept": "application/json, */*"}
    if headers:
        _hdrs.update(headers)

    def _do_request(target_url: str, req_method: str, req_data, req_json):
        try:
            return _requests.request(
                req_method,
                target_url,
                headers=_hdrs,
                data=req_data,
                json=req_json,
                timeout=timeout,
                allow_redirects=False,
                verify=True,
            )
        except _requests.exceptions.SSLError as exc:
            raise SafeFetchError(
                f"TLS verification failed for {target_url!r}: {exc}"
            ) from exc
        except _requests.exceptions.Timeout as exc:
            raise SafeFetchError(
                f"Request timed out for {target_url!r}: {exc}"
            ) from exc
        except _requests.exceptions.ConnectionError as exc:
            raise SafeFetchError(
                f"Connection failed for {target_url!r}: {exc}"
            ) from exc
        except _requests.exceptions.RequestException as exc:
            raise SafeFetchError(
                f"Request failed for {target_url!r}: {exc}"
            ) from exc

    if not allow_redirects:
        resp = _do_request(url, method, data, json_data)
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.content,
            "url": resp.url,
        }

    # Manual redirect following with re-validation at each hop (max 3 redirects)
    current_url = url
    cur_method = method
    cur_data = data
    cur_json = json_data

    for hop in range(4):
        resp = _do_request(current_url, cur_method, cur_data, cur_json)
        if resp.status_code not in (301, 302, 303, 307, 308):
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.content,
                "url": resp.url,
            }
        if hop == 3:
            raise SafeFetchError(
                f"Blocked: redirect chain exceeded 3 hops starting at {url!r}"
            )
        location = resp.headers.get("Location", "")
        if not location:
            raise SafeFetchError("Blocked: redirect response has no Location header")
        next_url = urljoin(current_url, location)
        _validate_url(next_url)
        current_url = next_url
        # Standard browser behaviour: downgrade POST → GET on 301/302/303
        if resp.status_code in (301, 302, 303) and cur_method not in ("GET", "HEAD"):
            cur_method = "GET"
            cur_data = None
            cur_json = None

    raise SafeFetchError("redirect loop terminated unexpectedly")  # pragma: no cover


def safe_fetch_json(url: str, **kwargs) -> tuple:
    """Convenience wrapper: safe_fetch + JSON decode.

    Returns (status_code, parsed_dict). Raises SafeFetchError on JSON failure.
    """
    result = safe_fetch(url, **kwargs)
    try:
        return result["status"], _json.loads(result["body"])
    except Exception as exc:
        raise SafeFetchError(f"JSON decode failed for {url!r}: {exc}") from exc
