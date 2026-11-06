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
  6. Pinned address: the host name is resolved once, and the connection goes
     to an address that passed the check. The host name is still used for the
     Host header, the TLS server name and certificate verification. A second
     DNS answer (DNS rebinding) can therefore not move the request elsewhere.

fetch_public() applies 3, 4 and 6 without the allowlist and never follows a
redirect. It is for targets that cannot be listed in advance: the hosts found
by DNS recon and the sites of the WhatsMyName corpus.

The Tor SOCKS5 crawler path (crawler.py, tor_client.py) is intentionally
excluded — it contacts .onion addresses through a local Tor daemon, where
the allowlist and IP-blocklist models do not apply. Neither function here
accepts a .onion host.
"""

import ipaddress
import json as _json
import os
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests as _requests
from requests.adapters import HTTPAdapter as _HTTPAdapter

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
    # Quick Scan clearnet paste sources (see quick_scan_sources.py). The dpaste
    # source ships disabled pending a search endpoint; the host is pre-allowlisted
    # so enabling it is a one-line change rather than a security review.
    "dpaste.org",
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
    ipaddress.ip_network("64:ff9b:1::/48"),  # local-use NAT64 (RFC 8215)
    ipaddress.ip_network("fec0::/10"),       # site-local (deprecated, RFC 3879)
]

# A name can have several addresses. All of them are checked; the connection is
# tried on at most this many, in order, IPv4 first.
_MAX_PINNED_ADDRESSES = 3

_DEFAULT_HEADERS = {"User-Agent": "OSINTPH/1.0", "Accept": "application/json, */*"}
_REDIRECT_CODES = (301, 302, 303, 307, 308)


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
    if any(ip in net for net in _BLOCKED_NETS):
        return True
    # 6to4 (2002::/16) and Teredo (2001::/32) addresses carry an IPv4 address
    # that the packet is relayed to; judge them by it.
    if ip.version == 6:
        embedded = [ip.sixtofour]
        if ip.teredo:
            embedded.extend(ip.teredo)
        return any(e is not None and _is_private_ip(str(e)) for e in embedded)
    return False


def resolve_and_check_target(host: str) -> list:
    """Resolve host once, check every address, return them (IPv4 first).

    Raises SafeFetchError if the name does not resolve or if any address is
    private, loopback, or otherwise blocked: a name that mixes public and
    internal addresses is refused as a whole. The returned addresses are the
    ones to connect to (see fetch_public and _PinnedAdapter); resolving the
    name again later could give a different answer.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError) as exc:
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
    if not public_ips:
        raise SafeFetchError(f"DNS resolution failed for {host!r}: no addresses")
    public_ips.sort(key=lambda a: ":" in a)  # stable: IPv4 before IPv6
    return public_ips


def _resolve_and_check(hostname: str) -> list:
    """Resolve hostname and raise SafeFetchError if any resolved IP is private."""
    return resolve_and_check_target(hostname)


def check_host_ssrf(hostname: str) -> None:
    """IP-blocklist check without allowlist enforcement.

    Use when the set of target hosts is too large for a static allowlist
    (e.g. the WhatsMyName corpus of 200+ sites). Raises SafeFetchError if the
    hostname resolves to any private or loopback address.

    A check on its own does not bind the request that follows to the address
    that was checked. To fetch from such a host, use fetch_public().
    """
    _resolve_and_check(hostname)


# ── Connecting to the address that was checked ────────────────────────────────


def _host_header(url: str) -> str:
    """Value of the Host header for url: the host name, plus the port if it is not the default."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        host = f"{host}:{parsed.port}"
    return host


class _PinnedAdapter(_HTTPAdapter):
    """Transport adapter that connects to one address that was already checked.

    requests would otherwise hand the host name to the socket layer, which
    resolves it again and may get another answer than the one that passed the
    block list. Here only the TCP connection uses ``address``. The request
    still carries the host name in the Host header, and for HTTPS the host name
    is the TLS server name (SNI) and the name the certificate must match.
    """

    def __init__(self, address: str):
        self._address = address
        super().__init__(max_retries=0)

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(request, verify, cert)
        hostname = host_params["host"]
        host_params["host"] = self._address
        if host_params["scheme"] == "https" and hostname != self._address:
            pool_kwargs["server_hostname"] = hostname
            pool_kwargs["assert_hostname"] = hostname
        return host_params, pool_kwargs

    def send(self, request, **kwargs):
        # http.client fills in Host from the connection target, which is the address.
        request.headers["Host"] = _host_header(request.url)
        return super().send(request, **kwargs)


def _ca_bundle():
    # The session below ignores the environment (no proxy, no .netrc), so the
    # two CA settings requests would have read from it are passed on by hand.
    return os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE") or True


def _pinned_request(method, url, addresses, *, headers, data=None, json_data=None,
                    timeout=15, max_bytes=None):
    """One request without redirects, connected to a checked address.

    Returns (response, body). With max_bytes the body is cut off after that
    many bytes. When an address refuses the connection or does not answer,
    the next checked address is tried.
    """
    last_exc: Optional[Exception] = None
    for address in list(addresses)[:_MAX_PINNED_ADDRESSES]:
        session = _requests.Session()
        session.trust_env = False
        adapter = _PinnedAdapter(address)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        try:
            resp = session.request(
                method,
                url,
                headers=headers,
                data=data,
                json=json_data,
                timeout=timeout,
                allow_redirects=False,
                verify=_ca_bundle(),
                stream=max_bytes is not None,
            )
            if max_bytes is None:
                return resp, resp.content
            try:
                body = resp.raw.read(max_bytes, decode_content=True) if max_bytes > 0 else b""
            finally:
                resp.close()
            return resp, body
        except _requests.exceptions.SSLError:
            raise
        except _requests.exceptions.ConnectionError as exc:
            last_exc = exc
        finally:
            session.close()
    if last_exc is None:
        raise SafeFetchError(f"Blocked: no checked address to connect to for {url!r}")
    raise last_exc


def _send(method, url, addresses, *, headers, data=None, json_data=None, timeout=15, max_bytes=None):
    """_pinned_request with every transport error turned into SafeFetchError."""
    try:
        return _pinned_request(
            method, url, addresses,
            headers=headers, data=data, json_data=json_data, timeout=timeout, max_bytes=max_bytes,
        )
    except _requests.exceptions.SSLError as exc:
        raise SafeFetchError(
            f"TLS verification failed for {url!r}: {exc}"
        ) from exc
    except _requests.exceptions.Timeout as exc:
        raise SafeFetchError(
            f"Request timed out for {url!r}: {exc}"
        ) from exc
    except _requests.exceptions.ConnectionError as exc:
        raise SafeFetchError(
            f"Connection failed for {url!r}: {exc}"
        ) from exc
    except _requests.exceptions.RequestException as exc:
        raise SafeFetchError(
            f"Request failed for {url!r}: {exc}"
        ) from exc
    except (OSError, ValueError) as exc:  # e.g. the connection dropped while the body was read
        raise SafeFetchError(
            f"Request failed for {url!r}: {exc}"
        ) from exc


def _origin(url: str) -> tuple:
    parsed = urlparse(url)
    return (parsed.scheme, (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme == "https" else 80))


def _result(resp, body: bytes, url: str) -> dict:
    return {
        "status": resp.status_code,
        "headers": dict(resp.headers),
        "body": body,
        "url": url,
    }


def _validate_url(url: str) -> list:
    """Enforce HTTPS, allowlist membership, and IP blocklist. Raises SafeFetchError.

    Returns the checked addresses of the host, for the connection to use.
    """
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
    if parsed.username is not None or parsed.password is not None:
        raise SafeFetchError("Blocked: credentials in the URL are not permitted")
    return _resolve_and_check(host)


def safe_fetch(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict] = None,
    data: Optional[bytes] = None,
    json_data: Optional[dict] = None,
    timeout: int = 15,
    allow_redirects: bool = False,
    max_bytes: Optional[int] = None,
) -> dict:
    """Hardened HTTP fetch with HTTPS enforcement, host allowlist, and IP blocklist.

    Returns {"status": int, "headers": dict, "body": bytes, "url": str}.
    Raises SafeFetchError for any policy violation or network/TLS error.

    The host is resolved once per hop and the connection goes to a checked
    address. With allow_redirects=True, a redirect to another host is followed
    for GET and HEAD only, and the caller's headers (API keys among them) are
    not sent to that host. max_bytes cuts the body off after that many bytes.

    The Tor SOCKS5 crawler path is explicitly excluded; do not route .onion
    traffic through this function.
    """
    addresses = _validate_url(url)

    _hdrs = dict(_DEFAULT_HEADERS)
    if headers:
        _hdrs.update(headers)

    def _do_request(target_url: str, target_addresses: list, req_method: str, req_headers: dict,
                    req_data, req_json):
        return _send(
            req_method, target_url, target_addresses,
            headers=req_headers, data=req_data, json_data=req_json, timeout=timeout, max_bytes=max_bytes,
        )

    if not allow_redirects:
        resp, body = _do_request(url, addresses, method, _hdrs, data, json_data)
        return _result(resp, body, resp.url)

    # Manual redirect following with re-validation at each hop (max 3 redirects)
    current_url = url
    cur_addresses = addresses
    cur_method = method
    cur_headers = _hdrs
    cur_data = data
    cur_json = json_data

    for hop in range(4):
        resp, body = _do_request(current_url, cur_addresses, cur_method, cur_headers, cur_data, cur_json)
        if resp.status_code not in _REDIRECT_CODES:
            return _result(resp, body, resp.url)
        if hop == 3:
            raise SafeFetchError(
                f"Blocked: redirect chain exceeded 3 hops starting at {url!r}"
            )
        location = resp.headers.get("Location", "")
        if not location:
            raise SafeFetchError("Blocked: redirect response has no Location header")
        next_url = urljoin(current_url, location)
        cur_addresses = _validate_url(next_url)
        # Standard browser behaviour: downgrade POST → GET on 301/302/303
        if resp.status_code in (301, 302, 303) and cur_method not in ("GET", "HEAD"):
            cur_method = "GET"
            cur_data = None
            cur_json = None
        if _origin(next_url) != _origin(url):
            # Another host: the caller's headers and body were meant for the first one.
            if cur_method not in ("GET", "HEAD"):
                raise SafeFetchError(
                    f"Blocked: {cur_method} redirected to another host by {current_url!r}"
                )
            cur_headers = dict(_DEFAULT_HEADERS)
        current_url = next_url

    raise SafeFetchError("redirect loop terminated unexpectedly")  # pragma: no cover


def fetch_public(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict] = None,
    timeout: int = 10,
    max_bytes: Optional[int] = None,
    https_only: bool = True,
    addresses: Optional[list] = None,
) -> dict:
    """Fetch from a host that cannot be on the allowlist, without leaving the public internet.

    For recon probes of discovered hosts and for the WhatsMyName sites. The
    host name is resolved once, every address is checked against the IP
    blocklist, and the connection goes to a checked address. Redirects are
    never followed: a 3xx answer is returned as it is, for the caller to
    record its Location as data.

    addresses: the result of an earlier resolve_and_check_target() for the
    same host, to resolve once for several requests. Each one is checked again.
    max_bytes: cut the body off after that many bytes (0: headers only).

    Returns {"status": int, "headers": dict, "body": bytes, "url": str}.
    Raises SafeFetchError for any policy violation or network/TLS error.
    """
    parsed = urlparse(url)
    if parsed.scheme not in (("https",) if https_only else ("https", "http")):
        raise SafeFetchError(
            f"Blocked: scheme {parsed.scheme!r} is not permitted"
        )
    try:
        parsed.port  # raises ValueError for a port that is not a number
    except ValueError as exc:
        raise SafeFetchError(f"Blocked: invalid port in {url!r}") from exc
    host = (parsed.hostname or "").lower()
    if not host:
        raise SafeFetchError(f"Blocked: no host in {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise SafeFetchError("Blocked: credentials in the URL are not permitted")
    if host == "onion" or host.endswith(".onion"):
        raise SafeFetchError("Blocked: .onion hosts are reached through Tor, not from this host")

    if addresses is None:
        addresses = resolve_and_check_target(host)
    else:
        addresses = list(addresses)
        for addr in addresses:
            if _is_private_ip(addr):
                raise SafeFetchError(
                    f"Blocked: {host!r} resolves to a private/loopback address {addr!r}"
                )
        if not addresses:
            raise SafeFetchError(f"Blocked: no checked address for {host!r}")

    _hdrs = {"User-Agent": _DEFAULT_HEADERS["User-Agent"], "Accept": "*/*"}
    if headers:
        _hdrs.update(headers)

    resp, body = _send(method, url, addresses, headers=_hdrs, timeout=timeout, max_bytes=max_bytes)
    return _result(resp, body, url)


def safe_fetch_json(url: str, **kwargs) -> tuple:
    """Convenience wrapper: safe_fetch + JSON decode.

    Returns (status_code, parsed_dict). Raises SafeFetchError on JSON failure.
    """
    result = safe_fetch(url, **kwargs)
    try:
        return result["status"], _json.loads(result["body"])
    except Exception as exc:
        raise SafeFetchError(f"JSON decode failed for {url!r}: {exc}") from exc
