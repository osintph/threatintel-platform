"""
DNS Crawler — passive + active DNS reconnaissance.
Sources: dnspython (active), crt.sh (passive CT logs),
         HackerTarget (passive), ipwho.is (geolocation, over HTTPS).
No paid API keys required.

Recon is for public domain names only. A name that is not a public, fully
qualified domain name is refused (check_public_domain), and so is one that
resolves to an internal address when the recon starts: inside the Docker
network a name such as ``postgres`` or ``postgres.<network>`` resolves to a
container. Addresses that are not public are left out of every result, and no
reverse lookup is made for them.

Everything that fans out (resolving, probing, port checks) runs on the shared
pool in dashboard/jobs.py; nothing here starts threads of its own.
"""

import ipaddress
import json
import logging
import re
import socket
import unicodedata
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote, urlencode, urljoin, urlparse

from .dashboard import http_client, jobs
from .dashboard.upstream_cache import TTLCache

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10
DNS_TIMEOUT = 5
# How many of one operation's lookups or probes are in the shared pool at a time.
FAN_OUT = 12


# ── Helpers ────────────────────────────────────────────────────────────────────

def _clean_domain(domain: str) -> str:
    """Strip protocol, path, trailing dots."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"/.*$", "", domain)
    domain = domain.rstrip(".")
    return domain


# A probe target: a host name or IPv4 address, optionally with a port.
_PROBE_TARGET_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$", re.IGNORECASE)


def _probe_host(target: str) -> Optional[str]:
    """Host part of a probe target, or None when the target is not a plain host[:port]."""
    if not _PROBE_TARGET_RE.match(target or ""):
        return None
    try:
        parsed = urlparse(f"//{target}")
        parsed.port  # raises ValueError when out of range
        return parsed.hostname
    except ValueError:
        return None


def _clean_text(value, max_len: int) -> str:
    """Text taken from a probed host, kept as data: one line, no control or
    invisible formatting characters, at most max_len characters."""
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in str(value or ""))
    return " ".join(text.split())[:max_len]


def _redirect_target(url: str, location: str, max_len: int) -> str:
    """The Location of a 3xx answer as an absolute URL, for display only. It is never requested."""
    try:
        location = urljoin(url, location)
    except ValueError:
        pass
    return _clean_text(location, max_len)


# ── Public names only ──────────────────────────────────────────────────────────

NOT_PUBLIC = "Enter a public domain name, such as example.com"
RESOLVES_INTERNALLY = "This name resolves to an address that is not public, so recon was not run"

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_TLD_RE = re.compile(r"^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
# Top-level names that are never delegated in the public DNS (RFC 6761, RFC 6762,
# RFC 8375, ICANN's reserved list) and the ones private networks commonly use.
_NON_PUBLIC_TLDS = frozenset({
    "local", "localhost", "localdomain", "internal", "intranet", "private", "lan",
    "home", "corp", "test", "invalid", "example", "onion", "arpa",
})


class NotPublicName(ValueError):
    """``message`` is written for the user."""

    def __init__(self, message: str = NOT_PUBLIC):
        super().__init__(message)
        self.message = message


def check_public_domain(name: str) -> str:
    """``name`` as a lower-case public FQDN, or NotPublicName.

    Refused: a single label (``postgres``), an IP address, a name under a
    top-level name that only exists inside private networks, and anything that
    is not a host name. No DNS query is made; see resolves_internally().
    """
    name = str(name or "").strip().lower().rstrip(".")
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2:
        raise NotPublicName(NOT_PUBLIC)
    try:
        ipaddress.ip_address(name)
        raise NotPublicName(NOT_PUBLIC)
    except ValueError as exc:
        if isinstance(exc, NotPublicName):
            raise
    if not all(_LABEL_RE.match(label) for label in labels):
        raise NotPublicName(NOT_PUBLIC)
    if not _TLD_RE.match(labels[-1]) or labels[-1] in _NON_PUBLIC_TLDS:
        raise NotPublicName(NOT_PUBLIC)
    return name


def _is_public_name(name: str) -> bool:
    try:
        check_public_domain(name)
        return True
    except NotPublicName:
        return False


def resolves_internally(name: str) -> bool:
    """True when the resolver this process uses gives ``name`` an address that is not public.

    That resolver also knows the names of the private network the app runs in
    (Docker's service names, a tailnet). A name with no address at all is not
    internal: a domain may have no A record.
    """
    try:
        infos = socket.getaddrinfo(name, None)
    except (OSError, UnicodeError):
        return False
    return any(http_client._is_private_ip(info[4][0]) for info in infos)


def _public_addresses(values: list) -> list:
    return [v for v in values if not http_client._is_private_ip(v)]


def _under(name: str, domain: str) -> bool:
    """True for ``domain`` itself and for names below it. ``notexample.com`` is not under ``example.com``."""
    return name == domain or name.endswith(f".{domain}")


# ── Active DNS resolution ──────────────────────────────────────────────────────

def query_dns_records(domain: str) -> dict:
    """
    Query all common DNS record types directly.
    Returns dict of record_type -> list of values.
    """
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        logger.error("dnspython not installed")
        return {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    results = {}

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            values = []
            for rdata in answers:
                val = rdata.to_text()
                # Clean up trailing dots
                if val.endswith("."):
                    val = val[:-1]
                values.append(val)
            if values:
                results[rtype] = values
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.exception.DNSException):
            pass
        except Exception as e:
            logger.debug(f"DNS {rtype} query for {domain} failed: {e}")

    return results


def attempt_zone_transfer(domain: str) -> dict:
    """
    Attempt AXFR zone transfer against all NS servers.
    Returns results per nameserver.
    """
    try:
        import dns.exception
        import dns.query
        import dns.resolver
        import dns.zone
    except ImportError:
        return {"error": "dnspython not installed"}

    results = {}
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=DNS_TIMEOUT)
        nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answers]
    except Exception as e:
        logger.debug("NS lookup for %s failed: %s", domain, e)
        return {"error": "Could not resolve NS records"}

    for ns in nameservers:
        # The NS name comes from the zone under investigation. One that is not a
        # public name, or does not have a public address, gets the same answer
        # whether or not it exists here.
        if not _is_public_name(ns):
            results[ns] = {"success": False, "error": "Skipped: not a public name server"}
            continue
        try:
            ns_ip = socket.gethostbyname(ns)
            if http_client._is_private_ip(ns_ip):
                results[ns] = {"success": False, "error": "Skipped: not a public name server"}
                logger.warning("Zone transfer blocked: %r resolves to private IP %r", ns, ns_ip)
                continue
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=DNS_TIMEOUT))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "value": rdata.to_text().rstrip("."),
                        })
            results[ns] = {
                "success": True,
                "record_count": len(records),
                "records": records[:200],  # cap output
            }
            logger.warning(f"ZONE TRANSFER SUCCEEDED on {ns} for {domain}")
        except Exception as e:
            logger.debug("Zone transfer from %s for %s failed: %s", ns, domain, e)
            results[ns] = {"success": False, "error": "Transfer refused or failed"}

    return results


def reverse_dns(ip: str) -> Optional[str]:
    """PTR lookup for a public IP. No lookup is made for any other address."""
    if http_client._is_private_ip(ip):
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_ip(hostname: str) -> list[str]:
    """Resolve hostname to IPs."""
    try:
        info = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in info})
    except Exception:
        return []


# ── Passive: certificate transparency (crt.sh) ────────────────────────────────

def fetch_crtsh(domain: str) -> list[dict]:
    """
    Query crt.sh for all certificates issued for domain.
    Returns list of subdomains with cert metadata.
    """
    # Use safe_fetch: crt.sh is allowlisted, TLS verified, IP pre-checked.
    try:
        result = http_client.safe_fetch(
            "https://crt.sh/?" + urlencode({"q": f"%.{domain}", "output": "json"}),
            headers={"User-Agent": "OSINTPH-DNSCrawler/1.0"},
            timeout=REQUEST_TIMEOUT,
        )
    except http_client.SafeFetchError:
        return []
    if result["status"] != 200:
        return []

    try:
        data = json.loads(result["body"])
    except Exception:
        return []

    seen = set()
    results = []
    for entry in data:
        # name_value can contain \n-separated SANs
        names = entry.get("name_value", "").split("\n")
        for name in names:
            name = name.strip().lower().lstrip("*.")
            if not name or name in seen:
                continue
            if not _under(name, domain):
                continue
            seen.add(name)
            results.append({
                "subdomain": name,
                "issuer": entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "cert_id": entry.get("id"),
            })

    # Sort: base domain first, then alphabetically
    results.sort(key=lambda x: (x["subdomain"] != domain, x["subdomain"]))
    return results


# ── Passive: HackerTarget DNS lookup ──────────────────────────────────────────

def _hackertarget(tool: str, domain: str) -> Optional[str]:
    """The text answer of one HackerTarget tool for ``domain``, or None."""
    try:
        result = http_client.safe_fetch(
            f"https://api.hackertarget.com/{tool}/?" + urlencode({"q": domain}),
            headers={"User-Agent": "OSINTPH-DNSCrawler/1.0"},
            timeout=REQUEST_TIMEOUT,
            max_bytes=2 * 1024 * 1024,
        )
    except http_client.SafeFetchError as e:
        logger.debug("HackerTarget %s for %s failed: %s", tool, domain, e)
        return None
    if result["status"] != 200:
        return None
    return result["body"].decode("utf-8", errors="replace")


def fetch_hackertarget(domain: str) -> list[str]:
    """
    HackerTarget free API for subdomain enumeration.
    Returns list of subdomains (free tier: 20 results).
    """
    text = _hackertarget("hostsearch", domain)
    if text is None:
        return []

    subdomains = []
    for line in text.splitlines():
        parts = line.strip().split(",")
        if parts and _under(parts[0].strip().lower(), domain):
            subdomains.append(parts[0].strip().lower())
    return subdomains


# ── Passive: DNS history via HackerTarget ─────────────────────────────────────

def fetch_dns_history(domain: str) -> list[dict]:
    """Fetch DNS history from HackerTarget."""
    text = _hackertarget("dnslookup", domain)
    if text is None:
        return []
    records = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("error"):
            records.append({"raw": line})
    return records


# ── Passive: ASN / IP geolocation ─────────────────────────────────────────────

GEO_SOURCE = "ipwho.is"
GEO_TIMEOUT = 8
# ipwho.is answers over HTTPS without a key, one address per request, 1,000
# requests a day. So: an address is asked for once a day at most, a recon asks
# for at most GEO_MAX_IPS addresses it has not seen, and the process stops
# asking before the day's allowance is gone.
GEO_MAX_IPS = 30
GEO_DAILY_LIMIT = 900

_geo_cache = TTLCache("geolocation", ttl=86400, stale_for=6 * 86400, error_ttl=600, max_entries=5000)
_geo_window = jobs.RateWindow(GEO_DAILY_LIMIT, per=86400.0)


class GeoError(Exception):
    """The geolocation service gave no usable answer for an address."""


def _geolocate_one(ip: str) -> Optional[dict]:
    """Geolocation of one public address, in the field names the pages and the PDF use."""
    def fetch():
        if not _geo_window.try_take():
            raise GeoError("the daily allowance is used up")
        result = http_client.safe_fetch(
            f"https://{GEO_SOURCE}/{quote(ip, safe=':')}",
            headers={"User-Agent": "OSINTPH-DNSCrawler/1.0"},
            timeout=GEO_TIMEOUT,
            max_bytes=65536,
        )
        if result["status"] != 200:
            raise GeoError(f"HTTP {result['status']}")
        data = json.loads(result["body"])
        if not isinstance(data, dict) or not data.get("success"):
            raise GeoError("no data for this address")
        conn = data.get("connection") if isinstance(data.get("connection"), dict) else {}
        org = str(conn.get("org") or "")
        asn = conn.get("asn")
        return {
            "status": "success",
            "country": str(data.get("country") or ""),
            "countryCode": str(data.get("country_code") or ""),
            "regionName": str(data.get("region") or ""),
            "city": str(data.get("city") or ""),
            "org": org,
            "as": f"AS{asn} {org}".strip() if asn else "",
            "isp": str(conn.get("isp") or ""),
            "query": ip,
        }

    return _geo_cache.get(ip, fetch)


def geolocate_ips(ips: list[str]) -> dict[str, dict]:
    """
    Geolocate public IPs with ipwho.is (HTTPS, no key).
    Returns dict of ip -> geo data. Addresses that are not public are not sent
    anywhere. At most GEO_MAX_IPS addresses that are not in the cache are
    looked up per call; the rest are left out.
    """
    found: dict = {}
    todo = []
    for ip in dict.fromkeys(ips):
        if http_client._is_private_ip(ip):
            continue
        known = _geo_cache.peek(ip)
        if known is not None:
            found[ip] = known
        elif len(todo) < GEO_MAX_IPS:
            todo.append(ip)
    for ip, geo in zip(todo, jobs.fan_out(_geolocate_one, todo, parallel=6, timeout=3 * GEO_TIMEOUT)):
        if geo:
            found[ip] = geo
    return found


# ── SPF / DMARC / DKIM analysis ───────────────────────────────────────────────

def analyze_email_security(domain: str, dns_records: dict) -> dict:
    """Analyse SPF, DMARC, DKIM from already-fetched DNS records."""
    analysis = {
        "spf": None,
        "spf_valid": False,
        "dmarc": None,
        "dmarc_valid": False,
        "dkim_selectors_found": [],
        "issues": [],
    }

    # SPF
    for txt in dns_records.get("TXT", []):
        if txt.startswith('"v=spf1') or txt.startswith("v=spf1"):
            analysis["spf"] = txt.strip('"')
            analysis["spf_valid"] = True
            break
    if not analysis["spf_valid"]:
        analysis["issues"].append("No SPF record — domain vulnerable to email spoofing")

    # DMARC
    try:
        import dns.exception
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DNS_TIMEOUT)
        for rdata in answers:
            val = rdata.to_text().strip('"')
            if "v=DMARC1" in val:
                analysis["dmarc"] = val
                analysis["dmarc_valid"] = True
                if "p=none" in val:
                    analysis["issues"].append("DMARC policy is 'none' — monitoring only, no enforcement")
                break
    except Exception:
        pass
    if not analysis["dmarc_valid"]:
        analysis["issues"].append("No DMARC record — email authentication not enforced")

    # DKIM — check common selectors
    common_selectors = ["default", "google", "k1", "k2", "mail", "dkim", "selector1", "selector2", "smtp", "email"]
    try:
        import dns.exception
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        for sel in common_selectors:
            try:
                resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=2)
                analysis["dkim_selectors_found"].append(sel)
            except Exception:
                pass
    except Exception:
        pass

    return analysis


# ── Subdomain resolution with geolocation ─────────────────────────────────────

def resolve_subdomains(subdomains: list[str], max_workers: int = 20) -> list[dict]:
    """
    Resolve a list of subdomains to IPs in parallel, then geolocate.
    Private IPs are filtered from results before returning.
    """
    def resolve_one(sub: str) -> Optional[dict]:
        ips = resolve_ip(sub)
        if ips:
            public_ips = _public_addresses(ips)
            if public_ips:
                return {"subdomain": sub, "ips": public_ips}
        return None

    found = jobs.fan_out(resolve_one, subdomains[:300], parallel=min(max_workers, FAN_OUT), timeout=90)
    resolved = [r for r in found if r]

    # Geolocate all unique IPs
    all_ips = list({ip for r in resolved for ip in r["ips"]})
    geo = geolocate_ips(all_ips)
    for r in resolved:
        r["geo"] = [geo.get(ip, {}) for ip in r["ips"]]

    resolved.sort(key=lambda x: x["subdomain"])
    return resolved


# ── Master recon function ──────────────────────────────────────────────────────

def run_dns_recon(domain: str) -> dict:
    """
    Full DNS reconnaissance on a domain.
    Runs passive (crt.sh, HackerTarget) and active (dnspython) in parallel.
    Returns structured result dict suitable for storage and display.
    """
    domain = check_public_domain(_clean_domain(domain))
    if resolves_internally(domain):
        raise NotPublicName(RESOLVES_INTERNALLY)
    started_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    logger.info(f"Starting DNS recon for {domain}")

    result = {
        "domain": domain,
        "started_at": started_at,
        "dns_records": {},
        "zone_transfer": {},
        "subdomains_passive": [],
        "subdomains_resolved": [],
        "email_security": {},
        "errors": [],
    }

    # ── Phase 1: parallel passive + active fetch ──
    phase1 = jobs.call_all({
        "DNS records": lambda: query_dns_records(domain),
        "crt.sh": lambda: fetch_crtsh(domain),
        "HackerTarget": lambda: fetch_hackertarget(domain),
        "Zone transfer": lambda: attempt_zone_transfer(domain),
    }, timeout=45)
    for step, answer in phase1.items():
        if answer is None:
            result["errors"].append(f"{step}: no answer in time")
    result["dns_records"] = phase1["DNS records"] or {}
    result["subdomains_passive"] = phase1["crt.sh"] or []
    ht_subs = phase1["HackerTarget"] or []
    result["zone_transfer"] = phase1["Zone transfer"] or {}

    # Address records that are not public are left out: this process's resolver
    # also answers for the private network it runs in.
    left_out = 0
    for rtype in ("A", "AAAA"):
        values = result["dns_records"].get(rtype, [])
        public = _public_addresses(values)
        left_out += len(values) - len(public)
        if public:
            result["dns_records"][rtype] = public
        else:
            result["dns_records"].pop(rtype, None)
    if left_out:
        result["errors"].append(f"{left_out} address record(s) that are not public were left out")

    # Geolocate the main IPs first: they come before the subdomains' addresses
    # in the per-recon allowance of new lookups.
    main_ips = result["dns_records"].get("A", [])
    result["ip_geo"] = geolocate_ips(main_ips[:20])
    result["geo_source"] = GEO_SOURCE

    # ── Phase 2: merge + deduplicate subdomains ──
    crt_subs = {e["subdomain"] for e in result["subdomains_passive"]}
    all_subs = crt_subs | set(ht_subs)
    # Add NS/MX hostnames
    for ns in result["dns_records"].get("NS", []):
        if ns.endswith(f".{domain}") or ns == domain:
            all_subs.add(ns)
    for mx in result["dns_records"].get("MX", []):
        # MX format: "10 mail.example.com"
        parts = mx.split()
        host = parts[-1] if parts else mx
        if host.endswith(f".{domain}"):
            all_subs.add(host)

    # ── Phase 2b: active brute-force subdomain enumeration ──
    try:
        bf_results = brute_force_subdomains(domain)
        result["subdomains_bruteforce"] = bf_results
        for r in bf_results:
            all_subs.add(r["subdomain"])
        logger.info(f"Brute-force added {len(bf_results)} new subdomains for {domain}")
    except Exception:
        logger.exception("Brute-force for %s failed", domain)
        result["errors"].append("Brute-force: failed")
        result["subdomains_bruteforce"] = []

    # ── Phase 3: resolve all subdomains ──
    result["subdomains_resolved"] = resolve_subdomains(list(all_subs))

    # ── Phase 4: email security analysis ──
    result["email_security"] = analyze_email_security(domain, result["dns_records"])

    # ── Phase 5: reverse DNS on main A records (public addresses only, see Phase 1) ──
    ptr_ips = main_ips[:10]
    ptr_records = {ip: ptr for ip, ptr in zip(ptr_ips, jobs.fan_out(reverse_dns, ptr_ips, parallel=FAN_OUT, timeout=30)) if ptr}
    result["ptr_records"] = ptr_records

    # ── Phase 6: geolocation — done after Phase 1; say so when addresses are missing ──
    located = set(result["ip_geo"]) | {g.get("query") for r in result["subdomains_resolved"] for g in r.get("geo", []) if g}
    wanted = set(main_ips[:20]) | {ip for r in result["subdomains_resolved"] for ip in r["ips"]}
    if wanted - located:
        result["errors"].append(
            f"Geolocation: {len(wanted & located)} of {len(wanted)} addresses located "
            f"(at most {GEO_MAX_IPS} new lookups per recon, or {GEO_SOURCE} did not answer)"
        )

    # ── Phase 7: HTTP banner / service probe ──
    try:
        result["services"] = probe_services(list(all_subs)[:40])
    except Exception:
        logger.exception("Service probe for %s failed", domain)
        result["services"] = {}
        result["errors"].append("Service probe: failed")

    result["completed_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    result["subdomain_count"] = len(all_subs)
    result["resolved_count"] = len(result["subdomains_resolved"])

    logger.info(
        f"DNS recon complete for {domain}: "
        f"{result['subdomain_count']} subdomains, "
        f"{result['resolved_count']} resolved"
    )
    return result


# ── Port Scanner (Scilla-inspired) ─────────────────────────────────────────────

# Common ports with service names — mirrors Scilla's default port list
COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (587, "SMTP-Sub"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (8888, "Dev-HTTP"),
    (9200, "Elasticsearch"),
    (27017, "MongoDB"),
    (11211, "Memcached"),
    (2181, "Zookeeper"),
    (6443, "K8s-API"),
    (9090, "Prometheus"),
]

PORT_SCAN_TIMEOUT = 1.5  # seconds per port — keep fast


def scan_port(host: str, port: int, timeout: float = PORT_SCAN_TIMEOUT) -> str:
    """
    Attempt TCP connect to host:port.
    Returns 'open', 'closed', or 'filtered'.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return "open" if result == 0 else "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"


def scan_ports(host: str, ports: list[tuple] = None, max_workers: int = 50) -> list[dict]:
    """
    Scan a list of (port, service) tuples against host in parallel.
    Returns list of {port, service, status} sorted by port number.
    """
    if ports is None:
        ports = COMMON_PORTS

    def check(port_svc):
        port, svc = port_svc
        status = scan_port(host, port)
        return {"port": port, "service": svc, "status": status}

    results = [r for r in jobs.fan_out(check, ports, parallel=min(max_workers, FAN_OUT), timeout=120) if r]
    results.sort(key=lambda x: x["port"])
    return results


def scan_ports_multi(hosts: list[str], max_workers: int = 30) -> dict[str, list[dict]]:
    """
    Scan all COMMON_PORTS against multiple hosts in parallel.
    Returns dict of host -> list of port results.
    Private/reserved IPs are skipped and logged.
    """
    results = {}

    safe_hosts = []
    for h in hosts[:10]:  # cap at 10 hosts
        if http_client._is_private_ip(h):
            logger.warning("scan_ports_multi: skipping private/reserved IP %r", h)
        else:
            safe_hosts.append(h)

    # One host after the other; each host's ports go through the shared pool.
    for host in safe_hosts:
        results[host] = scan_ports(host, COMMON_PORTS, max_workers=max_workers)

    return results


# ── Subdomain Brute-Force (Scilla-inspired) ────────────────────────────────────

# Built-in wordlist — common subdomain prefixes used by Scilla
SUBDOMAIN_WORDLIST = [
    "www", "mail", "email", "webmail", "smtp", "pop", "imap",
    "ftp", "ftps", "sftp", "ssh",
    "api", "api2", "api-v1", "api-v2", "rest", "graphql",
    "dev", "development", "staging", "stage", "stg", "preprod", "uat",
    "test", "testing", "sandbox", "demo", "preview",
    "admin", "administrator", "backend", "cms", "portal", "dashboard",
    "panel", "control", "manage", "management", "console",
    "app", "apps", "mobile", "m", "wap",
    "vpn", "remote", "access", "citrix", "rdp", "ras",
    "intranet", "internal", "corp", "corporate", "extranet",
    "cdn", "assets", "static", "media", "img", "images", "files",
    "download", "downloads", "upload", "uploads",
    "blog", "forum", "support", "help", "docs", "wiki", "kb",
    "shop", "store", "pay", "payment", "billing", "invoice",
    "auth", "login", "sso", "oauth", "id", "accounts",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
    "monitor", "status", "health", "metrics", "grafana", "kibana",
    "git", "gitlab", "github", "bitbucket", "svn", "code", "repo",
    "ci", "cd", "jenkins", "build", "deploy",
    "proxy", "gateway", "lb", "loadbalancer", "ha",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay", "bounce",
    "backup", "archive", "old", "legacy", "v1", "v2",
    "secure", "ssl", "tls",
    "cloud", "aws", "azure", "gcp",
    "search", "es", "elastic",
    "chat", "jabber", "xmpp", "slack", "teams",
    "crm", "erp", "hr", "finance",
    "video", "stream", "media", "live",
    "web", "web1", "web2", "www2", "www3",
    "server", "server1", "server2", "host",
    "mail2", "mail3", "smtp2",
    "vps", "vps1", "vps2",
    "new", "beta", "alpha",
    "reports", "reporting", "analytics", "data",
]


def brute_force_subdomains(domain: str, wordlist: list[str] = None, max_workers: int = 50) -> list[dict]:
    """
    Actively brute-force subdomains by DNS resolution against a wordlist.
    Returns list of {subdomain, ips} for each that resolves to a public IP.
    """
    if wordlist is None:
        wordlist = SUBDOMAIN_WORDLIST

    candidates = list(dict.fromkeys(f"{word}.{domain}" for word in wordlist))

    def try_resolve(fqdn: str) -> Optional[dict]:
        ips = resolve_ip(fqdn)
        if ips:
            public_ips = _public_addresses(ips)
            if public_ips:
                return {"subdomain": fqdn, "ips": public_ips, "source": "bruteforce"}
        return None

    answers = jobs.fan_out(try_resolve, candidates, parallel=min(max_workers, FAN_OUT), timeout=90)
    found = [r for r in answers if r]

    found.sort(key=lambda x: x["subdomain"])
    logger.info(f"Brute-force found {len(found)} subdomains for {domain}")
    return found


# ── Directory Enumeration (Scilla-inspired) ────────────────────────────────────

# Common web paths — mirrors Scilla's built-in dir list
DIR_WORDLIST = [
    "/", "/admin", "/admin/", "/administrator", "/administrator/",
    "/login", "/login/", "/signin", "/wp-admin", "/wp-admin/",
    "/wp-login.php", "/wp-content/", "/wp-includes/",
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/swagger", "/api/docs", "/swagger", "/swagger-ui.html",
    "/openapi.json", "/graphql",
    "/dashboard", "/dashboard/", "/portal", "/panel",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/myadmin",
    "/cpanel", "/webmail", "/roundcube",
    "/backup", "/backup/", "/backups",
    "/.env", "/.git", "/.git/config", "/.git/HEAD",
    "/.htaccess", "/web.config", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info",
    "/status", "/health", "/healthz", "/ping",
    "/metrics", "/actuator", "/actuator/health",
    "/console", "/h2-console",
    "/uploads", "/upload", "/files", "/static", "/assets",
    "/images", "/img", "/media",
    "/config", "/config.php", "/configuration.php",
    "/install", "/install.php", "/setup", "/setup.php",
    "/test", "/test.php", "/info.php", "/phpinfo.php",
    "/shell.php", "/cmd.php",
    "/old", "/old/", "/legacy", "/bak",
    "/cgi-bin", "/cgi-bin/",
    "/js", "/css",
    "/logout", "/signout",
    "/register", "/signup",
    "/forgot", "/reset",
    "/search",
    "/404", "/500",
]

HTTP_TIMEOUT = 5


def enumerate_directories(
    target: str,
    paths: list[str] = None,
    max_workers: int = 20,
) -> list[dict]:
    """
    Actively probe HTTP/HTTPS for each path in the wordlist.
    target: hostname or IP (no protocol prefix)
    Returns list of {path, url, status_code, content_length, redirect_to}
    for any path that returns a non-404 response.

    The target is resolved once, every address is checked, and all requests go
    to a checked address. Redirects are not followed; the Location of a 3xx
    answer is reported as redirect_to.
    """
    SafeFetchError = http_client.SafeFetchError
    fetch_public = http_client.fetch_public
    resolve_and_check_target = http_client.resolve_and_check_target

    host = _probe_host(target)
    if not host:
        logger.warning("enumerate_directories: %r is not a host name or address", target)
        return []
    try:
        addresses = resolve_and_check_target(host)
    except SafeFetchError as e:
        logger.warning("enumerate_directories: %r blocked by SSRF guard — %s", target, e)
        return []

    if paths is None:
        paths = DIR_WORDLIST

    protocols = ["https", "http"]
    scan_headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINTPH-DirScan/1.0)"}

    # First figure out which protocol is reachable.
    # TLS verification is enforced (verify=True). Targets with self-signed
    # certs will fail the HTTPS probe and fall through to HTTP.
    base_url = None
    for proto in protocols:
        try:
            fetch_public(
                f"{proto}://{target}/",
                method="HEAD",
                headers=scan_headers,
                timeout=HTTP_TIMEOUT,
                max_bytes=0,
                https_only=False,
                addresses=addresses,
            )
            base_url = f"{proto}://{target}"
            break
        except SafeFetchError:
            continue

    if not base_url:
        logger.debug(f"Dir enum: {target} unreachable on HTTP/HTTPS")
        return []

    def probe(path: str) -> Optional[dict]:
        url = base_url + path
        try:
            r = fetch_public(
                url,
                headers=scan_headers,
                timeout=HTTP_TIMEOUT,
                max_bytes=0,
                https_only=False,
                addresses=addresses,
            )
        except SafeFetchError:
            return None
        status_code = r["status"]
        # Skip boring 404s and common irrelevant codes
        if status_code in (404, 410):
            return None
        hdrs = {k.lower(): v for k, v in r["headers"].items()}
        redirect_to = ""
        if status_code in (301, 302, 303, 307, 308) and hdrs.get("location"):
            redirect_to = _redirect_target(url, hdrs["location"], REDIRECT_MAX_LEN)
        return {
            "path": path,
            "url": url,
            "status_code": status_code,
            "content_length": _clean_text(hdrs.get("content-length", ""), 20),
            "redirect_to": redirect_to,
        }

    results = [r for r in jobs.fan_out(probe, paths, parallel=min(max_workers, FAN_OUT), timeout=120) if r]
    results.sort(key=lambda x: x["status_code"])
    logger.info(f"Dir enum on {target}: {len(results)} non-404 paths found")
    return results


def run_port_and_dir_scan(domain: str, ips: list[str]) -> dict:
    """
    Run port scan + directory enumeration for a domain and its resolved IPs.
    Called separately from run_dns_recon (on-demand from the dashboard).
    Returns {port_scan: {ip: [results]}, dir_enum: {target: [results]}}
    """
    result = {
        "domain": domain,
        "started_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "port_scan": {},
        "dir_enum": {},
        "errors": [],
    }

    # Port scan all resolved IPs
    if ips:
        logger.info(f"Port scanning {len(ips)} IPs for {domain}")
        result["port_scan"] = scan_ports_multi(ips)

    # Dir enum against domain + first IP
    targets = [domain] + ips[:2]
    for target in targets:
        try:
            logger.info(f"Directory enumeration on {target}")
            result["dir_enum"][target] = enumerate_directories(target)
        except Exception:
            logger.exception("Directory enumeration on %s failed", target)
            result["errors"].append(f"Dir enum {target}: failed")

    result["completed_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    return result


# ── HTTP Service / Banner Probe ────────────────────────────────────────────────

HTTP_BANNER_TIMEOUT = 5
HTTP_BANNER_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINTPH-Recon/1.0)"}
HTTP_BANNER_BYTES = 4096  # enough of the body to find a <title>
SERVER_MAX_LEN = 120
TITLE_MAX_LEN = 80
REDIRECT_MAX_LEN = 300

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def probe_service(fqdn: str) -> Optional[dict]:
    """
    Probe a single hostname over HTTPS then HTTP.
    Returns {host, url, status_code, server, title, tech, redirect_to} or None.

    The name is resolved once, every address is checked, and both requests go
    to a checked address. Redirects are not followed: a host that answers 3xx
    is reported with that status and its Location as redirect_to, so a
    redirect cannot send the probe to an internal address. Header and title
    text is stored as data, without control characters and capped in length.
    """
    SafeFetchError = http_client.SafeFetchError
    fetch_public = http_client.fetch_public
    resolve_and_check_target = http_client.resolve_and_check_target

    host = _probe_host(fqdn)
    if not host:
        logger.warning("probe_service: %r is not a host name or address", fqdn)
        return None
    try:
        addresses = resolve_and_check_target(host)
    except SafeFetchError as e:
        logger.warning("probe_service: %r blocked by SSRF guard — %s", fqdn, e)
        return None

    for proto in ("https", "http"):
        url = f"{proto}://{fqdn}"
        try:
            # TLS enforced; targets with invalid certs fall through to HTTP
            resp = fetch_public(
                url,
                headers=HTTP_BANNER_HEADERS,
                timeout=HTTP_BANNER_TIMEOUT,
                max_bytes=HTTP_BANNER_BYTES,
                https_only=False,
                addresses=addresses,
            )
        except SafeFetchError:
            continue

        try:
            status_code = resp["status"]
            hdrs = {k.lower(): v for k, v in resp["headers"].items()}

            server = _clean_text(hdrs.get("server") or hdrs.get("x-powered-by") or "", SERVER_MAX_LEN)
            # Normalise: strip version noise e.g. "nginx/1.18.0" -> "nginx"
            server_clean = server.split("/")[0].strip().lower() if server else ""

            # Extract <title>
            title = ""
            m = _TITLE_RE.search(resp["body"].decode("utf-8", errors="ignore"))
            if m:
                title = _clean_text(m.group(1), TITLE_MAX_LEN)

            # Detect tech stack from headers
            tech = []
            h = {k: v.lower() for k, v in hdrs.items()}
            if "cloudflare" in h.get("server", "") or "cf-ray" in h:
                tech.append("Cloudflare")
            if "x-powered-by" in h:
                tech.append(_clean_text(h["x-powered-by"].split("/")[0].title(), 20))
            if "x-aspnet-version" in h or "x-aspnetmvc-version" in h:
                tech.append("ASP.NET")
            if "x-wp-total" in h or "x-pingback" in h:
                tech.append("WordPress")
            if h.get("x-amz-cf-id") or h.get("x-amz-request-id"):
                tech.append("AWS")
            if "awselb" in server.lower() or "awsalb" in server.lower():
                tech.append("AWS ELB")

            redirect_to = ""
            if status_code in (301, 302, 303, 307, 308) and hdrs.get("location"):
                redirect_to = _redirect_target(url, hdrs["location"], REDIRECT_MAX_LEN)

            return {
                "host": fqdn,
                "url": url,
                "final_url": url,  # redirects are not followed
                "status_code": status_code,
                "server": server_clean or "unknown",
                "server_raw": server,
                "title": title,
                "tech": tech,
                "redirect_to": redirect_to,
                "proto": proto,
            }
        except Exception:
            continue
    return None


def probe_services(hosts: list[str], max_workers: int = 20) -> dict[str, dict]:
    """
    Probe a list of hostnames in parallel.
    Returns dict of host -> probe result.
    """
    probed = jobs.fan_out(probe_service, hosts, parallel=min(max_workers, FAN_OUT), timeout=120)
    results = {r["host"]: r for r in probed if r}
    logger.info(f"Service probe complete: {len(results)}/{len(hosts)} hosts responded")
    return results
