"""
DNS Crawler — passive + active DNS reconnaissance.
Sources: dnspython (active), crt.sh (passive CT logs),
         HackerTarget (passive), ip-api.com (geolocation).
No paid API keys required.
"""

import json
import logging
import re
import socket
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10
DNS_TIMEOUT = 5


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


def _safe_http(url: str, method: str = "get", **kwargs) -> Optional[requests.Response]:
    try:
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        kwargs.setdefault("headers", {"User-Agent": "OSINTPH-DNSCrawler/1.0"})
        return getattr(requests, method)(url, **kwargs)
    except Exception as e:
        logger.debug(f"HTTP {method} {url} failed: {e}")
        return None


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

    from darkweb_scanner.dashboard.http_client import _is_private_ip

    results = {}
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=DNS_TIMEOUT)
        nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answers]
    except Exception as e:
        return {"error": f"Could not resolve NS records: {e}"}

    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns)
            if _is_private_ip(ns_ip):
                results[ns] = {"success": False, "error": "Blocked: nameserver resolves to a private/reserved IP"}
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
            results[ns] = {"success": False, "error": str(e)}

    return results


def reverse_dns(ip: str) -> Optional[str]:
    """PTR lookup for an IP."""
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
    from darkweb_scanner.dashboard.http_client import SafeFetchError, safe_fetch
    try:
        result = safe_fetch(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers={"User-Agent": "OSINTPH-DNSCrawler/1.0"},
            timeout=REQUEST_TIMEOUT,
        )
    except SafeFetchError:
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
            if not name.endswith(domain):
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

def fetch_hackertarget(domain: str) -> list[str]:
    """
    HackerTarget free API for subdomain enumeration.
    Returns list of subdomains (free tier: 20 results).
    """
    resp = _safe_http(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not resp or resp.status_code != 200:
        return []

    subdomains = []
    for line in resp.text.splitlines():
        parts = line.strip().split(",")
        if parts and parts[0].endswith(domain):
            subdomains.append(parts[0].strip())
    return subdomains


# ── Passive: DNS history via HackerTarget ─────────────────────────────────────

def fetch_dns_history(domain: str) -> list[dict]:
    """Fetch DNS history from HackerTarget."""
    resp = _safe_http(f"https://api.hackertarget.com/dnslookup/?q={domain}")
    if not resp or resp.status_code != 200:
        return []
    records = []
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith("error"):
            records.append({"raw": line})
    return records


# ── Passive: ASN / IP geolocation ─────────────────────────────────────────────

def geolocate_ips(ips: list[str]) -> dict[str, dict]:
    """
    Bulk geolocate IPs using ip-api.com (free, 100/min limit).
    Returns dict of ip -> geo data.
    """
    if not ips:
        return {}

    # Batch up to 100
    batch = ips[:100]
    resp = _safe_http(
        "http://ip-api.com/batch",
        method="post",
        json=[{"query": ip, "fields": "status,country,countryCode,regionName,city,org,as,isp,query"} for ip in batch],
    )
    if not resp or resp.status_code != 200:
        # Fall back to individual lookups
        results = {}
        for ip in batch[:10]:  # limit fallback
            r = _safe_http(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,org,as,isp,query")
            if r and r.status_code == 200:
                try:
                    results[ip] = r.json()
                except Exception:
                    pass
        return results

    try:
        data = resp.json()
        return {entry.get("query", ""): entry for entry in data if entry.get("status") == "success"}
    except Exception:
        return {}


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
    from darkweb_scanner.dashboard.http_client import _is_private_ip

    resolved = []

    def resolve_one(sub: str) -> Optional[dict]:
        ips = resolve_ip(sub)
        if ips:
            public_ips = [ip for ip in ips if not _is_private_ip(ip)]
            if public_ips:
                return {"subdomain": sub, "ips": public_ips}
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(resolve_one, s): s for s in subdomains[:300]}
        for future in as_completed(futures):
            result = future.result()
            if result:
                resolved.append(result)

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
    domain = _clean_domain(domain)
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
    with ThreadPoolExecutor(max_workers=6) as ex:
        f_dns = ex.submit(query_dns_records, domain)
        f_crtsh = ex.submit(fetch_crtsh, domain)
        f_ht = ex.submit(fetch_hackertarget, domain)
        f_axfr = ex.submit(attempt_zone_transfer, domain)

        try:
            result["dns_records"] = f_dns.result(timeout=15)
        except Exception as e:
            result["errors"].append(f"DNS records: {e}")

        try:
            crt_entries = f_crtsh.result(timeout=20)
            result["subdomains_passive"] = crt_entries
        except Exception as e:
            result["errors"].append(f"crt.sh: {e}")

        try:
            ht_subs = f_ht.result(timeout=15)
        except Exception as e:
            ht_subs = []
            result["errors"].append(f"HackerTarget: {e}")

        try:
            result["zone_transfer"] = f_axfr.result(timeout=20)
        except Exception as e:
            result["errors"].append(f"Zone transfer: {e}")

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
    except Exception as e:
        result["errors"].append(f"Brute-force: {e}")
        result["subdomains_bruteforce"] = []

    # ── Phase 3: resolve all subdomains ──
    result["subdomains_resolved"] = resolve_subdomains(list(all_subs))

    # ── Phase 4: email security analysis ──
    result["email_security"] = analyze_email_security(domain, result["dns_records"])

    # ── Phase 5: reverse DNS on main A records ──
    main_ips = result["dns_records"].get("A", [])
    ptr_records = {}
    for ip in main_ips[:10]:
        ptr = reverse_dns(ip)
        if ptr:
            ptr_records[ip] = ptr
    result["ptr_records"] = ptr_records

    # ── Phase 6: geolocate main IPs ──
    result["ip_geo"] = geolocate_ips(main_ips[:20])

    # ── Phase 7: HTTP banner / service probe ──
    try:
        result["services"] = probe_services(list(all_subs)[:40])
    except Exception as e:
        result["services"] = {}
        result["errors"].append(f"Service probe: {e}")

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

    results = []

    def check(port_svc):
        port, svc = port_svc
        status = scan_port(host, port)
        return {"port": port, "service": svc, "status": status}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check, ps): ps for ps in ports}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                logger.debug(f"Port scan error: {e}")

    results.sort(key=lambda x: x["port"])
    return results


def scan_ports_multi(hosts: list[str], max_workers: int = 30) -> dict[str, list[dict]]:
    """
    Scan all COMMON_PORTS against multiple hosts in parallel.
    Returns dict of host -> list of port results.
    Private/reserved IPs are skipped and logged.
    """
    from darkweb_scanner.dashboard.http_client import _is_private_ip

    results = {}

    safe_hosts = []
    for h in hosts[:10]:  # cap at 10 hosts
        if _is_private_ip(h):
            logger.warning("scan_ports_multi: skipping private/reserved IP %r", h)
        else:
            safe_hosts.append(h)

    def scan_host(host):
        return host, scan_ports(host, COMMON_PORTS, max_workers=50)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_host, h): h for h in safe_hosts}
        for future in as_completed(futures):
            try:
                host, port_results = future.result()
                results[host] = port_results
            except Exception as e:
                logger.debug(f"Host scan error: {e}")

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
    from darkweb_scanner.dashboard.http_client import _is_private_ip

    if wordlist is None:
        wordlist = SUBDOMAIN_WORDLIST

    candidates = [f"{word}.{domain}" for word in wordlist]
    found = []

    def try_resolve(fqdn: str) -> Optional[dict]:
        ips = resolve_ip(fqdn)
        if ips:
            public_ips = [ip for ip in ips if not _is_private_ip(ip)]
            if public_ips:
                return {"subdomain": fqdn, "ips": public_ips, "source": "bruteforce"}
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(try_resolve, c): c for c in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

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
    from darkweb_scanner.dashboard.http_client import (
        SafeFetchError,
        fetch_public,
        resolve_and_check_target,
    )

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

    results = []
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

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, p): p for p in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

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
        except Exception as e:
            result["errors"].append(f"Dir enum {target}: {e}")

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
    from darkweb_scanner.dashboard.http_client import (
        SafeFetchError,
        fetch_public,
        resolve_and_check_target,
    )

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
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_service, h): h for h in hosts}
        for future in as_completed(futures):
            try:
                r = future.result()
                if r:
                    results[r["host"]] = r
            except Exception as e:
                logger.debug(f"Service probe error: {e}")
    logger.info(f"Service probe complete: {len(results)}/{len(hosts)} hosts responded")
    return results
