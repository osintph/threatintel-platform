# threatintel-platform

A self-hosted, open-source threat intelligence platform built for the Philippine and Southeast Asian security landscape. Crawls .onion networks, monitors Telegram channels, tracks ransomware groups, profiles threat actors, and delivers a daily intelligence digest — all from a single Docker Compose deployment.

**Version: 1.1.0 · License: AGPL-3.0**

---

## Features

- **Dark Web Crawler** — async Tor-based crawler for .onion sites, configurable keyword monitoring, real-time webhook and email alerts
- **Quick Scan** — on-demand OSINT sweep of any domain, IP, URL, or company name across configured sources, with live progress and cancellation
- **Intelligence Dashboard** — start page with live threat level, ransomware victim feed, group rankings, SEA country breakdown, ThreatFox IOC mini-feed, and press headlines
- **ransomware.live PRO Integration** — 324+ tracked groups, 26 000+ victims, IOCs, negotiation chats, ransom notes, YARA rules, SEC 8-K filings, CSIRT directory
- **IOC Feed** — live indicators of compromise from ThreatFox, URLhaus, and Feodo Tracker with search, type filtering, and confidence scoring
- **Ransomware Tracker** — live tracking with SEA/PH regional focus, victim counts, and SEA-targeting flags
- **Threat Actor Profiles** — structured APT and cybercriminal profiles relevant to Southeast Asia
- **DNS Investigations** — passive + active DNS recon, subdomain brute-force (50 workers), TCP port scan (30 ports), HTTP directory enumeration, crt.sh certificate transparency, zone transfer attempts, SPF/DMARC/DKIM scoring, interactive subdomain graph, PDF export with world map
- **IP Investigation** — parallel AbuseIPDB + VirusTotal lookups with geolocation, ASN, and history
- **WhatsMyName Username Check** — checks a username across 200+ sites concurrently
- **OSINT Domain Intel** — proxied access to Shodan, Censys, GreyNoise, URLScan, MXToolbox, SecurityTrails, VirusTotal, RDAP/WHOIS, and GitHub/Reddit/Discord/TikTok OSINT profiles
- **ThreatFox / URLhaus / AbuseIPDB proxies** — backend-proxied API calls to avoid CORS and keep keys server-side
- **Channel Monitor** — on-demand Telegram channel scraping from the dashboard, auto-translated to English, with media download and ZIP export
- **Telegram Scraper** — background monitoring of configured public channels for keyword hits
- **Projects** — scoped monitoring engagements with per-project keywords, target domains, entities, and hit tracking
- **PDF Report Generation** — ReportLab + Playwright-rendered world map for DNS investigations; digest PDF via Mailgun
- **Daily Digest** — morning email with CISA KEV, OTX pulses, abuse.ch feeds, and curated RSS
- **Authentication** — bcrypt passwords, TOTP 2FA, optional Google/GitHub/Microsoft/Apple OAuth, role-based access control (admin / analyst)

---

## Security Posture

- **safe\_fetch with host allowlist and IP blocklist** — all outbound proxy calls go through a hardened HTTP client that enforces HTTPS, TLS verification, a per-host allowlist, and an IP blocklist covering loopback, RFC 1918, link-local, and IPv4-mapped IPv6 ranges; redirects are re-validated per hop
- **DNS rebinding note** — safe\_fetch performs a pre-flight IP check followed by a standard requests connect; a low-TTL rebind between the two resolutions can still reach private IPs on the dns\_crawler recon path (see SECURITY\_REVIEW\_FABLE.md finding 2/3 for details and planned remediation)
- **Non-root containers** — the app container runs as uid 1000 (appuser); the Tor sidecar runs as debian-tor
- **TLS verification** — `verify=True` enforced on all safe\_fetch calls; legacy `ssl.CERT_NONE` paths in dns\_crawler are documented as lower-trust
- **Healthcheck** — dashboard container exposes a Docker healthcheck at `GET /`; nginx depends on it
- **Secret key enforcement** — Flask refuses to start if `DASHBOARD_SECRET_KEY` is absent or set to the placeholder value
- **HTML escaping** — all keyword hit context is escaped before inclusion in alert emails

---

## Architecture

```
docker-compose
  postgres:16-alpine       ← persistent storage (named volume)
  tor                      ← SOCKS5 proxy + control port; runs as debian-tor
  dashboard                ← Flask app; runs as appuser (uid 1000)
  nginx                    ← SSL reverse proxy; Let's Encrypt or self-signed
  webcheck                 ← lissy93/web-check (optional OSINT service)
```

All external API calls (ransomware.live, ThreatFox, AbuseIPDB, VirusTotal, etc.) go over the clearnet. Only `.onion` crawling is Tor-routed.

SQLAlchemy sessions are request-scoped via Flask `g` and torn down at request end, reducing connection pool pressure.

N+1 queries on the ransomware groups and threat actors endpoints have been collapsed: all keyword hit counts are fetched in a single query and merged in Python.

---

## Deployment

### Requirements

- Fresh Linux server (Ubuntu 22.04/24.04 recommended)
- 2 GB RAM minimum (Playwright/Chromium for PDF map rendering requires headroom)
- Ports 80 and 443 open
- A domain name (optional — self-signed SSL works for LAN/VPS access)

### Quick deploy

```bash
curl -fsSL https://raw.githubusercontent.com/osintph/threatintel-platform/main/deploy.sh \
  -o /tmp/deploy.sh && sudo bash /tmp/deploy.sh
```

With a domain and Let's Encrypt SSL:

```bash
DOMAIN=intel.yourdomain.com SSL_EMAIL=you@example.com \
  sudo bash /tmp/deploy.sh
```

The script installs Docker, clones the repo, generates secrets, configures Tor, and starts all services.

### First-time setup after deploy

1. Visit `https://YOUR_SERVER_IP/register` to create your admin account. Registration closes automatically after the first account is created.
2. Edit your configuration:
   ```bash
   nano ~/threatintel-platform/.env
   nano ~/threatintel-platform/config/keywords.yaml
   nano ~/threatintel-platform/config/seeds.txt
   ```
3. Restart to apply changes:
   ```bash
   cd ~/threatintel-platform && docker compose restart dashboard
   ```

### Updating

```bash
cd ~/threatintel-platform
git pull
docker compose build --no-cache
docker compose up -d
```

### Web Check (manual step)

Web Check runs as a separate service and is not started by default. See [docs/deployment.md](docs/deployment.md#web-check-integration) for setup steps.

---

## Configuration

All configuration lives in `.env`. **Never commit this file.**

### Minimum required variables

| Variable | Description |
|----------|-------------|
| `DASHBOARD_SECRET_KEY` | Flask session secret — must be a long random string; the app refuses to start without it |
| `POSTGRES_PASSWORD` | PostgreSQL password — auto-generated by deploy.sh |
| `DATABASE_URL` | PostgreSQL connection string — auto-set by deploy.sh |
| `TOR_CONTROL_PASSWORD` | Tor control port password — auto-generated by deploy.sh |

### Threat intelligence feeds

| Variable | Description |
|----------|-------------|
| `RANSOMWARE_LIVE_API_KEY` | ransomware.live PRO — free at my.ransomware.live; unlocks IOCs, negotiations, YARA rules, 3 000 calls/day |
| `THREATFOX_API_KEY` | ThreatFox (abuse.ch) — free at threatfox.abuse.ch |
| `WHITEINTEL_API_KEY` | WhiteIntel — free tier at whiteintel.io — credential exposure monitoring |
| `OTX_API_KEY` | AlienVault OTX — free at otx.alienvault.com |
| `ABUSEIPDB_API_KEY` | AbuseIPDB — free tier: 1 000 checks/day |
| `VIRUSTOTAL_API_KEY` | VirusTotal — free tier: 4 req/min |
| `DNSDUMPSTER_API_KEY` | DNSDumpster — for DNS investigation enrichment |

### Daily digest (Mailgun)

| Variable | Description |
|----------|-------------|
| `MAILGUN_API_KEY` | Mailgun API key |
| `MAILGUN_DOMAIN` | Your Mailgun sending domain |
| `MAILGUN_FROM` | Sender address (default: `OSINT PH Threat Intel <digest@intel.osintph.info>`) |

### Telegram

| Variable | Description |
|----------|-------------|
| `TELEGRAM_API_ID` | From my.telegram.org/apps |
| `TELEGRAM_API_HASH` | From my.telegram.org/apps |
| `TELEGRAM_PHONE` | Your phone number with country code — required for Channel Monitor |
| `TELEGRAM_CHANNELS` | Comma-separated channel usernames (no @) — used by background scraper |

### Quick Scan

| Variable | Default | Description |
|----------|---------|-------------|
| `QUICK_SCAN_MAX_CONCURRENT` | `4` | Max concurrent source checks per scan session |
| `QUICK_SCAN_DELAY_MIN` | falls back to `CRAWL_DELAY_MIN` (2s) | Min delay between source requests |
| `QUICK_SCAN_DELAY_MAX` | falls back to `CRAWL_DELAY_MAX` (8s) | Max delay between source requests |

### OAuth (optional)

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth — callback: `/oauth/google/callback` |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth — callback: `/oauth/github/callback` |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` / `MICROSOFT_TENANT_ID` | Microsoft OAuth |
| `APPLE_CLIENT_ID` / `APPLE_CLIENT_SECRET` | Apple Sign In |

See `.env.example` for all variables with descriptions and safe placeholder values.

---

## Test Suite

```bash
source .venv/bin/activate
pytest tests/ -v
```

Current count: **135 passed, 2 skipped**. Tests cover:

- Scanner keyword matching (hit detection, case insensitivity, context windows, add/remove)
- Crawler URL normalisation, domain extraction, link extraction, crawl filter logic
- HTTP client (safe\_fetch allowlist, IP blocklist, TLS enforcement, redirect re-validation, IPv4-mapped IPv6 blocking, SSRF guard)
- Storage models, session lifecycle, and Storage methods (unit + integration against SQLite)
- Quick scan target detection, variant normalisation, and deduplication
- Proxy route wiring (integration, with safe\_fetch mocked)
- Tor connectivity (skipped unless `TOR_INTEGRATION=1`)

---

## Development Setup

```bash
git clone https://github.com/osintph/threatintel-platform
cd threatintel-platform
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,all]"
make setup          # copies .env.example → .env and example configs
```

Run the dashboard locally (requires a running PostgreSQL and Tor):

```bash
python -m darkweb_scanner.dashboard.app
```

Or via Docker Compose:

```bash
docker compose up -d
```

> Note: the Dockerfile CMD starts Flask's built-in server (`python -m darkweb_scanner.dashboard.app`). Migrating to gunicorn with a proper worker count is a planned follow-up.

---

## Project Structure

```
config/
  keywords.yaml          # keyword monitoring rules
  seeds.txt              # .onion seed URLs for the crawler
docs/                    # feature documentation
src/darkweb_scanner/
  crawler.py             # async Tor crawler (BFS, SOCKS5)
  scanner.py             # keyword matching engine
  storage.py             # SQLAlchemy models and storage layer
  quick_scan.py          # Quick Scan orchestrator
  quick_scan_sources.py  # source config and normalisation
  feeds.py               # OTX, CISA, abuse.ch, RSS feeds
  digest.py              # daily email digest + PDF
  dns_crawler.py         # DNS recon, brute-force, port scan, dir enum
  ip_lookup.py           # IP investigation (AbuseIPDB + VirusTotal)
  ransomware_live.py     # ransomware.live PRO API client
  ransomware_data.py     # local ransomware group data (merged with live API)
  threat_actors.py       # threat actor profile data
  telegram_scraper.py    # background Telegram channel scraper
  channel_monitor.py     # on-demand Telegram channel monitor
  paste_monitor.py       # rentry.co paste polling
  auth.py                # bcrypt, TOTP, OAuth helpers
  dashboard/
    app.py               # Flask application factory
    http_client.py       # safe_fetch — hardened outbound HTTP client
    auth_routes.py       # /login, /register, /totp/*, /oauth/*
    dashboard_routes.py  # all API and dashboard routes
    ransomware_live_routes.py  # /api/rwlive/* blueprint
    channel_monitor_routes.py  # Channel Monitor API + job runner
    quick_scan_routes.py       # /api/quick-scan/* blueprint
    storage_helper.py    # request-scoped Storage singleton
    templates/
      index.html         # single-page dashboard UI
docker/
  app/Dockerfile         # app image; non-root (appuser uid 1000)
  tor/Dockerfile         # Tor sidecar; non-root (debian-tor)
  nginx/                 # nginx with auto SSL entrypoint
deploy.sh                # zero-prerequisite deployment script
```

---

## Useful Commands

```bash
# Run from the install directory

make scan          # run a crawl (foreground)
make check-tor     # verify Tor connectivity
make stats         # show scan statistics
make hits          # show recent keyword hits
make logs          # tail all container logs
make stop          # stop all containers
```

---

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).

You may use, modify, and distribute this software. If you run a modified version as a network service, you must make the source code available to users of that service.

See the [LICENSE](LICENSE) file for the full text.

---

## Contributing

Pull requests are welcome. If you're a Philippine or Southeast Asian security researcher and want to collaborate on keyword lists, threat actor data, or regional intelligence coverage — please reach out.

Issues and feature requests: https://github.com/osintph/threatintel-platform/issues

OSINT PH: https://www.osintph.info
