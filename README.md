# threatintel-platform

A self-hosted, open-source threat intelligence platform built for the Philippine and Southeast Asian security landscape. Crawls .onion networks, monitors Telegram channels, tracks ransomware groups, profiles threat actors, and delivers a daily intelligence digest — all from a single Docker Compose deployment.

**Version: 1.3.0 · License: AGPL-3.0**

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
- **Channel Monitor** — on-demand scraping of public Telegram channels from the dashboard (administrators only), translated to English with Google Translate, with media download and ZIP export; archives are deleted after 90 days
- **Telegram Scraper** — background monitoring of configured public channels for keyword hits
- **Projects** — scoped monitoring engagements with per-project keywords, target domains, entities, and hit tracking
- **PDF Report Generation** — ReportLab + Playwright-rendered world map for DNS investigations; digest PDF via Mailgun
- **Daily Digest** — morning email with CISA KEV, OTX pulses, abuse.ch feeds, and curated RSS
- **Authentication** — local accounts with bcrypt passwords and mandatory TOTP two-factor sign-in, lockouts, a sign-in log, and two roles (administrator / user). In-app **Help & privacy** page lists who can do what and which data leaves the server

---

## Security Posture

- **safe\_fetch with host allowlist and IP blocklist** — all outbound proxy calls go through a hardened HTTP client that enforces HTTPS, TLS verification, a per-host allowlist, and an IP blocklist covering loopback, RFC 1918, link-local, and IPv4-mapped IPv6 ranges; redirects are re-validated per hop
- **Pinned outbound connections** — a host name is resolved once and the connection goes to an address that passed the check, so a second DNS answer (DNS rebinding) cannot move a request to an internal address. This covers the proxy routes, the DNS recon probes and the user-name check; recon probes never follow redirects
- **Sessions checked on the server** — the cookie carries a user id and a session version; the user, the role and the second factor are read from the database on every request. Sessions end after 12 hours, and at sign-out, password change, second-factor change or user deletion
- **CSRF protection** — every request that changes something needs the session's token and, when the browser sends one, a matching `Origin`
- **Sign-in throttling** — 10 wrong passwords per user name or 20 failures per address in 15 minutes lock sign-in for 15 minutes; 5 wrong codes lock the second step; a code works once
- **Admin-only changes** — global settings, crawl control, deletes, user administration and Channel Monitor require the administrator role, checked on the server
- **Content security policy** — dashboard pages run scripts from the application's own `/static/` only: no inline script, no inline event handlers, no third-party script hosts (the map library is served by the application)
- **Bounded work** — heavy lookups run as background jobs with limits per user and in total (429 when full), keyword patterns are checked for catastrophic backtracking before they are saved, and page bodies are read up to a byte cap
- **Escaped output** — the dashboard renders API data as text (no data in event handlers, URL schemes checked); PDF exports and the Channel Monitor report escape everything they did not write themselves
- **No Tor control port** — the Tor container is a SOCKS client only and its configuration is rendered when it starts
- **Non-root containers** — the app container runs as uid 1000 (appuser); the Tor sidecar runs as debian-tor
- **TLS verification** — `verify=True` enforced on all safe\_fetch calls; legacy `ssl.CERT_NONE` paths in dns\_crawler are documented as lower-trust
- **Healthcheck** — the dashboard container's healthcheck calls `GET /healthz`, which runs a query against the database, so "healthy" means the app can reach PostgreSQL
- **Pinned supply chain** — Python dependencies are installed only from `requirements.lock` with hash checking; base images are pinned by digest
- **Start-up checks** — the dashboard refuses to start if `DASHBOARD_SECRET_KEY` is absent, a placeholder or shorter than 32 characters, or if `DATABASE_URL` is not set
- **HTML escaping** — all keyword hit context is escaped before inclusion in alert emails

---

## Architecture

```
docker-compose
  postgres:16-alpine       ← persistent storage (named volume)
  tor                      ← SOCKS5 proxy only (no control port); runs as debian-tor
  dashboard                ← Flask app under gunicorn (1 worker, 8 threads); runs as appuser (uid 1000)
  nginx                    ← SSL reverse proxy; Let's Encrypt or self-signed
```

nginx answers only for the names it is configured with: a request for any other host name is closed without a response. It takes the visitor's address from `CF-Connecting-IP` when the connection comes from Cloudflare, limits sign-in requests to 10 a minute per visitor, and looks the dashboard up at request time, so the dashboard can be rebuilt without touching nginx. Certificates and keys in the `letsencrypt` volume are never rewritten by a container start.

The nginx entrypoint also generates the static website vhost when `WWW_DOMAIN` is set. That vhost serves the site's own `404.html` with status 404 for missing paths (no fallback to the home page) and permanently redirects the withdrawn Thai and German page URLs to their English pages. The config is generated when the container starts, so a change to `docker/nginx/entrypoint.sh` takes effect only after the nginx image is rebuilt.

API calls to third-party services (ransomware.live, ThreatFox, AbuseIPDB, VirusTotal, etc.) go over the clearnet from the server's address. The crawler fetches `.onion` addresses only, and Quick Scan sends everything through Tor, including its clearnet sources (HTTPS, allowlisted hosts, no redirects).

The database schema is versioned with Alembic; the dashboard brings it up to date when it starts (see [docs/runbook.md](docs/runbook.md#database-schema)).

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

The script installs Docker, clones the repo, generates secrets (including the one-time setup token), and starts all services.

### First-time setup after deploy

1. Visit `https://YOUR_SERVER_IP/register` and create the administrator account. The page asks for the setup token that `deploy.sh` wrote to `.env` (`grep '^SETUP_TOKEN=' ~/threatintel-platform/.env`), then for a user name and password, and then makes you enrol an authenticator app. It works only while no users exist.
2. Edit your configuration:
   ```bash
   vi ~/threatintel-platform/.env
   vi ~/threatintel-platform/config/keywords.yaml
   vi ~/threatintel-platform/config/seeds.txt
   ```
3. Restart to apply changes:
   ```bash
   cd ~/threatintel-platform && docker compose up -d dashboard
   ```

### Updating

```bash
cd ~/threatintel-platform
sudo ./upgrade.sh            # tip of main
sudo ./upgrade.sh v1.3.0     # or a release tag
```

`upgrade.sh` dumps the database first, checks out the release, fixes known `.env` issues (and removes settings that are no longer used, after keeping a copy), rebuilds the images from the lock file, recreates the containers one by one and ends by checking that nginx answers 200 for each site. Details and rollback: [docs/runbook.md](docs/runbook.md#upgrading).

**Upgrading to 1.3.0:** the database schema is upgraded at the first start (the paste monitor tables and the OAuth columns are dropped; `upgrade.sh` dumps the database first); the paste monitor and the public `/api/digest/subscribe` and `/api/send-brief` endpoints are gone; Channel Monitor runs one job at a time and never asks Telegram for a login code; if its session is not signed in, a job ends with an error that names `make channel-monitor-auth`. See the upgrade notes in [CHANGELOG.md](CHANGELOG.md).

**Upgrading to 1.2.0:** everyone signs in again; every account needs a second factor; Channel Monitor archives older than 90 days are deleted at the first start. See the upgrade notes in [CHANGELOG.md](CHANGELOG.md).

---

## Configuration

All configuration lives in `.env`. **Never commit this file.**

### Minimum required variables

| Variable | Description |
|----------|-------------|
| `DASHBOARD_SECRET_KEY` | Session secret — at least 32 random characters; the app refuses to start without it. Changing it signs everyone out |
| `SETUP_TOKEN` | Needed once, to create the first administrator at `/register` (at least 24 characters) — auto-generated by deploy.sh |
| `POSTGRES_PASSWORD` | PostgreSQL password — auto-generated by deploy.sh |
| `DATABASE_URL` | PostgreSQL connection string, `postgresql+psycopg2://…` — auto-set by deploy.sh; required |

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
| `TELEGRAM_PHONE` | Your phone number with country code — used by the one-time Channel Monitor sign-in (`make channel-monitor-auth`) |
| `TELEGRAM_CHANNELS` | Comma-separated channel usernames (no @) — used by background scraper |
| `CHANNEL_MONITOR_RETENTION_DAYS` | Channel Monitor archives are deleted after this many days (default `90`) |
| `CHANNEL_MONITOR_MAX_*`, `CHANNEL_MONITOR_MIN_FREE_GB` | Limits of a Channel Monitor job: messages, file, video and job size, free disk, download size. See [TELEGRAM.md](TELEGRAM.md) |

### Quick Scan

| Variable | Default | Description |
|----------|---------|-------------|
| `QUICK_SCAN_MAX_CONCURRENT` | `4` | Max concurrent source checks per scan session |
| `QUICK_SCAN_DELAY_MIN` | falls back to `CRAWL_DELAY_MIN` (2s) | Min delay between source requests |
| `QUICK_SCAN_DELAY_MAX` | falls back to `CRAWL_DELAY_MAX` (8s) | Max delay between source requests |

### Limits and timeouts

Optional; the defaults suit one server. `MAX_PAGE_BYTES` (page body cap), `TOR_CHECK_TIMEOUT`, `CRAWL_HEARTBEAT_SECONDS` and `CRAWL_STALE_SECONDS`, `HEAVY_JOBS_MAX` and `HEAVY_JOBS_PER_USER`, `FANOUT_WORKERS`, `UPSTREAM_CACHE_SECONDS`, `VIRUSTOTAL_PER_MINUTE`, `SMTP_TIMEOUT`, `ALERT_QUEUE_SIZE`, `ALERT_FLUSH_SECONDS`. Each is described in `.env.example`.

See `.env.example` for all variables with descriptions and safe placeholder values.

---

## Test Suite

```bash
source .venv/bin/activate
pytest tests/ -v
```

Current count: **801 passed, 2 skipped**. Tests cover:

- Sign-in, sessions, CSRF, lockouts, the second factor and the setup token, against the real application
- Authorization: every admin-only route as a non-admin, and deletes scoped to their project
- Input validation for every route that takes user input
- Dashboard templates (static rules: no data in event handlers, URLs and colours checked, CSRF token on writes)
- Channel Monitor report and routes (escaping, public-channel check, ownership, retention)
- Outbound requests (allowlist, IP blocklist, pinned address, redirects, PDF text escaping)
- Scanner, crawler, storage, Quick Scan, proxy routes, Tor client
- Background job limits, the upstream cache, keyword pattern checks, crawl heartbeat and ownership, alert queue
- Channel Monitor job states, limits and sign-in; the content security policy
- Schema migrations (the revisions alone produce the models' schema, on SQLite and PostgreSQL)
- Tor connectivity (skipped unless `TOR_INTEGRATION=1`)

Set `TEST_DATABASE_URL` to run the integration tests on PostgreSQL instead of in-memory SQLite (the database is emptied before each test). CI does this, and also runs:

```bash
tests/deploy/test_env_secrets.sh             # deploy.sh keeps secrets on a second run
tests/upgrade/test_upgrade_steps.sh          # paste cron removal, schema step-back before a rollback
tests/scripts/test_restore_test.sh           # restore test accepts a good dump, rejects a damaged one
python tests/browser/xss_check.py            # dashboard pages in headless Chromium, hostile data in every API answer
tests/nginx/test_entrypoint.sh <nginx image> # certificates survive restarts, unknown hosts refused
tests/tor/test_entrypoint.sh <tor image>     # rendered torrc, no control port
```

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

The Docker image and CI install the exact versions in `requirements.lock`. After changing a dependency in `pyproject.toml`, regenerate it with `make lock` (needs [uv](https://docs.astral.sh/uv/)).

Run the dashboard locally (requires `DATABASE_URL`, a `DASHBOARD_SECRET_KEY` of 32+ characters, and Tor for crawling). `DASHBOARD_ALLOW_HTTP=1` lets the session cookie travel over plain HTTP; use it on your own machine only:

```bash
DASHBOARD_ALLOW_HTTP=1 gunicorn --bind 127.0.0.1:8080 --workers 1 --threads 8 'darkweb_scanner.dashboard.app:create_app()'
```

Or via Docker Compose:

```bash
docker compose up -d
```

> The dashboard runs under gunicorn with one worker process (see `docker-compose.yml`). Keep it at one: job limits, the upstream cache, Quick Scan and Channel Monitor jobs live in that process. The crawl session's owner and heartbeat are in the database.

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
  regex_safety.py        # checks keyword patterns before they are used
  migrations/            # Alembic revisions of the database schema
  auth.py                # sessions, CSRF, lockouts, bcrypt, TOTP
  pdf_text.py            # escaping for text placed in PDF exports
  templates/             # Channel Monitor report template
  dashboard/
    app.py               # Flask application factory
    http_client.py       # safe_fetch — hardened outbound HTTP client
    auth_routes.py       # /login, /register, /totp/*, /logout
    validation.py        # input validation for the API routes
    dashboard_routes.py  # all API and dashboard routes
    ransomware_live_routes.py  # /api/rwlive/* blueprint
    channel_monitor_routes.py  # Channel Monitor API + job runner
    quick_scan_routes.py       # /api/quick-scan/* blueprint
    storage_helper.py    # request-scoped Storage singleton
    jobs.py              # background jobs, limits, shared fan-out pool
    upstream_cache.py    # cache for third-party answers
    file_store.py        # locked updates of the keyword and seed files
    errors.py            # error answers with an error id
    security_headers.py  # content security policy, static file caching
    static/              # dashboard scripts and the vendored map library
    templates/
      index.html         # single-page dashboard UI
      help.html          # Help & privacy page
docker/
  app/Dockerfile         # app image; non-root (appuser uid 1000)
  tor/                   # Tor sidecar; non-root (debian-tor); torrc rendered at start
  nginx/                 # nginx with auto SSL entrypoint
ops/cf-origin-lock/      # optional: limit ports 80/443 to Cloudflare (systemd unit + timer)
requirements.lock        # exact dependency versions with hashes (make lock)
deploy.sh                # zero-prerequisite deployment script
upgrade.sh               # upgrade an existing install to a release
```

---

## Useful Commands

```bash
# Run from the install directory

make scan          # run a crawl (foreground)
make check-tor     # verify Tor connectivity
make stats         # show scan statistics
make hits          # show recent keyword hits
make users         # list accounts and sign-in locks
make db-status     # database schema revision
make channel-monitor-auth  # sign the Channel Monitor session in (once)
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
