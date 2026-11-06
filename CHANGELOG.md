# Changelog

All notable changes to this project will be documented in this file.
The format follows **Keep a Changelog**. This project adheres to **Semantic Versioning**.

## [Unreleased]

## [1.2.0] - 2026-11-06

Security release for the application, from the November 2026 audit: sign-in and sessions are checked on the server, every change needs a CSRF token and the right role, the dashboard and its exports show data as text, outbound requests cannot be redirected to internal addresses, and Channel Monitor is limited to administrators and public channels.

### Upgrade notes

- Upgrade with `sudo ./upgrade.sh v1.2.0`.
- **Everyone signs in again.** All sessions end at the upgrade. Passwords and authenticators are unchanged. An account without a second factor is taken to enrolment right after it signs in; there is no way to skip it.
- **Channel Monitor archives older than 90 days are deleted when the dashboard first starts.** Download what you want to keep before upgrading, or set `CHANNEL_MONITOR_RETENTION_DAYS` in `.env` first.
- **`.env`:** `upgrade.sh` removes the settings nothing reads any more (`TOR_CONTROL_PORT`, `TOR_CONTROL_PASSWORD`, `FLASK_DEBUG`, `DASHBOARD_PORT`, the OAuth client ids and secrets) after copying the old file to `backups/env-before-<time>`. It stops before rebuilding anything if `DASHBOARD_SECRET_KEY` is shorter than 32 characters. `SETUP_TOKEN` is needed for new installs only.
- **OAuth sign-in is gone.** An account that only ever signed in through Google, GitHub, Microsoft or Apple has no password: an administrator deletes it and creates it again.
- **Non-administrators lose the controls listed under "Changed".** Give the admin role to the people who need them.
- **Scripts that call the API** with a session cookie must send the `X-CSRF-Token` header on every request that is not a GET, and now get `401` with a JSON body, not a redirect, when the session has ended.
- **Locked out or lost authenticator:** `docker compose exec dashboard python -m darkweb_scanner.main user-unlock NAME` and `... user-reset-mfa NAME`; see `docs/runbook.md`.

### Security

**Sign-in and sessions**

- **A session is checked against the database on every request.** The cookie used to be trusted as it was: a deleted user kept working for as long as the cookie stayed valid (12 hours, renewed by every request), and the admin flag and the "second factor done" flag were read from the cookie. The cookie now carries a user id and a session version; the user, the role and the second factor come from the database each time. Sessions end 12 hours after sign-in however active they are, and at sign-out, a password change, a second-factor change, an administrator's reset, or when the user is deleted.
- **Two-factor sign-in is mandatory and enforced on the server.** The enrolment page had a "skip" link and the API did not check enrolment at all. An account without a second factor can now reach only the enrolment page.
- **A code works once.** A six-digit code that was accepted is refused when it is sent again.
- **Replacing or removing a second factor needs proof.** Replacing needs a code from the current authenticator; removing needs the password and a current code. The secret being enrolled is kept on the server, not in the cookie.
- **Changing a password needs the current password**, and ends the user's other sessions.
- **Sign-in is throttled in the application**, not only by nginx: 10 wrong passwords for one user name, or 20 failures from one address, within 15 minutes lock sign-in for 15 minutes; 5 wrong codes lock the second step and the password has to be entered again. The answer is the same whether or not the user name exists, and takes the same time.
- **CSRF protection.** Every request that is not a GET, HEAD or OPTIONS must carry the session's token (`X-CSRF-Token` header or `csrf_token` form field), and an `Origin` header must name this host. Sign-out is a POST. The cookie is `__Host-session`: Secure, HttpOnly, SameSite=Lax.
- **The first administrator needs a setup token.** `/register` was open to whoever reached a fresh install first. It now needs `SETUP_TOKEN` from the server's `.env`, and is closed when no token is set.
- **Sign-in log.** Sign-ins, failures, lockouts, sign-outs, password and second-factor changes and user administration are written to the new `auth_events` table and to the container log, with time, user name and address, and kept for 365 days. Administrators read it under Users.
- **The visitor's address is taken from nginx** (`ProxyFix`, one hop), so the log and the per-address limit see the real client.
- **Start-up checks:** the dashboard does not start with a `DASHBOARD_SECRET_KEY` shorter than 32 characters, or without `DATABASE_URL`. The silent fallback to an empty SQLite file, which reopened first-admin registration, is gone.
- **Password rule:** at least 12 characters with an uppercase letter, a lowercase letter, a number and a symbol, for passwords set from now on.
- **Sign-in redirect:** the `next` target must be a path on this site; backslashes and control characters are refused.

**Authorization**

- **Administrator role required**, checked on the server, for: adding, importing and removing keywords, seeds, clearnet seeds, paste sources, Telegram channels and custom ransomware-group and threat-actor entries; starting and stopping a crawl and a paste scan; deleting breach, IP and DNS investigations; digest subscribers and sending the digest; user administration; everything in Channel Monitor. The data stays a workspace shared by all signed-in users.
- **Project rows can only be removed through their own project.** Deleting a keyword, domain or entity took the row id alone, so a member of one project could delete another project's rows.
- **The role of a new user is explicit:** `is_admin` must be a JSON boolean. An administrator cannot delete their own account.

**Dashboard pages (cross-site scripting)**

- **API data is shown as text.** Values from feeds, crawl results, investigations, subscribers and HTTP headers were placed into markup, event handlers and attributes with an escaper that skipped quotes. The escaper now covers all five characters, no data is written into an event handler (buttons carry `data-` attributes and one listener dispatches to a fixed list of functions), links accept `http` and `https` only, colours must be hex colours, and path segments are URL-encoded. External links open with `rel="noopener noreferrer"`.
- **Controls a user may not use are hidden**, by a class set on the server.

**Channel Monitor**

- **The report can no longer run script.** `messages.html` was assembled from message text, entity data and file names as HTML. It is now rendered from a template with auto-escaping, from the raw text and entity offsets; links are `http`, `https` or `tg` only; media files are named `<message id>.<ext>` from a fixed list of types, anything else is saved as `.bin` and linked, not displayed; the page carries a content security policy that blocks scripts and remote content.
- **Public channels only.** `me`, phone numbers, numeric ids, invite links and titles are refused before Telegram is contacted, and the resolved chat must be a public channel. Previously the tab could read the saved messages and private chats of the Telegram account configured on the server.
- **Administrators only, with job ownership.** Jobs record who started them; a malformed, unknown or foreign job id answers 404; a running job cannot be deleted (409).
- **Retention:** archives and job folders are deleted 90 days after their last change (`CHANNEL_MONITOR_RETENTION_DAYS`).
- **Input is validated:** wrong types are refused, numbers are kept within limits.

**Outbound requests**

- **Connections go to the address that was checked.** A host name is resolved once and the request is sent to an address that passed the internal-address check, with the name still used for TLS. A second DNS answer can no longer move the request to an internal address. This applies to the proxy routes, the DNS recon probes and the user-name check.
- **Recon probes do not follow redirects.** A host that answers with a redirect is reported as "redirects to …"; the target is not fetched. Names that resolve to any internal address are skipped. Proxy settings and `.netrc` are ignored. Request headers are not carried to another host on a redirect.
- **PDF exports escape their text.** A `<` or `&` in a hit, a DNS record or a feed title was parsed as ReportLab markup, which could break the export or pull in a remote image. Every value is now escaped, and only `http`/`https` URLs become links.
- **The ThreatFox relay builds its own request**; it no longer forwards the caller's body.
- **Input validation** on every route that takes user input: e-mail addresses, domains, IP addresses, URLs, user names, channel names, keywords, limits.

**Tor**

- **No control port.** The control port was open to every container on the stack's network, protected by a password whose hash was committed. Tor now runs as a SOCKS client only. The crawler gets a new circuit by using new SOCKS credentials, so nothing needs the port, and the `stem` dependency is gone.
- **`torrc` is rendered when the container starts** (`docker/tor/entrypoint.sh`); the repository and the image hold no `torrc` and no hash.

### Changed

- **The dashboard runs under gunicorn** (one worker, eight threads) in place of Flask's development server. There is no debug switch. `python -m darkweb_scanner.dashboard.app` no longer starts a server.
- **API answers for a signed-out or not-yet-enrolled user** are JSON with status 401 or 403; pages still redirect to sign-in.
- **`deploy.sh`** generates `SETUP_TOKEN` once and tells you where to find it, checks the length of `DASHBOARD_SECRET_KEY`, and no longer generates a Tor password or edits `torrc`.
- **`upgrade.sh`** removes obsolete settings from `.env` (with a copy kept) and checks `DASHBOARD_SECRET_KEY` before rebuilding.
- **`.env.example`:** `SETUP_TOKEN` and `CHANNEL_MONITOR_RETENTION_DAYS` added; Tor control, OAuth, `FLASK_DEBUG` and `DASHBOARD_PORT` removed.
- **DNS recon results:** the HTTP table shows each probed host's own answer; 303 answers are reported.
- **Digest PDF:** text is escaped, and links that are not `http`/`https` are shown as text.
- **CI** runs the integration tests on PostgreSQL 16 as well as SQLite, loads the app with gunicorn, renders the dashboard in headless Chromium with hostile data in every API answer, tests the Tor image, and shellchecks the new scripts.

### Added

- **Help & privacy page** (`/help`, linked from the header): sign-in rules, who can do what, what Channel Monitor does with message text, which services receive which data, and what is stored and logged.
- **Account commands on the server:** `user-list`, `user-unlock`, `user-reset-mfa` (`python -m darkweb_scanner.main …`, `make users`).
- **Users panel:** "Reset 2FA" for a user who lost their authenticator, and the sign-in log.
- **Tests:** sign-in flow, authorization, input validation, the application's URL map, dashboard templates, Channel Monitor report and routes, outbound pinning, PDF exports, the Tor client and container, the account commands (595 tests, up from 135).

### Removed

- **OAuth sign-in** (Google, GitHub, Microsoft, Apple): routes, buttons, helpers and settings. The two unused columns stay in the `users` table until the next release.
- **Tor control port**, `TOR_CONTROL_PORT`, `TOR_CONTROL_PASSWORD`, the committed `torrc` files and the unused root `Dockerfile.tor`.
- **`FLASK_DEBUG`** and the development server entry point.

## [1.1.1] - 2026-11-06

Build, deployment and nginx fixes from the November 2026 audit: locked dependencies, an upgrade script, certificates that survive restarts, and a Cloudflare origin lock.

### Upgrade notes

- Upgrade with `sudo ./upgrade.sh v1.1.1` (from 1.1.0 or older: check out `main` once to get the script, see `docs/runbook.md`).
- **Certificates:** after the upgrade, look for `were overwritten` in `docker compose logs nginx`. For each name reported, run `docker compose exec nginx certbot renew --cert-name <name> --force-renewal`, then `docker compose exec nginx nginx -s reload`. Behind Cloudflare, switch the SSL mode to Full (strict) afterwards.
- **Web Check:** a full `upgrade.sh` run removes the container. Then delete its certificate (`docker compose exec nginx certbot delete --cert-name webcheck.<your domain>`), its image (`docker image rm lissy93/web-check`) and its DNS record.
- **`.env`:** `DATABASE_URL` must start with `postgresql+psycopg2://`; `upgrade.sh` changes it for you and sets the file to mode 600.

### Fixed

- **nginx replaced its Let's Encrypt chain and private key with a self-signed pair at every container start.** `/etc/nginx/certs/*.pem` are links into `/etc/letsencrypt/live/`, and the entrypoint ran `openssl req` against those names on every start, so it wrote through the links: the real private key was destroyed and the origin served a self-signed certificate while certbot still saw a valid `cert.pem`. The entrypoint (`docker/nginx/entrypoint.sh`, rewritten) now only links to existing Let's Encrypt files, generates a self-signed pair only for a name that has no certificate, and removes whatever is at the target path before writing. A lineage that was damaged this way is reported in the log at start, with the command that repairs it. **After upgrading, run the forced renewal once** (see Upgrade notes below). New regression test `tests/nginx/test_entrypoint.sh`, run in CI.
- **A rebuilt dashboard answered 502 until nginx was restarted, and nginx could not start while the dashboard was down.** nginx resolved `dashboard` once at start. It now uses Docker's DNS (`resolver 127.0.0.11 valid=10s`) with a variable in `proxy_pass`, so the name is looked up at request time. The relay upstreams on the threat-watch site are resolved the same way.
- **`scripts/configure-ssl.sh` did not apply the domain it had just written.** It ran `docker compose restart nginx`, which does not re-read `.env`; it now runs `docker compose up -d nginx`.
- **A fresh build could not reach PostgreSQL.** Nothing pinned SQLAlchemy, and from 2.1 a bare `postgresql://` URL selects the psycopg 3 driver, which the image does not ship; the first query failed with `No module named 'psycopg'` while the container still reported healthy. `.env.example` and `deploy.sh` now write `postgresql+psycopg2://`, `upgrade.sh` corrects existing `.env` files, and `Storage` normalises a bare URL itself.
- **The healthcheck could not see a broken database connection.** It requested `/`, which never touches the database. New `GET /healthz` runs `SELECT 1` and answers 200 or 503; the compose healthcheck uses it and the dashboard now waits for a healthy PostgreSQL. Healthcheck requests are kept out of the access log.
- **Chromium could not be launched by the runtime user.** Playwright's browser was installed into root's home and the app runs as `appuser`, so the world map in the DNS PDF export could not render. The browser now installs to `/opt/playwright` (`PLAYWRIGHT_BROWSERS_PATH`).
- **Channel Monitor download corruption:** `GET /api/channel-monitor/jobs/<id>/download` no longer streams the ZIP live from an in-request generator with no `Content-Length`. The old approach also ignored `Range` headers, so a resumed/reconnected download got a fresh full `200` body that clients would splice onto bytes they already had — producing archives with a valid small entry followed by orphaned tail data and no End Of Central Directory record. The ZIP is now built to a temp file server-side, verified (on-disk byte count checked against bytes written, plus an `is_zipfile` EOCD check) before anything is sent, then served via `send_file` with a real `Content-Length` and correct `Range`/206 support; the temp file is removed after the response completes. Oversized output directories (>5 GB, configurable via `CHANNEL_MONITOR_MAX_DOWNLOAD_GB`) are rejected up front with a 413 instead of being zipped.

### Changed

- **Dependencies are locked.** New `requirements.lock` (exact versions with hashes, generated by `make lock`). The app image installs only from it with `pip install --require-hashes` and runs the code from `/app/src`; CI installs the same file. This also moves the image to fixed releases of pillow, aiohttp, urllib3, certifi, dnspython, multidict, pyasn1 and werkzeug.
- **Base images are pinned by digest** (`python:3.11-slim`, `debian:bookworm-slim`, `nginx:alpine`, `postgres:16-alpine`); `.github/dependabot.yml` proposes updates monthly.
- **`docker-compose.yml`:** `name: darkweb-scanner` pins the project name, so volume names no longer depend on the install directory (and `deploy.sh` finds the `darkweb-scanner-tor` image it builds); every service rotates its log (5 × 20 MB).
- **New `.dockerignore`** keeps `.env`, the real `config/keywords.yaml` and `config/seeds.txt`, `*.bak` files, backups and the website directories out of the build context.
- **`www` submodule** now records `bba43f7`, the commit that is deployed.
- **CI** runs the integration tests as well as the unit tests, shellchecks the deploy, upgrade and ops scripts, builds all three images, and checks that the app image starts as its runtime user and can launch Chromium.
- **Website vhost returns real 404s.** In the website server block generated by `docker/nginx/entrypoint.sh`, missing paths no longer fall back to `/index.html` with status 200: `try_files` ends in `=404` and `error_page 404 /404.html` serves the site's own 404 page. The withdrawn Thai and German URLs redirect permanently: `/index-de.html` and `/index-th.html` to `/index.html`, `/contact-th.html` to `/contact.html`. The threat-watch vhost is unchanged. **Deployment state:** this is live as a hot patch of the generated nginx config (tested and reloaded, no rebuild or restart) until the next approved nginx image rebuild. Until that rebuild, a container restart regenerates the old fallback from the image's copy of this script.
- **nginx refuses unknown host names.** New catch-all servers: port 80 closes the connection (444) and port 443 rejects the TLS handshake, so a request with any other `Host` no longer lands on the dashboard. The stock `conf.d/default.conf` is removed from the image. Without `DOMAIN` (access by IP address) the dashboard stays the default.
- **nginx sees the visitor's address.** `CF-Connecting-IP` is used as the client address for connections that come from Cloudflare's published ranges (`docker/nginx/cloudflare-realip.conf`, regenerated by the new `scripts/update-cloudflare-ips.sh`) and ignored from anyone else. `X-Forwarded-For` and `X-Forwarded-Host` are now set by nginx and no longer passed through from the client.
- **Rate limits are applied.** The two `limit_req_zone` lines in `nginx.conf` were never used. `/login`, `/register`, `/totp/setup`, `/totp/verify`, `/api/digest/subscribe` and `/api/send-brief` now share 10 requests a minute per visitor (burst 10); over the limit nginx answers 429.
- **Threat-watch relays are narrowed.** `/api/nvd/`, `/api/threatfox` and `/api/urlhaus` each accept one method and one fixed upstream path, bodies up to 4 kB, 30 requests a minute per visitor, and no longer send `Access-Control-Allow-Origin: *`, so other websites cannot use them.
- **`/healthz` answers 404 through nginx**; it is for the container healthcheck only.

### Added

- **`upgrade.sh`** — upgrades an existing install to a release: pre-flight checks, verified database dump, checkout, `.env` fixes, origin lock update, image rebuild, containers recreated one by one, health and public URL checks. Documented in `docs/runbook.md`.
- **Cloudflare origin lock (`ops/cf-origin-lock/`).** A systemd oneshot (`cf-origin-lock.service`, ordered after Docker and the CrowdSec firewall bouncer) with a weekly refresh timer. It builds the `cf4` and `cf6` ipsets from Cloudflare's published lists and adds `DOCKER-USER` rules for `iptables` and `ip6tables` that drop new inbound connections to ports 80 and 443 from any other source. The rules carry `--ctdir ORIGINAL`, so replies to connections that containers open to ports 80/443 are no longer matched; each run removes rules of the older form that broke container egress. Lists are validated before use, the last good copy is kept when a download fails, an unterminated last line is no longer dropped, and every run ends with a self-test (rules, ipset sizes, one HTTPS request from a container). `deploy.sh` installs it with `ORIGIN_LOCK=1`. No SSH or ufw changes. Documented in `docs/runbook.md`.

### Removed

- **Web Check.** The `webcheck` service (`lissy93/web-check:latest`, public and unauthenticated on the stack's network), its virtual host, the dashboard's Web Check button and the documentation section are gone. See Upgrade notes.
- **`/api/send-brief` proxy locations** on the website and threat-watch virtual hosts. No page on either site calls the endpoint.

## [1.1.0] - 2026-07-04

Quick Scan tab, safe_fetch SSRF/TLS hardening, session lifecycle refactor, N+1 collapse, and audit remediation.

### Security

- **SEC-FABLE-1 / SEC-05 / SEC-06:** Introduced `dashboard/http_client.py` with `safe_fetch` — hardened outbound HTTP client enforcing HTTPS, TLS verification (`verify=True`), per-host allowlist, and IP blocklist; all proxy routes and the crt.sh fetch in `dns_crawler.py` migrated to `safe_fetch`
- **SEC-FABLE-1:** Closed IPv4-mapped IPv6 bypass (`::ffff:a.b.c.d`) and missing reserved ranges (CGNAT `100.64.0.0/10`, `192.0.0.0/24`, `198.18.0.0/15`, `0.0.0.0/8`) in the private-IP blocklist
- **SEC-FABLE-3:** Applied SSRF guard to `dns_crawler` recon path (port scan, directory enumeration, zone transfer); private-IP targets rejected before connect
- **SEC-FABLE-4:** Added missing negative tests for `check_host_ssrf` and default redirect behaviour
- **SEC-FABLE-6:** Stopped leaking stack traces and resolved IPs in error responses; generic messages returned to client, full detail logged server-side
- **SEC-05 / SEC-06:** Allowlisted RDAP registry servers so domain lookups resolve past the rdap.org redirect
- **SEC-01:** Flask refuses to start if `DASHBOARD_SECRET_KEY` is absent or set to the placeholder value
- **SEC-04:** `next=` redirect parameter validated against open-redirect; only paths starting with `/` accepted
- **SEC-08:** `html.escape()` applied to all hit context fields before interpolation in alert email body
- **SEC-13:** Warning emitted when Tor control port accepts unauthenticated connections

### Performance

- **PERF-01 / COR-06:** Collapsed N+1 on ransomware groups endpoint — all keyword hit counts fetched in a single query
- **COR-07:** Collapsed N+1 on threat actors endpoint — same pattern

### Features

- **Quick Scan tab** — on-demand OSINT sweep of any domain, IP, URL, or company name; live progress streaming, per-source results, cancel endpoint with orchestrator interrupt, source config module and target-type normalisation
- Quick Scan storage models and `Storage` methods (`quick_scan_sessions`, `quick_scan_findings`)
- Quick Scan routes: `POST /api/quick-scan/start`, `GET /api/quick-scan/<id>/status`, `POST /api/quick-scan/<id>/cancel`
- Unit and integration tests for Quick Scan target detection, variant normalisation, and storage

### Chore

- **PERF-05 / COR-05:** Refactored `Storage` methods to use request-scoped SQLAlchemy session via Flask `g` when in Flask context, reducing per-request connection overhead
- **COR-05:** Added request-scoped session lifecycle (`get_session`, teardown) via `storage_helper.py`
- **OPS-02:** App container now runs as non-root user (`appuser`, uid 1000)
- **OPS-01:** Added healthcheck to `dashboard` service (`GET /` via curl, 15 s interval)
- **COR-14:** Synced `__version__` and `__license__` in `__init__.py` with `pyproject.toml`
- **COR-03:** Replaced `exit(1)` with `RuntimeError` in `check_disk_space()`
- **COR-02:** Replaced SQLite `datetime('now')` with portable Python timestamp
- **COR-01:** Fixed crawl session status double-update on failure — failed scans no longer appear as completed
- Replaced deprecated `datetime.utcnow()` with timezone-aware equivalent throughout
- Fixed ruff lint errors (E402, E701, noqa syntax, unused variables, ambiguous names)
- Thread-safe `Storage` singleton to eliminate `create_tables` race on startup

## [1.0.1] - 2026-03-15

### Added
- **Intelligence Dashboard (Home tab)** — new start page replacing the crawler stats as the default landing page
  - Regional threat level indicator (HIGH/ELEVATED/MODERATE) based on live SEA victim counts
  - KPI bar: RW groups, total victims, press reports, crawl hits, seeds, keywords
  - Live recent victims feed from ransomware.live PRO
  - Top active groups ranked by victim count with SEA targeting flags
  - SEA victim breakdown bar chart by country (PH, ID, MY, TH, VN, SG) with real counts
  - ThreatFox IOC mini-feed (latest 8 IOCs)
  - Ransomware press feed filtered for SEA-relevant articles
  - Quick actions grid for common workflows
  - System status panel showing all API/service health
- **ransomware.live PRO API integration** (`ransomware_live.py` + `ransomware_live_routes.py`)
  - Full PRO API client covering all documented endpoints: groups, victims, IOCs, negotiations, press, ransom notes, YARA rules, SEC 8-K filings, CSIRT directory, sectors
  - `/api/rwlive/*` Flask blueprint with 20+ endpoints
  - Graceful fallback to unauthenticated v2 API when no PRO key is set
  - Local `RANSOMWARE_GROUPS` data merged with live API data for SEA context enrichment
  - Composite endpoints for single-call data bundles (`/api/rwlive/home-data`, `/api/rwlive/ransomware-tab-data`)
  - SEA-specific convenience endpoints (`/api/rwlive/victims/sea`, `/api/rwlive/press/recent?sea=1`)
- **IOC Feed tab** — live indicators of compromise with sub-tabs for ThreatFox, URLhaus, and Feodo Tracker
  - Stats bar: total IOCs, IPs, domains, URLs, hashes
  - Searchable/filterable table with type chips, malware family, confidence bars, reporter
  - All feeds proxied through backend to avoid CORS restrictions
- **Backend proxy routes** in `dashboard_routes.py`
  - `POST /api/proxy/threatfox` — ThreatFox API proxy with `Auth-Key` header injection
  - `POST /api/proxy/urlhaus` — URLhaus recent URLs proxy
  - `GET /api/proxy/feodo` — Feodo Tracker C2 blocklist proxy
  - `GET /api/whiteintel/alerts` — WhiteIntel credential alerts proxy
  - `GET /api/whiteintel/search` — WhiteIntel domain search proxy
- **Crawls tab** — renamed from "Dashboard" tab, preserves all existing crawler session/stats UI
- New environment variables: `RANSOMWARE_LIVE_API_KEY`, `THREATFOX_API_KEY`, `WHITEINTEL_API_KEY`

### Changed
- Default landing page is now the Intelligence Dashboard (Home tab) instead of the Crawls tab
- Nav tab order updated: Dashboard (Home) → Crawls → Keywords → Seeds → ... → IOC Feed → ...
- `ransomware_live.py` press endpoints now correctly unwrap `{results:[...]}` response wrapper from PRO API
- SEA victim counts now fetch up to 500 victims per country instead of capped at 20
- Group display on Home tab uses live victim counts from ransomware.live (not local static data)

### Fixed
- ThreatFox 401 errors — correct `Auth-Key` header now used (was `API-KEY`)
- JS syntax errors from nested quotes in `querySelector` `onclick` attributes — replaced with `hdGoTo()` helper
- Press feed returning empty — PRO API wraps response in `{results:[...]}` which is now unwrapped
- SEA breakdown bars all showing 20 — removed per-country cap, now shows real counts

## [1.0.0] - 2026-03-10

### Added
- **DNSDumpster enrichment** — `POST /api/dns/investigations/<id>/enrich` fetches additional passive DNS records from DNSDumpster and merges them into the investigation; requires `DNSDUMPSTER_API_KEY` in `.env`
- **Certificate Transparency tab** — dedicated Cert History view in the DNS tab
  - Live fetch from crt.sh with stat strip: total certs, active, expired, expiring soon, unique SANs
  - Certificate issuers bar chart and issuance-by-year timeline chart
  - SAN list with copy-to-clipboard button
  - Full cert table with 50-row pagination and colour-coded status (active / expiring / expired)
- **OSINT Toolkit tab** — seven proxied OSINT tools accessible directly from the dashboard without leaving the UI: Shodan, Censys, GreyNoise, URLScan, MXToolbox, SecurityTrails, and VirusTotal; plus curated OSINT resource links
- **PDF world map** — Infrastructure Recon PDF now includes a real world map (Playwright + jsvectormap screenshot) with active country markers; layout updated so map appears between the pie charts and ASN table on page 1
- **PDF certificate section** — rich Certificate Transparency section in PDF export with stat strip, issuer bar chart, issuance timeline, and full colour-coded cert table
- `playwright>=1.40` added to dependencies; Chromium installed at Docker build time for server-side map rendering

### Changed
- PDF Infrastructure Overview layout: world map now sits between the overview charts and the ASN detail table on page 1; subdomain graph moved to its own page
- Docker app image now installs Chromium system dependencies and runs `playwright install chromium` during build — no manual setup required

### Fixed
- `GET /api/dns/certs/<domain>` route now registered with `strict_slashes=False` to handle trailing slash variants
- Cert history 502 errors caused by nginx timeout on slow crt.sh responses — resolved by reducing default request timeout

## [0.9.1] - 2026-03-07

### Fixed
- `genProjectSelect` dropdown not populating with projects on Keywords tab load
- API returns plain array but code was reading `pd.projects` — fixed to `Array.isArray(pd)`
- `.panel` CSS `overflow:hidden` was clipping the dropdown — changed to `visible`
- Flask template cache required `docker compose restart` to pick up changes

### Changed
- `_populateGenProjectDropdown()` extracted as standalone function, called on tab switch

## [0.9.0] - 2026-03-09

### Added
- **Active subdomain brute-force** (`dns_crawler.py`)
  - 100-entry built-in wordlist covering common prefixes: `www`, `api`, `mail`, `vpn`, `dev`, `staging`, `admin`, `portal`, `git`, `ci`, `monitor`, `db`, and more
  - Runs in parallel (50 workers) via `ThreadPoolExecutor` — typically completes in under 5 seconds
  - Results tagged with `source: bruteforce` to distinguish from passive discovery
- **TCP port scanner** — 30 common ports, per-port timeout configurable, returns open/closed/filtered
- **HTTP/HTTPS directory enumeration** — probes 70 common paths, surfaces all non-404 responses with status, content-length, and redirect destination
- **Two new API endpoints**: `POST /api/dns/investigations/<id>/scan` and `GET /api/dns/investigations/<id>/scan/status`
- **Redesigned DNS tab UI** — six view tabs: Graph, Subdomains, Ports, Directories, Email Security, DNS Records
- **Channel Monitor tab** — on-demand Telegram channel scraping from the dashboard
  - Auto-translates messages to English via `deep-translator`
  - Downloads photos and videos; packages results as a ZIP
  - Live streaming log with job history

### Changed
- `dns_crawler.py` — `run_dns_recon()` now includes Phase 2b (active brute-force) automatically
- `app.py` — registers `channel_monitor_bp` blueprint
- `pyproject.toml` — adds `deep-translator` and `langdetect` to dashboard dependencies

## [0.6.0] - 2026-02-23

### Added
- **PostgreSQL migration** — platform now runs on PostgreSQL 16 (was SQLite)
  - `postgres:16-alpine` service added to Docker Compose
  - `pg_data` named volume for persistent storage

## [0.5.0] - 2026-02-22

### Added
- **Web Check integration** — on-demand OSINT analysis for any domain as a separate Docker service
- **Projects feature** — scoped monitoring engagements with per-project keywords, domains, entities, and hit tracking
- **Paste Monitor** — monitors rentry.co for keyword hits
- **Telegram scraper enhancements** — expanded to 49 channels covering SEA/PH threat intel

## [0.4.0] - 2026-02-21

### Added
- DNS Reconnaissance module — passive + active DNS recon, zone transfer attempts, crt.sh enumeration, HackerTarget subdomain discovery, geolocation, SPF/DMARC/DKIM analysis, PDF export

## [0.3.0] - 2026-02-15

### Added
- Curated daily threat intelligence digest — CISA KEV, OTX pulses, URLhaus, Feodo Tracker, RSS feeds; PDF generation and HTML email delivery via Mailgun

## [0.2.0] - 2026-02-01

### Added
- IP Investigation module — AbuseIPDB + VirusTotal lookups with history
- Ransomware tracker — 12+ active groups with SEA victim focus
- Threat actor profiles — APT and criminal groups targeting SEA
- Telegram channel scraper — monitors configurable public channels
- TOTP two-factor authentication and OAuth (Google/GitHub)
- PDF report generation via ReportLab
- Role-based access control (admin / analyst)

## [0.1.0] - 2024-01-01

### Added
- Async BFS crawler with configurable depth and concurrency
- Tor circuit rotation via stem
- Keyword scanner with category support and context windows
- SQLite and PostgreSQL storage backends via SQLAlchemy
- Webhook and email alerting
- Flask dashboard with real-time hit viewer
- Docker Compose setup
- CLI with `scan`, `stats`, `hits`, `check-tor` commands 
