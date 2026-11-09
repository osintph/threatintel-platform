# Operations runbook

Day-to-day operations for a production install. Commands are run as root from the install directory unless stated otherwise.

- [Upgrading](#upgrading)
- [Database schema](#database-schema)
- [Backups and restore test](#backups-and-restore-test)
- [Accounts and sign-in](#accounts-and-sign-in)
- [Dependencies and base images](#dependencies-and-base-images)
- [Health and logs](#health-and-logs)
- [Tor](#tor)
- [Channel Monitor](#channel-monitor)
- [nginx](#nginx)
- [Certificates](#certificates)
- [Cloudflare origin lock](#cloudflare-origin-lock)
- [Demo instance](#demo-instance)

---

## Upgrading

```bash
cd /path/to/install
sudo ./upgrade.sh            # tip of main
sudo ./upgrade.sh v1.4.0     # a release tag, branch or commit
```

What it does, in order:

1. **Pre-flight.** Stops if a git operation is unfinished (cherry-pick, merge, rebase) or tracked files have local changes. Untracked files, `.env`, `config/` and a `docker-compose.override.yml` are left alone.
2. **Database dump** to `backups/pre-upgrade-<UTC time>.dump` (`pg_dump -Fc`), read back with `pg_restore --list`. The five newest are kept. `SKIP_BACKUP=1` skips it.
3. **Checkout.** A branch is fast-forwarded; a tag or commit is checked out detached. The commit you came from is written to `.upgrade-previous-commit`. The `www` submodule is not moved unless you pass `UPDATE_WWW=1`, because the website is deployed on its own schedule. When the release you are moving to has an older database schema than the one installed, the schema is taken back first (see [Roll back](#roll-back)).
4. **`.env` fixes and checks.** `DATABASE_URL` gets the `postgresql+psycopg2://` driver name; the file is set to mode 600. Settings that no release reads any more (`TOR_CONTROL_PORT`, `TOR_CONTROL_PASSWORD`, `FLASK_DEBUG`, `DASHBOARD_PORT` and the OAuth client settings) are removed, after the old file is copied to `backups/env-before-<UTC time>` (mode 600); their names are printed, values never. The script stops here, before anything is rebuilt, if `DASHBOARD_SECRET_KEY` is shorter than 32 characters. Settings that `.env.example` has and your `.env` lacks are listed by name.
5. **Leftovers of removed features.** The paste monitor's job is removed from root's crontab, after the crontab is copied to `backups/root-crontab-before-<UTC time>`. Every other line stays.
6. **Origin lock.** Updated in place when it is installed (see below).
7. **Build and start.** The image each service runs is kept as `<image>:previous`. Images are rebuilt from `requirements.lock` and the pinned base images, then PostgreSQL, Tor, the dashboard and nginx are recreated in that order, each waited for. nginx is reloaded at the end. A full run (no `SERVICES`) also removes containers of services that are no longer in `docker-compose.yml`. The dashboard brings the database schema up to date when it starts (see [Database schema](#database-schema)); its healthcheck passes only after that.
8. **Checks.** Version and container states, then every URL in `SITE_URLS` (default: `https://DOMAIN/login` and `https://WWW_DOMAIN/`) is requested from this server's own nginx on loopback, under its host name, and must answer 200; the script exits non-zero otherwise. The same URLs are then tried the public way. A server error (5xx) there also fails the run. Any other answer is only reported: Cloudflare, for one, answers requests from the server's own address with a challenge page (403), which says nothing about the site, so open the URL from another machine.

`SERVICES="tor dashboard" sudo ./upgrade.sh` limits steps 7 and 8 to those services.

A [demo instance](#demo-instance) that is running is moved to the new image after step 7. A problem there is reported and does not fail the upgrade.

### Roll back

```bash
sudo ./upgrade.sh "$(cat .upgrade-previous-commit)"
```

That rebuilds the previous commit. When that release has an older database schema (1.3.0 back to 1.2.0, for example), the script does three things before the checkout: it dumps the database as on every run, stops the dashboard, and takes the schema back with the installed release (`db-downgrade`). What the newer revisions added is dropped, and what they removed comes back empty; the dump holds the state from before. It refuses to do this with `SKIP_BACKUP=1`.

If the build itself is the problem, start the kept image instead. Take the schema back by hand first when the two releases differ in schema revision (compare `db-status` with the table in [Database schema](#database-schema)):

```bash
docker compose stop dashboard
docker compose run --rm --no-deps dashboard python -m darkweb_scanner.main db-downgrade 0001 --yes   # only if the schema changed
docker tag darkweb-scanner-dashboard:previous darkweb-scanner-dashboard:latest
docker compose up -d --no-deps --no-build dashboard
```

Restore the database only if the upgrade changed data you need back:

```bash
docker compose stop dashboard
docker compose exec -T postgres pg_restore -U scanner -d darkweb_scanner --clean --if-exists < backups/pre-upgrade-<time>.dump
docker compose up -d dashboard
```

A restored dump carries its own schema revision, and the dashboard upgrades it again when it starts.

## Database schema

The schema is versioned with Alembic. The revisions are in `src/darkweb_scanner/migrations/versions/`, and the table `alembic_version` holds the one the database is at.

| Revision | Release | What it does |
|---|---|---|
| `0001` | 1.2.0 | The baseline: every table and index of 1.2.0. It creates only what is missing, so it is safe on a database that already has them. |
| `0002` | 1.3.0 | `crawl_sessions` gets `heartbeat_at`, `owner` and `error`; the tables `seen_pastes` and `paste_hits` and the columns `users.oauth_provider` and `users.oauth_id` are dropped. |

- **Nothing to run by hand.** The dashboard, and every `python -m darkweb_scanner.main` command, brings the schema to the newest revision of its release before it does anything else. On PostgreSQL this happens in one transaction under an advisory lock: all revisions apply or none, and two processes starting together do not collide.
- **A new, empty database** gets the current tables directly and is marked as being at the newest revision.
- **A database from 1.2.0 or older** has no `alembic_version` table. It is treated as being before `0001`: the baseline adds whatever is missing, then the later revisions apply. Rows are kept.
- **Check:** `docker compose exec dashboard python -m darkweb_scanner.main db-status` prints the revision of the database and the newest one the release knows. If a revision fails, the dashboard does not start and the reason is in `docker compose logs dashboard`; the database is left as it was.
- **Going back** to an older release needs the older schema first, because old code does not know the new one. `upgrade.sh` does it (see [Roll back](#roll-back)). By hand: stop the dashboard, then `docker compose run --rm --no-deps dashboard python -m darkweb_scanner.main db-downgrade <revision> --yes` with the release that is installed, then switch releases. Do not start the newer dashboard in between; it would upgrade the schema again.
- **Changing the schema** (developers): change the model in `storage.py` and add `versions/000N_<what>.py` whose `down_revision` is the newest existing one, with an `upgrade()` and a `downgrade()`. `tests/integration/test_migrations.py` fails until the revisions alone produce the same schema as the models, on SQLite and on PostgreSQL.

## Backups and restore test

`upgrade.sh` dumps the database before every upgrade, but those dumps stay on the same disk. A backup that survives the loss of the server needs a copy somewhere else (restic, borg or a snapshot service), taken on a schedule, of these:

| What | Where | Why |
|---|---|---|
| Database | a nightly `docker compose exec -T postgres pg_dump -U scanner -Fc darkweb_scanner > <file>` | Everything the dashboard shows. Back up the dump file, not the `pg_data` volume of a running server. |
| `.env` | the install directory | Every secret and setting. Without `DASHBOARD_SECRET_KEY` all sessions end; without `POSTGRES_PASSWORD` a restored volume cannot be opened. |
| `config/` | the install directory | Keywords, seeds, digest subscribers. |
| Data volume | `/var/lib/docker/volumes/darkweb-scanner_app_data/_data` | The Telegram session files (without them: authorise again) and the Channel Monitor archives. |
| Certificates | `/var/lib/docker/volumes/darkweb-scanner_letsencrypt/_data` | Saves a new issuance, which Let's Encrypt limits per week. |
| Files you added | `docker-compose.override.yml` and anything else untracked in the install directory (`git status --short --ignored`) | Not in git, so not restorable from the repository. |
| Server set-up | `/usr/local/sbin/cf-origin-lock`, `/etc/systemd/system/cf-origin-lock.service`, your backup scripts and their configuration | Small, and tedious to redo. |

Not needed: the `tor_data` volume (Tor rebuilds it) and the images (rebuilt from the repository).

The dump runs over the socket inside the PostgreSQL container, so no password is needed and none appears in a process list.

### Restore test

A backup counts once a restore from it has worked. `scripts/restore-test.sh` restores a dump into a throwaway PostgreSQL container that has no network and keeps its data in memory, prints the row count of every table, and removes the container. The live database is not touched, and no row content is printed.

```bash
scripts/restore-test.sh backups/pre-upgrade-<time>.dump          # a pg_dump -Fc file, plain or gzipped
COMPARE=1 scripts/restore-test.sh /path/to/nightly.dump.gz       # with the live row counts next to it
ssh server 'sudo cat /path/to/nightly.dump.gz' | scripts/restore-test.sh -     # on another machine; nothing is written to its disk
```

It ends with `restore-test: PASSED — <n> tables, <n> rows restored without an error` and exit status 0, or with `FAILED` and status 1. With `COMPARE=1`, tables whose count differs from the live database are marked; tables that receive rows all the time (sign-in log, crawl results) differ by what was added since the dump.

Do this **after every change to the backup set-up and once a quarter**, with a file taken from the off-site copy, not from the server's own disk. Once a year, do the full exercise on a spare machine: restore the files from the table above, run `deploy.sh`, restore the dump with the `pg_restore` command under [Roll back](#roll-back), and sign in.

## Accounts and sign-in

The rules, as the application enforces them on every request (they are also shown to users under **Help & privacy** in the dashboard):

- **Roles.** A user is an administrator or not. Global settings (keywords, seeds, sources, channel lists), crawl control, deletes, digest subscribers, user administration and Channel Monitor are for administrators. Everything else is a workspace shared by all signed-in users.
- **Second factor.** Mandatory for everyone. An account without one can only reach the enrolment page. A code works once.
- **Passwords.** At least 12 characters with an uppercase letter, a lowercase letter, a number and a symbol. A new user gets a temporary password from the administrator and must replace it at the first sign-in.
- **Lockouts.** 10 wrong passwords for one user name, or 20 failed attempts from one address, within 15 minutes: sign-in is refused for 15 minutes. 5 wrong codes: the second step is locked for 15 minutes. nginx also limits the sign-in pages to 10 requests a minute per visitor.
- **Sessions** end 12 hours after sign-in. Signing out, a password change, a second-factor change, an administrator's reset or deleting the user ends that user's sessions everywhere. Changing `DASHBOARD_SECRET_KEY` ends everyone's.

### First administrator

`/register` works only while the database holds no users, and only with the `SETUP_TOKEN` from `.env` (`deploy.sh` generates it; at least 24 characters). With no token set the page is closed. After the administrator exists the token has no further use; remove the line if you like.

```bash
grep '^SETUP_TOKEN=' .env          # run this on the server, in your own terminal
```

Further users are created by an administrator on the dashboard's **Users** tab.

### Locked out, or a lost authenticator

An administrator can reset another user's second factor on the **Users** tab ("Reset 2FA"). For the administrator's own account, or when nobody can sign in, use the commands on the server. They need no password and show no secrets:

```bash
docker compose exec dashboard python -m darkweb_scanner.main user-list
docker compose exec dashboard python -m darkweb_scanner.main user-unlock NAME [--address 203.0.113.9]
docker compose exec dashboard python -m darkweb_scanner.main user-reset-mfa NAME
```

- `user-list` shows each account (id, name, admin, second factor on or off, temporary password pending, last sign-in) and the locks in force.
- `user-unlock` lifts the password lock and the code lock of that user and, with `--address`, the lock on a network address.
- `user-reset-mfa` removes the second factor and ends the user's sessions; the user signs in with the password and enrols a new authenticator straight away.

Both changes are written to the sign-in log.

### Sign-in log

Sign-ins, failures, lockouts, sign-outs, password and second-factor changes and user administration are stored in the `auth_events` table for 365 days, with the time, user name and address. Administrators read it on the dashboard's **Users** tab (Sign-in log) or with:

```bash
docker compose logs dashboard | grep 'auth event='
```

## Dependencies and base images

- `requirements.lock` holds the exact version and hashes of every Python package. The image installs only from it (`pip install --require-hashes`). Change a dependency in `pyproject.toml`, then run `make lock` and commit both files.
- The base images in `docker/*/Dockerfile` and the PostgreSQL image in `docker-compose.yml` are pinned by digest. Dependabot opens a pull request each month when a newer digest exists.
- **Monthly:** run `make lock`, merge the Dependabot pull requests, let CI pass, then `sudo ./upgrade.sh` on the server. This picks up security fixes in Python packages and in the base images.

## Health and logs

- `GET /healthz` on the dashboard runs `SELECT 1` and answers 200 or 503. The container healthcheck uses it, so `docker compose ps` shows `unhealthy` when the app cannot reach PostgreSQL. It needs no login and returns no data.
- Every service logs through `json-file` with at most 5 files of 20 MB. Read them with `docker compose logs --tail 200 <service>`.
- The dashboard is served by gunicorn with **one worker process and 8 threads**. Keep it at one worker: the job limits, the upstream cache and the Quick Scan and Channel Monitor jobs live in that process's memory, and a second worker would not see them. A crawl records its owner (`host:pid`) and a heartbeat in `crawl_sessions`; a running session whose heartbeat is older than `CRAWL_STALE_SECONDS` is ended as `interrupted`, so a dead crawl no longer blocks the next one. There is no debug mode.
- The dashboard does not start without `DATABASE_URL`, or with a `DASHBOARD_SECRET_KEY` shorter than 32 characters; the reason is in `docker compose logs dashboard`.
- A change in `.env` takes effect after `docker compose up -d dashboard` (`restart` does not re-read the file).

## Tor

- The Tor container is a client only. Its `torrc` is written by `docker/tor/entrypoint.sh` each time the container starts; neither the repository nor the image holds one. See it with `docker compose exec tor cat /etc/tor/torrc`.
- There is **no control port** and no control password. The crawler gets a new circuit every `ROTATE_CIRCUIT_EVERY` pages by opening its next connections with new SOCKS credentials, which Tor keeps on separate circuits.
- The SOCKS port (9050) is reachable from the stack's Docker network only; it is not published on the host.
- Check: `make check-tor`, or `docker compose logs tor | grep Bootstrapped`.

## Channel Monitor

- **Administrators only**, and **public channels only**: a public user name, `@name` or a `t.me/name` link. Private chats, saved messages, phone numbers, numeric ids and invite links are refused before Telegram is contacted, and again after the name is resolved.
- **Translation uses Google Translate.** The text of each message that is not English is sent from the server to `translate.google.com` (no key, no account; media, sender and channel name are not sent). Do not run a job on content that must not be disclosed to Google.
- **Retention.** A job folder and its archive are deleted `CHANNEL_MONITOR_RETENTION_DAYS` days (default 90) after their last change. The sweep runs when the dashboard starts and at most once an hour while Channel Monitor is in use. It never touches a running job or the Telegram session file. **The first start of 1.2.0 deletes every job folder older than the limit**, so download what you want to keep before upgrading.
- Jobs record the administrator who started them. A running job cannot be deleted.
- **One job at a time.** A second start answers 409 and names the running job.
- **Job state is on disk.** Each job folder under `/app/data/channel_monitor/` holds `job.json` (state) and `job.log`. After a restart the list is read from the folders: a job that was running shows as **Interrupted**, and an export from before 1.3.0 (no `job.json`) shows as **Archived**; both can be downloaded and deleted.
- **Sign-in.** A job never asks Telegram for a login code. Sign the session in once with `docker compose exec dashboard python -m darkweb_scanner.main channel-monitor-auth` (it asks for the code Telegram sends, and for the phone number if `TELEGRAM_PHONE` is empty). Run it when no job is running. The session file `channel_monitor.session` is kept at mode 600. A job that finds no signed-in session ends with an error that names the command.
- **Limits** are set in `.env`, never by the request: `CHANNEL_MONITOR_MAX_MESSAGES` (5000), `CHANNEL_MONITOR_MAX_FILE_MB` (50, photos and image files), `CHANNEL_MONITOR_MAX_VIDEO_MB` (200), `CHANNEL_MONITOR_MAX_JOB_GB` (2, media of one job), `CHANNEL_MONITOR_MIN_FREE_GB` (5), `CHANNEL_MONITOR_MAX_DOWNLOAD_GB` (5). Below the free-space minimum no job starts and a running job stops, keeps what it has read and ends with an error. Keep the job limit at or below the download limit.
- **One ZIP per job**, built on the first download and reused, so a downloaded job takes about twice its size until it is deleted or expires. `job.log` is in the ZIP; `job.json` is not.
- **Errors.** The job log and the API show a plain sentence and an 8-character error id; the traceback is in `docker compose logs dashboard` under `[error_id=...]`.
- **A stuck job** (a translation request that never returns, for example) holds the only slot. `docker compose up -d --force-recreate dashboard` ends it as Interrupted; what it saved can be downloaded.
- The report (`messages.html` in the archive) shows channel content as text only and carries a policy that blocks scripts and remote content.

## nginx

The virtual hosts are generated by `docker/nginx/entrypoint.sh` when the container starts; `docker/nginx/nginx.conf` holds the shared settings. A change to either needs the image rebuilt (`SERVICES=nginx sudo ./upgrade.sh`).

- **Unknown host names** are refused: port 80 closes the connection (444), port 443 rejects the TLS handshake. Only `DOMAIN`, `WWW_DOMAIN` (with `www.`) and `THREATWATCH_DOMAIN` are served. Without `DOMAIN` the dashboard answers on any name, for installs reached by IP address.
- **Visitor address.** `docker/nginx/cloudflare-realip.conf` lists Cloudflare's ranges; for connections from them, `CF-Connecting-IP` becomes `$remote_addr` (logs, rate limits, `X-Real-IP`). From any other peer the header is ignored. `X-Forwarded-For` and `X-Forwarded-Host` are set by nginx and never passed through from the client. When Cloudflare changes its ranges, run `scripts/update-cloudflare-ips.sh`, commit, and rebuild nginx.
- **Rate limits** (HTTP 429): `/login`, `/register`, `/totp/setup` and `/totp/verify` share 10 requests a minute per visitor with a burst of 10. The three relays on the threat-watch site (`/api/nvd/`, `/api/threatfox`, `/api/urlhaus`) allow 30 a minute with a burst of 20, one method each, same-origin only.
- **The dashboard is looked up at request time** (Docker's DNS, cached for 10 seconds). Rebuilding or recreating the dashboard needs no nginx restart, and nginx starts even when the dashboard is down (it answers 502 until it is back).
- **`/healthz`** is for the container healthcheck and answers 404 through nginx.
- **Reload without a restart:** `docker compose exec nginx nginx -s reload`.

## Certificates

- Let's Encrypt certificates and keys are in the `letsencrypt` volume (`/etc/letsencrypt` in the nginx container). `/etc/nginx/certs/*.pem` are links to them. A container start replaces the links and never writes to the files behind them.
- A name without a certificate gets a self-signed pair (a regular file in `/etc/nginx/certs`), kept until it has less than 30 days left. In domain mode the entrypoint then asks Let's Encrypt for a certificate over the webroot challenge.
- Renewal: `certbot renew` runs daily at 12:00 in the nginx container, followed by `nginx -s reload`.
- When you run `certbot renew` from a script or over a session without a terminal, add `--no-random-sleep-on-renew`; without it certbot waits up to eight minutes before it starts.

Check what the origin serves and what certbot holds:

```bash
echo | openssl s_client -connect 127.0.0.1:443 -servername scanner.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate
docker compose exec nginx certbot certificates
```

**Repair after a version before 1.1.1.** Those versions overwrote `fullchain.pem` and `privkey.pem` with a self-signed pair at every container start. certbot does not notice, because it reads the untouched `cert.pem`. nginx logs `the certificate files for <name> were overwritten` at start when that is the case. Order a new certificate once for each name that is reported, then reload:

```bash
docker compose exec nginx certbot renew --cert-name scanner.example.com --force-renewal --no-random-sleep-on-renew
docker compose exec nginx nginx -s reload
```

Let's Encrypt allows five certificates for the same set of names per week, so do not repeat this in a loop. When the origin serves a Let's Encrypt chain for every name, set the Cloudflare SSL mode to **Full (strict)**.

**Removing a name** (for example a retired service): delete its certificate so the daily renewal stops asking for it, and remove its DNS record:

```bash
docker compose exec nginx certbot delete --cert-name old.example.com
```

---

## Cloudflare origin lock

**Use this only when every public name of the server is proxied through Cloudflare.** Docker publishes ports 80 and 443 through its own NAT rules, which bypass ufw, so anyone who knows the server's address can reach nginx directly and skip Cloudflare. The origin lock drops new inbound connections to those ports unless they come from one of Cloudflare's published ranges.

Files, all installed from `ops/cf-origin-lock/`:

| File | Purpose |
|---|---|
| `/usr/local/sbin/cf-origin-lock` | the script: `apply`, `refresh`, `selftest`, `remove`, `status` |
| `/etc/systemd/system/cf-origin-lock.service` | oneshot at boot, after Docker and the CrowdSec firewall bouncer; `ExecStop` removes the lock |
| `/etc/systemd/system/cf-origin-lock-refresh.service` and `cf-origin-lock.timer` | weekly refresh of Cloudflare's ranges |
| `/etc/cf-origin-lock/ips-v4`, `ips-v6` | last good copy of Cloudflare's lists; used when a download fails |
| `/etc/default/cf-origin-lock` | settings: `IFACE` (written at install time from the default route) and `PORTS` (default `80 443`) |

### What it does

1. Downloads `https://www.cloudflare.com/ips-v4` and `ips-v6`. A download replaces the cached copy only if every line is a CIDR, no range is wider than /8 (IPv4) or /16 (IPv6) and the list is not unusually short. Otherwise the previous copy is kept.
2. Builds the ipsets `cf4` and `cf6` in a temporary set and swaps them in, so the live set is never empty.
3. Adds, for `iptables` with `cf4` and `ip6tables` with `cf6`, for each port:

   ```
   -A DOCKER-USER -i <iface> -p tcp -m conntrack --ctorigdstport <port> --ctdir ORIGINAL -m set ! --match-set <set> src -j DROP
   ```

   `--ctdir ORIGINAL` is essential. Without it the rule also matches the replies to connections that containers open to ports 80/443 elsewhere, and every container loses outbound HTTP(S). Each run deletes any rule of that older form.
4. Self-test: the four rules exist, both ipsets hold as many entries as the lists, and one HTTPS request from inside a running container succeeds. Any failure is logged to the journal and the unit ends in the `failed` state (the rules stay in place).

It touches the `DOCKER-USER` chain and the two ipsets only. It makes no SSH or ufw changes.

### Install or update

```bash
sudo bash ops/cf-origin-lock/install.sh
```

`deploy.sh` runs this when called with `ORIGIN_LOCK=1`. `upgrade.sh` runs it whenever the lock is already installed.

### Check it

```bash
systemctl status cf-origin-lock.service          # active (exited) is the healthy state
systemctl list-timers cf-origin-lock.timer       # next weekly refresh
cf-origin-lock status                            # rules with packet counters, ipset sizes
cf-origin-lock selftest; echo "exit=$?"          # 0 = all good
journalctl -u cf-origin-lock.service -u cf-origin-lock-refresh.service -n 50
```

Every proxied site should still answer through Cloudflare, and a container should still reach the internet:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://YOUR_DOMAIN/login
docker compose exec dashboard python3 -c "import socket; socket.create_connection(('149.154.167.51', 443), 10); print('egress ok')"
```

### Roll back

```bash
systemctl stop cf-origin-lock.service            # removes the four rules and both ipsets
systemctl disable cf-origin-lock.service cf-origin-lock.timer
```

The ports are then reachable from any address again. `systemctl start cf-origin-lock.service` puts the lock back.

### After a reboot

The unit applies the lock on its own. To confirm: `cf-origin-lock selftest`, then the two checks above.

## Demo instance

A second copy of the dashboard filled with fake data, for showing the product. It is the `demo` profile in `docker-compose.yml` and never starts unless asked: `demo-dashboard` (the dashboard image), `demo-postgres`, their own volumes `demo_pg_data` and `demo_app_data`, and their own network `demo_net`.

- **Isolation.** `demo_net` has normal outbound internet, so the live feeds work, and no route to `postgres`, `tor` or `dashboard`. nginx is on both networks and is the only thing shared. Without Tor, starting a crawl or a Quick Scan in the demo fails with the plain message the product shows when Tor is down.
- **Secrets.** `.env.demo` (mode 600, not in git) has its own `DASHBOARD_SECRET_KEY`, `POSTGRES_PASSWORD` and `SETUP_TOKEN`. From `.env` it takes only the keys for read-only lookups and feeds: ransomware.live, ThreatFox, OTX, WhiteIntel, VirusTotal, AbuseIPDB, DNSDumpster, HIBP. Mail, digest, alert and Telegram settings are blank in that file and again in `docker-compose.yml`, so the demo sends nothing. The live tabs use your real API quotas.
- **Production data.** `./config` is not mounted, so production keyword and seed lists stay out.

### Set it up

Needs Docker Compose 2.24 or newer. In `.env` set the host name, and the name of a certificate that covers it if there is one (without it nginx orders a certificate for the name):

```bash
vi .env                 # DEMO_DOMAIN=demo.example.com   DEMO_CERT_NAME=example.com
make demo-env           # writes .env.demo; run again after changing a lookup key, the secrets stay
docker compose up -d --build --no-deps nginx   # short interruption of every site on this server
make demo-up
make demo-seed
```

### First administrator

`/register` works only while the demo has no users, so the first `make demo-seed` adds no accounts.

1. `grep '^SETUP_TOKEN=' .env.demo`
2. Open `https://DEMO_DOMAIN/register`, enter the token, choose a user name and password, and enrol an authenticator app.
3. Run `make demo-seed` again. It adds the analyst accounts and their sign-in history and gives the projects and Quick Scan sessions to the first administrator. Quick Scan shows each user only their own sessions.

### Refresh and remove

`make demo-seed` replaces all demo data with the same fake data, dated over the 90 days before the run. Accounts you created stay; the analysts are recreated. It refuses to run unless `DEMO_MODE=1` is set and the database is `darkweb_scanner_demo` on `demo-postgres`. The analysts cannot sign in: their passwords are random and never stored. The data is invented: `.example` domains, documentation IP ranges (RFC 5737), masked passwords, and onion addresses that are valid in form only. Hits name only invented groups.

With `DEMO_MODE=1`, which only `demo-dashboard` has, the DNS tab's certificate history shows the seeded certificates for `.example` domains instead of asking crt.sh. Any other domain gets the live lookup, as in production.

`make demo-stop` stops it and keeps the data. `docker compose --profile demo down -v` would remove every volume of the project, including production's, so never use it. To delete the demo: `make demo-stop`, `docker compose --profile demo rm -f demo-dashboard demo-postgres`, `docker volume rm darkweb-scanner_demo_pg_data darkweb-scanner_demo_app_data`.

### Upgrades and rollback

`upgrade.sh` moves a running demo to the new image once production is up. It does not dump the demo database. The demo upgrades its own schema when it starts. After rolling back to a release with an older schema the demo may not start, because its schema is newer than the code: delete it as above and set it up again.
