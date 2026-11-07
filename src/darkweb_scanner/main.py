"""
Main entry point — orchestrates crawling, scanning, storage, and alerting.
"""

import asyncio
import functools
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click

from . import regex_safety
from .alerting import Alerter
from .crawler import (
    HEARTBEAT_SECONDS,
    STALE_SECONDS,
    CrawlAlreadyRunning,
    CrawlConfig,
    Crawler,
    claim_local_crawl,
    crawl_owner,
    release_local_crawl,
)
from .scanner import KeywordConfig, Scanner
from .storage import Storage
from .tor_client import TOR_CHECK_TIMEOUT, TorNotReachable, create_tor_client

# ── Logging setup ──────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
# To the container log only (rotated by Docker). There is no log file in the data volume.
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ── Core orchestration ─────────────────────────────────────────────────────────




@functools.lru_cache(maxsize=1024)
def _pattern_refusal(pattern: str):
    """Why regex_safety refuses ``pattern``, or None when it may run."""
    try:
        regex_safety.check_pattern(pattern)
    except regex_safety.UnsafePattern as exc:
        return str(exc)
    return None


_skipped_patterns: set = set()


def _project_pattern_matches(project: dict, pattern: str, context: str) -> bool:
    """A stored project pattern, checked again and run on clipped text only.

    A pattern saved before 1.3.0 may fail the check: it is skipped, with one
    warning per project and pattern, and the crawl carries on.
    """
    reason = _pattern_refusal(pattern)
    if reason is not None:
        key = (project.get("id"), pattern)
        if key not in _skipped_patterns:
            _skipped_patterns.add(key)
            logger.warning(
                "Project %r: skipping keyword pattern %r: %s",
                project.get("name"), pattern[:80], reason,
            )
        return False
    return regex_safety.search(pattern, context)


def match_hit_to_projects(hit_id: int, url: str, keyword: str, context: str, storage):
    """Match a newly saved hit against all active projects."""
    try:
        projects = storage.get_active_projects_with_config()
        for project in projects:
            matched_on = None
            matched_value = None

            # Match on project keyword
            for kw in project.get("keywords", []):
                kw_val = kw.keyword if hasattr(kw, 'keyword') else kw.get("keyword", "")
                is_regex = kw.is_regex if hasattr(kw, 'is_regex') else kw.get("is_regex", False)
                if is_regex:
                    if _project_pattern_matches(project, kw_val, context or ""):
                        matched_on = "keyword"
                        matched_value = kw_val
                else:
                    if kw_val.lower() in (keyword or "").lower():
                        matched_on = "keyword"
                        matched_value = kw_val

            # Match on project domain
            if not matched_on:
                for domain in project.get("domains", []):
                    d_val = domain.domain if hasattr(domain, 'domain') else domain.get("domain", "")
                    if d_val and d_val in (url or ""):
                        matched_on = "domain"
                        matched_value = d_val

            # Match on project entity
            if not matched_on:
                for entity in project.get("entities", []):
                    e_val = entity.value if hasattr(entity, 'value') else entity.get("value", "")
                    if e_val and e_val.lower() in (context or "").lower():
                        matched_on = "entity"
                        matched_value = e_val

            if matched_on:
                storage.create_project_hit(project["id"], hit_id, matched_on, matched_value)
    except Exception as e:
        logger.warning(f"Project hit matching error: {e}")

TOR_DOWN_MESSAGE = "Tor is not reachable. Is the tor container running? (make check-tor)"
CRAWL_FAILED_MESSAGE = "The crawl stopped with an unexpected error; the details are in the server log."


async def _heartbeat(storage: Storage, session_id: int, crawler: Crawler, counts: dict) -> None:
    """Keep the session's heartbeat fresh while the crawl runs, slow pages included.

    When the session is no longer running (someone ended it as interrupted),
    the crawl stops at the next page.
    """
    while True:
        await asyncio.sleep(HEARTBEAT_SECONDS)
        try:
            if not storage.heartbeat_crawl_session(session_id, counts["pages"], counts["hits"]):
                logger.warning("Crawl session %s was ended elsewhere; stopping", session_id)
                crawler.halt()
                return
        except Exception:
            logger.exception("Crawl session %s: heartbeat not written", session_id)


async def run_scan(
    seeds: list[str],
    keyword_config: KeywordConfig,
    crawl_config: CrawlConfig,
    storage: Storage,
    alerter: Alerter,
    check_tor: bool = True,
    stop_flag=None,
    session_id: Optional[int] = None,
):
    """Crawl ``seeds`` and record pages and hits.

    ``session_id``: a session the caller has claimed with
    Storage.begin_crawl_session (the dashboard). Without it the session is
    claimed here, and CrawlAlreadyRunning is raised when a crawl is running.
    Raises TorNotReachable when the Tor check fails; the process is never exited.
    """
    tor = create_tor_client()
    crawler = Crawler(tor, crawl_config, stop_flag=stop_flag)
    scanner = Scanner(keyword_config)

    logger.info(
        f"Starting scan with {len(seeds)} seed URL(s) and {scanner.keyword_count} keyword(s)"
    )

    if check_tor:
        logger.info("Checking Tor connectivity...")
        try:
            reachable = await asyncio.wait_for(tor.check_connectivity(), TOR_CHECK_TIMEOUT)
        except asyncio.TimeoutError:
            reachable = False
        if not reachable:
            logger.error("Tor connectivity check failed. Is the Tor daemon running?")
            await tor.close()
            if session_id is not None:
                storage.update_crawl_session(session_id, 0, 0, status="failed", error=TOR_DOWN_MESSAGE)
            raise TorNotReachable(TOR_DOWN_MESSAGE)
        logger.info("Tor connectivity confirmed.")

    claimed_here = session_id is None
    if claimed_here:
        claim_local_crawl()
        try:
            session_id = storage.begin_crawl_session(seeds, crawl_owner(), STALE_SECONDS)
        except Exception:
            release_local_crawl()
            await tor.close()
            raise
        if session_id is None:
            release_local_crawl()
            await tor.close()
            raise CrawlAlreadyRunning("A crawl is already running")

    counts = {"pages": 0, "hits": 0}
    _final_status = "failed"
    _error = None
    beat = asyncio.ensure_future(_heartbeat(storage, session_id, crawler, counts))

    try:
        async for page in crawler.crawl(seeds):
            counts["pages"] += 1

            storage.save_page(
                url=page.url,
                status_code=page.status_code,
                depth=page.depth,
                session_id=session_id,
                error=page.error,
            )

            if page.error or not page.text:
                continue

            hits = scanner.scan(url=page.url, text=page.text, depth=page.depth)

            for hit in hits:
                hit_id = storage.save_hit(
                    url=hit.url,
                    keyword=hit.keyword,
                    category=hit.category,
                    context=hit.context,
                    position=hit.position,
                    depth=hit.depth,
                    session_id=session_id,
                )
                counts["hits"] += 1
                match_hit_to_projects(hit_id, hit.url, hit.keyword, hit.context, storage)
                if alerter.alert(hit):
                    storage.mark_alerted(hit_id)

            if counts["pages"] % 10 == 0:
                logger.info(f"Progress: {counts['pages']} pages crawled, {counts['hits']} hits found")

        _final_status = "stopped" if crawler.stop_requested else "completed"
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        _final_status = "stopped"
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        _error = CRAWL_FAILED_MESSAGE
        raise
    finally:
        beat.cancel()
        storage.update_crawl_session(
            session_id, counts["pages"], counts["hits"], status=_final_status, error=_error
        )
        if claimed_here:
            release_local_crawl()
        await tor.close()

    logger.info(f"Scan complete. Pages: {counts['pages']} | Hits: {counts['hits']}")
    return {"pages_crawled": counts["pages"], "hits_found": counts["hits"]}


# ── CLI ────────────────────────────────────────────────────────────────────────


@click.group()
def cli():
    """Dark Web Scanner — keyword monitoring tool for .onion sites and Telegram."""
    pass


@cli.command()
@click.option("--seeds", "-s", default="config/seeds.txt", help="Path to seed URLs file")
@click.option("--keywords", "-k", default="config/keywords.yaml", help="Path to keywords YAML file")
@click.option("--depth", "-d", default=None, type=int, help="Max crawl depth (overrides env)")
@click.option("--no-tor-check", is_flag=True, default=False, help="Skip Tor connectivity check")
def scan(seeds: str, keywords: str, depth: int, no_tor_check: bool):
    """Run a dark web crawl and keyword scan."""
    # Prefer user-edited files in /app/data over read-only config defaults
    seeds_path = Path(_resolve_data_path(seeds, "seeds.txt"))
    keywords_path = Path(_resolve_keywords_path(keywords))

    if not seeds_path.exists():
        click.echo(f"Seeds file not found: {seeds_path}", err=True)
        click.echo("Add seeds via the dashboard Seeds tab or copy config/seeds.example.txt to config/seeds.txt", err=True)
        sys.exit(1)
    if not keywords_path.exists():
        click.echo(f"Keywords file not found: {keywords_path}", err=True)
        sys.exit(1)

    seed_urls = [
        line.strip()
        for line in seeds_path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not seed_urls:
        click.echo("No seed URLs found.", err=True)
        sys.exit(1)

    keyword_config = KeywordConfig.from_yaml(str(keywords_path))
    crawl_config = CrawlConfig()
    if depth is not None:
        crawl_config.max_depth = depth

    storage = Storage()
    alerter = Alerter()

    asyncio.run(
        run_scan(
            seeds=seed_urls,
            keyword_config=keyword_config,
            crawl_config=crawl_config,
            storage=storage,
            alerter=alerter,
            check_tor=not no_tor_check,
        )
    )


def _resolve_keywords_path(provided: str) -> str:
    """Check writable data dir first, fall back to read-only config."""
    data_kw = Path("/app/data/keywords.yaml")
    if data_kw.exists():
        return str(data_kw)
    return provided


def _resolve_data_path(provided: str, filename: str) -> str:
    """Check writable data dir first, fall back to provided path."""
    data_path = Path("/app/data") / filename
    if data_path.exists():
        return str(data_path)
    return provided


@cli.command("telegram-scan")
@click.option("--keywords", "-k", default="config/keywords.yaml", help="Path to keywords YAML file")
@click.option(
    "--channels",
    "-c",
    default=None,
    help="Comma-separated channel usernames (overrides TELEGRAM_CHANNELS env var)",
)
def telegram_scan(keywords: str, channels: str):
    """Scrape Telegram channels for keyword hits."""
    from .telegram_scraper import TelegramConfig, scrape_channels

    config = TelegramConfig.from_env()
    if not config:
        click.echo(
            "ERROR: TELEGRAM_API_ID and TELEGRAM_API_HASH must be set in .env\n"
            "Get them at: https://my.telegram.org",
            err=True,
        )
        sys.exit(1)

    if channels:
        config.channels = [c.strip().lstrip("@") for c in channels.split(",") if c.strip()]

    if not config.channels:
        click.echo(
            "ERROR: No channels specified. Set TELEGRAM_CHANNELS in .env or use --channels",
            err=True,
        )
        sys.exit(1)

    keywords = _resolve_keywords_path(keywords)

    keywords_path = Path(keywords)
    if not keywords_path.exists():
        click.echo(f"Keywords file not found: {keywords_path}", err=True)
        sys.exit(1)

    keyword_config = KeywordConfig.from_yaml(str(keywords_path))
    storage = Storage()
    alerter = Alerter()
    scanner_obj = __import__(
        "darkweb_scanner.scanner", fromlist=["Scanner"]
    ).Scanner(keyword_config)

    session_id = storage.create_crawl_session(
        [f"telegram:{c}" for c in config.channels]
    )

    click.echo(f"Scanning {len(config.channels)} Telegram channel(s)...")
    result = asyncio.run(
        scrape_channels(
            config=config,
            scanner=scanner_obj,
            storage=storage,
            alerter=alerter,
            session_id=session_id,
        )
    )
    storage.update_crawl_session(
        session_id,
        result["pages_scraped"],
        result["hits_found"],
        status="completed",
    )
    click.echo(
        f"Done. Messages scanned: {result['pages_scraped']} | Hits: {result['hits_found']}"
    )


@cli.command("telegram-auth")
def telegram_auth():
    """Authenticate with Telegram (run once before telegram-scan)."""
    from .telegram_scraper import TelegramConfig, interactive_auth

    config = TelegramConfig.from_env()
    if not config:
        click.echo(
            "ERROR: TELEGRAM_API_ID and TELEGRAM_API_HASH must be set in .env\n"
            "Get them at: https://my.telegram.org",
            err=True,
        )
        sys.exit(1)
    asyncio.run(interactive_auth(config))


@cli.command("channel-monitor-auth")
def channel_monitor_auth():
    """Sign in the Telegram session of the Channel Monitor tab (interactive, run once)."""
    from .channel_monitor import interactive_auth

    api_id = os.getenv("TELEGRAM_API_ID", "").strip()
    api_hash = os.getenv("TELEGRAM_API_HASH", "").strip()
    if not api_id.isdigit() or not api_hash:
        click.echo(
            "ERROR: TELEGRAM_API_ID (a number) and TELEGRAM_API_HASH must be set in .env\n"
            "Get them at: https://my.telegram.org",
            err=True,
        )
        sys.exit(1)
    # With TELEGRAM_PHONE unset, Telethon asks for the number.
    asyncio.run(interactive_auth(int(api_id), api_hash, os.getenv("TELEGRAM_PHONE", "").strip() or None))


@cli.command()
def stats():
    """Print database statistics."""
    storage = Storage()
    s = storage.get_stats()
    click.echo(f"\n{'=' * 40}")
    click.echo("  Dark Web Scanner — Statistics")
    click.echo(f"{'=' * 40}")
    click.echo(f"  Sessions:      {s['total_sessions']}")
    click.echo(f"  Pages crawled: {s['total_pages']}")
    click.echo(f"  Keyword hits:  {s['total_hits']}")
    if s["top_keywords"]:
        click.echo("\n  Top keywords:")
        for item in s["top_keywords"]:
            click.echo(f"    {item['keyword']:<40} {item['count']} hits")
    click.echo(f"{'=' * 40}\n")


@cli.command()
@click.option("--limit", "-n", default=20, help="Number of recent hits to show")
def hits(limit: int):
    """Show recent keyword hits."""
    storage = Storage()
    records = storage.get_recent_hits(limit=limit)
    if not records:
        click.echo("No hits found yet.")
        return
    for r in records:
        click.echo(f"\n[{r.found_at}] {r.keyword!r} ({r.category})")
        click.echo(f"  URL: {r.url}")
        click.echo(f"  Context: {r.context[:200]}...")


@cli.command("check-tor")
def check_tor():
    """Verify Tor is reachable."""

    async def _check():
        tor = create_tor_client()
        ok = await tor.check_connectivity()
        await tor.close()
        return ok

    ok = asyncio.run(_check())
    if ok:
        click.echo("✅ Tor is connected and routing correctly.")
    else:
        click.echo("❌ Tor connectivity check failed.", err=True)
        sys.exit(1)


# ── Accounts (run on the server; see docs/runbook.md) ──────────────────────────
# For the cases the dashboard cannot solve by itself: the only administrator is
# locked out or has lost the authenticator. Nothing here shows or sets a password.


def _find_user(storage: Storage, username: str):
    user = storage.get_user_by_username(username)
    if user is None:
        click.echo(f"No user named {username!r}. List the accounts with: user-list", err=True)
        sys.exit(1)
    return user


@cli.command("user-list")
def user_list():
    """List accounts and the sign-in locks in force (no secrets)."""
    storage = Storage()
    click.echo(f"{'id':>4}  {'user name':<32} {'admin':<6} {'2FA':<5} {'temp. password':<15} last sign-in")
    for u in storage.list_users():
        last = u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "never"
        click.echo(
            f"{u.id:>4}  {u.username:<32} {'yes' if u.is_admin else 'no':<6} "
            f"{'on' if u.totp_enabled and u.totp_secret else 'off':<5} "
            f"{'yes' if u.must_change_password else 'no':<15} {last}"
        )
    locks = storage.throttle_locks()
    click.echo("")
    if not locks:
        click.echo("No sign-in locks in force.")
    for lock in locks:
        kind, _, value = lock["key"].partition(":")
        what = {"user": "password, user name", "ip": "address", "totp": "second factor, user id"}.get(kind, kind)
        click.echo(f"Locked for {(lock['seconds'] + 59) // 60} more min: {what} {value}")


@cli.command("user-unlock")
@click.argument("username")
@click.option("--address", default=None, help="Also lift the lock on this network address")
def user_unlock(username: str, address: str):
    """Lift the sign-in locks on USERNAME (wrong passwords, wrong codes)."""
    from .auth import account_key, ip_key, totp_key

    storage = Storage()
    user = _find_user(storage, username)
    keys = [account_key(user.username), totp_key(user.id)]
    if address:
        keys.append(ip_key(address.strip()))
    for key in keys:
        storage.throttle_clear(key)
    storage.add_auth_event("unlock", user.username, user.id, "local", "command line")
    click.echo(f"Locks lifted for {user.username}" + (f" and address {address.strip()}." if address else "."))


@cli.command("user-reset-mfa")
@click.argument("username")
@click.confirmation_option(prompt="Remove this user's second factor and end their sessions?")
def user_reset_mfa(username: str):
    """Remove USERNAME's second factor; they enrol a new one at the next sign-in."""
    from .auth import totp_key

    storage = Storage()
    user = _find_user(storage, username)
    storage.disable_totp(user.id)
    storage.bump_session_version(user.id)
    storage.throttle_clear(totp_key(user.id))
    storage.add_auth_event("mfa_reset", user.username, user.id, "local", "command line")
    click.echo(f"Second factor removed for {user.username}. They sign in with their password and enrol again.")


# ── Database schema (see docs/runbook.md, "Database schema") ───────────────────
# Upgrades need no command: the schema is brought up to date whenever the
# application or one of these commands starts.


@cli.command("db-status")
@click.option("--quiet", is_flag=True, default=False, help="Print the revision only")
def db_status(quiet: bool):
    """Show the revision of the database schema."""
    from . import migrations

    storage = Storage()
    revision = migrations.current(storage.engine)
    if quiet:
        click.echo(revision or "")
        return
    click.echo(f"Database schema revision: {revision} (newest in this release: {migrations.head()})")


@cli.command("db-downgrade")
@click.argument("revision")
@click.confirmation_option(prompt="Take the database schema back? Data in dropped tables and columns is lost.")
def db_downgrade(revision: str):
    """Take the schema back to REVISION, before running an older release.

    Stop the dashboard first: any start of this release upgrades the schema again.
    """
    from . import migrations

    storage = Storage()
    before = migrations.current(storage.engine)
    migrations.downgrade(storage.engine, revision)
    click.echo(f"Database schema taken back from revision {before} to {migrations.current(storage.engine)}.")


def main():
    cli()


if __name__ == "__main__":
    main()
