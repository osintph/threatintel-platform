"""
Main entry point — orchestrates crawling, scanning, storage, and alerting.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

import click

from .alerting import Alerter
from .crawler import CrawlConfig, Crawler
from .scanner import KeywordConfig, Scanner
from .storage import Storage
from .tor_client import create_tor_client

# ── Logging setup ──────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/app/data/scanner.log")
        if os.path.exists("/app/data")
        else logging.NullHandler(),
    ],
)
logger = logging.getLogger(__name__)


# ── Core orchestration ─────────────────────────────────────────────────────────




def match_hit_to_projects(hit_id: int, url: str, keyword: str, context: str, storage):
    """Match a newly saved hit against all active projects."""
    import re as _re
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
                    try:
                        if _re.search(kw_val, (context or ""), _re.IGNORECASE):
                            matched_on = "keyword"
                            matched_value = kw_val
                    except Exception:
                        pass
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

async def run_scan(
    seeds: list[str],
    keyword_config: KeywordConfig,
    crawl_config: CrawlConfig,
    storage: Storage,
    alerter: Alerter,
    check_tor: bool = True,
    stop_flag=None,
):
    tor = create_tor_client()
    crawler = Crawler(tor, crawl_config)
    scanner = Scanner(keyword_config)

    logger.info(
        f"Starting scan with {len(seeds)} seed URL(s) and {scanner.keyword_count} keyword(s)"
    )

    if check_tor:
        logger.info("Checking Tor connectivity...")
        if not await tor.check_connectivity():
            logger.error("Tor connectivity check failed. Is the Tor daemon running?")
            sys.exit(1)
        logger.info("Tor connectivity confirmed.")

    session_id = storage.create_crawl_session(seeds)
    pages_crawled = 0
    hits_found = 0
    _final_status = "failed"

    try:
        async for page in crawler.crawl(seeds):
            pages_crawled += 1

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
                hits_found += 1
                match_hit_to_projects(hit_id, hit.url, hit.keyword, hit.context, storage)
                if alerter.alert(hit):
                    storage.mark_alerted(hit_id)

            if pages_crawled % 10 == 0:
                logger.info(f"Progress: {pages_crawled} pages crawled, {hits_found} hits found")

        _final_status = "completed"
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        raise
    finally:
        storage.update_crawl_session(session_id, pages_crawled, hits_found, status=_final_status)
        await tor.close()

    logger.info(f"Scan complete. Pages: {pages_crawled} | Hits: {hits_found}")
    return {"pages_crawled": pages_crawled, "hits_found": hits_found}


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


def main():
    cli()


if __name__ == "__main__":
    main()
