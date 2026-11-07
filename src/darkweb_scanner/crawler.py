"""
Async BFS crawler for .onion sites.
Follows links up to a configurable depth, respects rate limits,
and yields page content for downstream processing.

Only .onion addresses are fetched: seeds, links and redirect targets that are
anything else are left alone. Each body is read up to a byte cap.
"""

import asyncio
import logging
import os
import pathlib
import random
import re
import socket
import threading
from collections import deque
from dataclasses import dataclass
from typing import AsyncIterator, Optional, Set
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from .tor_client import (
    MAX_PAGE_BYTES,
    RedirectRefused,
    TorClient,
    _env_number,
    fetch_page,
    is_onion_url,
)

logger = logging.getLogger(__name__)

ONION_PATTERN = re.compile(r"https?://[a-z2-7]{16,56}\.onion", re.IGNORECASE)

# ── Which process runs a crawl ─────────────────────────────────────────────────
# The process that runs a crawl writes its name and a heartbeat into the
# session row (see Storage.heartbeat_crawl_session). A running session whose
# heartbeat is older than STALE_SECONDS belongs to a process that is gone.

HEARTBEAT_SECONDS = _env_number("CRAWL_HEARTBEAT_SECONDS", 15, 0.05)
STALE_SECONDS = max(_env_number("CRAWL_STALE_SECONDS", 120, 0.2), 3 * HEARTBEAT_SECONDS)

_local_lock = threading.Lock()
_local_crawls = 0  # crawls this process is running (or about to start)


class CrawlAlreadyRunning(RuntimeError):
    """A crawl is running, in this process or another one."""


def crawl_owner() -> str:
    """This process as written to crawl_sessions.owner (host:pid)."""
    return f"{socket.gethostname()}:{os.getpid()}"[:100]


def claim_local_crawl() -> None:
    """Note that this process runs a crawl. Call before the session row exists."""
    global _local_crawls
    with _local_lock:
        _local_crawls += 1


def release_local_crawl() -> None:
    global _local_crawls
    with _local_lock:
        _local_crawls = max(0, _local_crawls - 1)


def local_crawl_running() -> bool:
    with _local_lock:
        return _local_crawls > 0


def default_stop_flag() -> pathlib.Path:
    """The file whose presence asks the running crawl to stop (written by the dashboard)."""
    return pathlib.Path(os.environ.get("DATA_DIR", "/app/data")) / "crawl.stop"


@dataclass
class CrawlResult:
    url: str
    status_code: int
    html: str
    text: str
    links: list[str]
    depth: int
    error: Optional[str] = None


@dataclass
class CrawlConfig:
    max_depth: int = int(os.getenv("MAX_DEPTH", "3"))
    max_concurrent: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "10"))
    delay_min: float = float(os.getenv("CRAWL_DELAY_MIN", "2"))
    delay_max: float = float(os.getenv("CRAWL_DELAY_MAX", "8"))
    rotate_circuit_every: int = int(os.getenv("ROTATE_CIRCUIT_EVERY", "50"))
    max_pages_per_domain: int = int(os.getenv("MAX_PAGES_PER_DOMAIN", "100"))
    stay_on_domain: bool = os.getenv("STAY_ON_DOMAIN", "false").lower() == "true"
    allowed_content_types: tuple = ("text/html",)
    max_page_bytes: int = MAX_PAGE_BYTES


class Crawler:
    def __init__(
        self,
        tor_client: TorClient,
        config: Optional[CrawlConfig] = None,
        stop_flag: Optional[pathlib.Path] = None,
    ):
        self.tor = tor_client
        self.config = config or CrawlConfig()
        self.stop_flag = pathlib.Path(stop_flag) if stop_flag else default_stop_flag()
        # True once the stop flag was seen. The flag is left in place: whoever
        # runs the crawl removes it after the final status is written.
        self.stop_requested = False
        self._halt = False
        self._visited: Set[str] = set()
        self._domain_counts: dict[str, int] = {}
        self._pages_crawled: int = 0
        self._semaphore: Optional[asyncio.Semaphore] = None

    def halt(self) -> None:
        """End the crawl at the next page boundary (not a stop request by a user)."""
        self._halt = True

    def _stop_now(self) -> bool:
        if self._halt:
            return True
        try:
            if self.stop_flag.exists():
                self.stop_requested = True
                return True
        except OSError:
            pass
        return False

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        # strip fragments and normalize
        return parsed._replace(fragment="").geturl().rstrip("/")

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("#", "mailto:", "javascript:")):
                continue
            try:
                absolute = urljoin(base_url, href)
            except ValueError:
                continue
            # Clearnet links are never followed: only .onion addresses are fetched.
            if is_onion_url(absolute):
                links.append(self._normalize_url(absolute))
        return links

    def _get_domain(self, url: str) -> str:
        return urlparse(url).netloc

    def _should_crawl(self, url: str, origin_domain: str) -> bool:
        normalized = self._normalize_url(url)
        if normalized in self._visited:
            return False
        domain = self._get_domain(url)
        if not is_onion_url(url):
            return False
        if self.config.stay_on_domain and domain != origin_domain:
            return False
        count = self._domain_counts.get(domain, 0)
        if count >= self.config.max_pages_per_domain:
            logger.debug(f"Domain page limit reached for {domain}")
            return False
        return True

    async def _fetch(self, url: str, session: aiohttp.ClientSession) -> CrawlResult:
        try:
            page = await fetch_page(
                session,
                url,
                max_bytes=self.config.max_page_bytes,
                content_types=self.config.allowed_content_types,
            )
            if page.skipped:
                return CrawlResult(
                    url=url,
                    status_code=page.status,
                    html="",
                    text="",
                    links=[],
                    depth=0,
                    error=f"Skipped content-type: {page.content_type}",
                )
            html = page.text
            soup = BeautifulSoup(html, "lxml")
            # remove scripts and styles before extracting text
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            text = soup.get_text(separator=" ", strip=True)
            links = self._extract_links(html, page.url)
            return CrawlResult(
                url=url, status_code=page.status, html=html, text=text, links=links, depth=0
            )
        except RedirectRefused as e:
            return CrawlResult(
                url=url, status_code=0, html="", text="", links=[], depth=0, error=str(e)
            )
        except asyncio.TimeoutError:
            return CrawlResult(
                url=url, status_code=0, html="", text="", links=[], depth=0, error="Timeout"
            )
        except Exception as e:
            return CrawlResult(
                url=url, status_code=0, html="", text="", links=[], depth=0, error=str(e)
            )

    async def _crawl_url(self, url: str, depth: int) -> CrawlResult:
        async with self._semaphore:
            if self._stop_now():
                return CrawlResult(url=url, status_code=0, html="", text="", links=[], depth=depth, error="stopped")
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            await asyncio.sleep(delay)
            logger.info(f"Fetching [{depth}] {url}")
            session = await self.tor.get_session()
            result = await self._fetch(url, session)
            result.depth = depth
            self._pages_crawled += 1

            # rotate circuit periodically
            if self._pages_crawled % self.config.rotate_circuit_every == 0:
                logger.info("Rotating Tor circuit...")
                await self.tor.rotate_circuit_async()

            return result

    async def crawl(self, seed_urls: list[str]) -> AsyncIterator[CrawlResult]:
        """BFS crawl from seed URLs, yielding CrawlResult for each page."""
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        queue: deque[tuple[str, int, str]] = deque()  # (url, depth, origin_domain)

        for url in seed_urls:
            if not is_onion_url(url):
                logger.warning(f"Seed is not an .onion address; skipped: {url}")
                continue
            normalized = self._normalize_url(url)
            domain = self._get_domain(normalized)
            queue.append((normalized, 0, domain))
            self._visited.add(normalized)

        while queue:
            # Check for stop signal from dashboard
            if self._stop_now():
                if self.stop_requested:
                    logger.info("Stop flag detected — halting crawl gracefully.")
                break

            batch = []
            while queue and len(batch) < self.config.max_concurrent:
                batch.append(queue.popleft())

            tasks = [self._crawl_url(url, depth) for url, depth, _ in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                url, depth, origin_domain = batch[i]

                if isinstance(result, Exception):
                    logger.error(f"Unhandled exception crawling {url}: {result}")
                    continue

                if result.error == "stopped":
                    # Not fetched: the stop came first. Nothing to record.
                    continue

                domain = self._get_domain(url)
                self._domain_counts[domain] = self._domain_counts.get(domain, 0) + 1

                yield result

                # enqueue discovered links
                if depth < self.config.max_depth and not result.error:
                    for link in result.links:
                        if self._should_crawl(link, origin_domain):
                            self._visited.add(link)
                            queue.append((link, depth + 1, origin_domain))

        logger.info(f"Crawl complete. Total pages crawled: {self._pages_crawled}")

    def reset(self):
        self._visited.clear()
        self._domain_counts.clear()
        self._pages_crawled = 0
