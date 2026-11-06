"""
Async BFS crawler for .onion sites.
Follows links up to a configurable depth, respects rate limits,
and yields page content for downstream processing.
"""

import asyncio
import logging
import os
import pathlib
import random
import re
from collections import deque
from dataclasses import dataclass
from typing import AsyncIterator, Optional, Set
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from .tor_client import TorClient

logger = logging.getLogger(__name__)

ONION_PATTERN = re.compile(r"https?://[a-z2-7]{16,56}\.onion", re.IGNORECASE)


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


class Crawler:
    def __init__(self, tor_client: TorClient, config: Optional[CrawlConfig] = None):
        self.tor = tor_client
        self.config = config or CrawlConfig()
        self._visited: Set[str] = set()
        self._domain_counts: dict[str, int] = {}
        self._pages_crawled: int = 0
        self._semaphore: Optional[asyncio.Semaphore] = None

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
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme in ("http", "https") and parsed.netloc.endswith(".onion"):
                links.append(self._normalize_url(absolute))
        return links

    def _get_domain(self, url: str) -> str:
        return urlparse(url).netloc

    def _should_crawl(self, url: str, origin_domain: str) -> bool:
        normalized = self._normalize_url(url)
        if normalized in self._visited:
            return False
        domain = self._get_domain(url)
        if not domain.endswith(".onion"):
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
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if not any(ct in content_type for ct in self.config.allowed_content_types):
                    return CrawlResult(
                        url=url,
                        status_code=resp.status,
                        html="",
                        text="",
                        links=[],
                        depth=0,
                        error=f"Skipped content-type: {content_type}",
                    )
                html = await resp.text(errors="replace")
                soup = BeautifulSoup(html, "lxml")
                # remove scripts and styles before extracting text
                for tag in soup(["script", "style", "noscript"]):
                    tag.decompose()
                text = soup.get_text(separator=" ", strip=True)
                links = self._extract_links(html, url)
                return CrawlResult(
                    url=url, status_code=resp.status, html=html, text=text, links=links, depth=0
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
            stop_flag = pathlib.Path(os.environ.get("DATA_DIR", "/app/data")) / "crawl.stop"
            if stop_flag.exists():
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
            normalized = self._normalize_url(url)
            domain = self._get_domain(normalized)
            queue.append((normalized, 0, domain))
            self._visited.add(normalized)

        stop_flag = pathlib.Path(os.environ.get("DATA_DIR", "/app/data")) / "crawl.stop"

        while queue:
            # Check for stop signal from dashboard
            if stop_flag.exists():
                logger.info("Stop flag detected — halting crawl gracefully.")
                try:
                    stop_flag.unlink()
                except Exception:
                    pass
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
