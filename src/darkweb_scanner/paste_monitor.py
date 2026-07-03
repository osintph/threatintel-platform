"""
Paste site monitor — polls public paste sites for PH-specific patterns.
Only includes sources verified to work without API keys or IP whitelisting.

Working sources:
  - rentry.co/recent  (confirmed working)
  - hastebin.com      (public recent endpoint)
  - ghostbin.co       (public pastes)
  - termbin.com       (raw pastes via scraping)

Pastebin: blocks scrapers, API requires IP whitelist — excluded.
psbdmp.ws: shutting down, all endpoints 404 — excluded.
pastes.io: /public returns 404 — excluded.
controlc.com: removed public recent page — excluded.
"""
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15
POLL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ── PH pattern definitions ─────────────────────────────────────────────────────

PH_PATTERNS = {
    "ph_mobile":      re.compile(r'(\+63|0)(9\d{2}[-\s]?\d{3}[-\s]?\d{4})', re.IGNORECASE),
    "ph_domain":      re.compile(r'\b[\w.-]+\.ph\b', re.IGNORECASE),
    "ph_gov_domain":  re.compile(r'\b[\w.-]+\.gov\.ph\b', re.IGNORECASE),
    "ph_bank":        re.compile(
        r'\b(BDO|BPI|Metrobank|UnionBank|RCBC|Landbank|LBP|PNB|'
        r'Security\s*Bank|EastWest|PSBank|Chinabank|China\s*Bank|'
        r'Allied\s*Bank|Philippine\s*National\s*Bank|'
        r'Banco\s*de\s*Oro|Bank\s*of\s*the\s*Philippine\s*Islands)\b',
        re.IGNORECASE,
    ),
    "ph_sss":         re.compile(r'\b\d{2}-\d{7}-\d\b'),
    "ph_tin":         re.compile(r'\b\d{3}-\d{3}-\d{3}(-\d{3})?\b'),
    "ph_philhealth":  re.compile(r'\b\d{2}-\d{9}-\d\b'),
    "ph_card_bin":    re.compile(
        r'\b(4142|4143|4144|4145|4766|4767|4609|4580|'
        r'5299|5457|5180|5429|5392|5438)\d{10,12}\b'
    ),
    "ph_postal":      re.compile(r'\bPhilippines?\b|\bPilipinas?\b', re.IGNORECASE),
}

CONTEXT_WINDOW = 120  # chars around match to capture as context


@dataclass
class PasteSource:
    name: str
    archive_url: str
    base_url: str
    poll_interval: int  # seconds
    last_polled: float = field(default=0.0)
    enabled: bool = field(default=True)

    def is_due(self) -> bool:
        return self.enabled and (time.time() - self.last_polled >= self.poll_interval)

    def mark_polled(self):
        self.last_polled = time.time()


SOURCES = [
    PasteSource("rentry",    "https://rentry.co/recent",        "https://rentry.co",       300),
    # hastebin: requires auth (401)
    # ghostbin: domain dead (DNS failure)
    # pasty: requires auth (401)
]


def _safe_get(url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    try:
        r = requests.get(url, headers=POLL_HEADERS, timeout=timeout)
        r.raise_for_status()
        return r
    except Exception as e:
        logger.warning(f"Paste fetch failed {url}: {e}")
        return None


def _extract_context(text: str, match) -> str:
    start = max(0, match.start() - CONTEXT_WINDOW)
    end = min(len(text), match.end() + CONTEXT_WINDOW)
    return text[start:end].replace('\n', ' ').strip()


def scan_paste_content(text: str, url: str, paste_id: str,
                       source_name: str, storage) -> int:
    """Scan paste text against PH patterns. Returns number of hits saved."""
    hits = 0
    seen_patterns = set()

    for pattern_name, regex in PH_PATTERNS.items():
        for match in regex.finditer(text):
            key = (pattern_name, match.group(0)[:50])
            if key in seen_patterns:
                continue
            seen_patterns.add(key)

            context = _extract_context(text, match)
            storage.save_paste_hit(
                paste_id=paste_id,
                url=url,
                source=source_name,
                matched_pattern=pattern_name,
                matched_value=match.group(0)[:200],
                context=context,
            )
            hits += 1

    return hits


# ── Source-specific scrapers ───────────────────────────────────────────────────

def _get_rentry_urls() -> list[tuple[str, str]]:
    r = _safe_get("https://rentry.co/recent")
    if not r:
        return []
    soup = BeautifulSoup(r.text, "lxml")
    results = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if re.match(r"^/[a-zA-Z0-9_-]{4,20}$", href) and href not in (
            '/recent', '/new', '/login', '/register', '/raw'
        ):
            paste_id = href.strip("/")
            results.append((paste_id, f"https://rentry.co{href}/raw"))
    return results[:50]


def _get_hastebin_urls() -> list[tuple[str, str]]:
    # hastebin doesn't have a public recent page but we can try the documents endpoint
    r = _safe_get("https://hastebin.com/recent")
    if not r:
        return []
    soup = BeautifulSoup(r.text, "lxml")
    results = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if re.match(r"^/[a-z]{10}$", href):
            paste_id = href.strip("/")
            results.append((paste_id, f"https://hastebin.com/raw/{paste_id}"))
    return results[:30]


def _get_ghostbin_urls() -> list[tuple[str, str]]:
    r = _safe_get("https://ghostbin.com/recent")
    if not r:
        return []
    soup = BeautifulSoup(r.text, "lxml")
    results = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if re.match(r"^/paste/[a-z0-9]+$", href):
            paste_id = href.split("/")[-1]
            results.append((paste_id, f"https://ghostbin.com{href}/raw"))
    return results[:30]


def _get_pasty_urls() -> list[tuple[str, str]]:
    # pasty.lus.pm has a simple API
    r = _safe_get("https://pasty.lus.pm/api/v2/pastes?limit=50")
    if not r:
        return []
    try:
        items = r.json()
        if not isinstance(items, list):
            items = items.get("pastes", [])
        results = []
        for item in items:
            pid = item.get("id") or item.get("key", "")
            if pid:
                results.append((pid, f"https://pasty.lus.pm/{pid}/raw"))
        return results[:50]
    except Exception:
        return []


SOURCE_SCRAPERS = {
    "rentry":   _get_rentry_urls,
    "hastebin": _get_hastebin_urls,
    "ghostbin": _get_ghostbin_urls,
    "pasty":    _get_pasty_urls,
}


def probe_sources() -> dict:
    """Test which sources are reachable. Returns {source_name: bool}."""
    results = {}
    for source in SOURCES:
        scraper = SOURCE_SCRAPERS.get(source.name)
        if not scraper:
            results[source.name] = False
            continue
        try:
            urls = scraper()
            results[source.name] = len(urls) > 0
            logger.info(f"probe {source.name}: {len(urls)} URLs found")
        except Exception as e:
            results[source.name] = False
            logger.warning(f"probe {source.name} failed: {e}")
    return results


# ── Main monitor loop ──────────────────────────────────────────────────────────

def run_paste_monitor(storage, single_run: bool = False) -> dict:
    """
    Poll all paste sources and scan new pastes for PH patterns.
    If single_run=True, poll all sources once and return.
    Returns summary dict.
    """
    total_scanned = 0
    total_hits = 0
    total_new = 0

    for source in SOURCES:
        if not single_run and not source.is_due():
            continue

        scraper = SOURCE_SCRAPERS.get(source.name)
        if not scraper:
            continue

        logger.info(f"Polling {source.name}...")
        try:
            paste_urls = scraper()
        except Exception as e:
            logger.warning(f"Scraper error {source.name}: {e}")
            source.mark_polled()
            continue

        logger.info(f"{source.name}: found {len(paste_urls)} pastes")

        for paste_id, raw_url in paste_urls:
            if storage.is_paste_seen(source.name, paste_id):
                continue

            total_new += 1
            r = _safe_get(raw_url)
            if not r:
                storage.mark_paste_seen(source.name, paste_id, raw_url, had_hits=False)
                continue

            text = r.text
            if len(text) > 500_000:
                storage.mark_paste_seen(source.name, paste_id, raw_url, had_hits=False)
                continue

            hits = scan_paste_content(text, raw_url, paste_id, source.name, storage)
            storage.mark_paste_seen(source.name, paste_id, raw_url, had_hits=hits > 0)
            total_scanned += 1
            total_hits += hits

            if hits > 0:
                logger.info(f"[{source.name}] {paste_id} — {hits} PH pattern hits")

            time.sleep(0.3)

        source.mark_polled()

    return {
        "scanned": total_scanned,
        "new_pastes": total_new,
        "hits": total_hits,
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }

