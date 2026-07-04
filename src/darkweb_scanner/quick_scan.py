"""
Quick Scan — ad-hoc target investigation, independent of the project/IOC pipeline.

This module holds:
  1. Target auto-detection and normalization (pure functions).
  2. "High signal" classification and context-window extraction (pure functions).
  3. The async orchestrator ``run_quick_scan`` (added in a later change).

Detection and normalization are deliberately pure and side-effect free so they can
be unit-tested exhaustively without any network or database.
"""

import asyncio
import json
import logging
import os
import random
import re
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Target types
TYPE_EMAIL = "email"
TYPE_DOMAIN = "domain"
TYPE_URL = "url"
TYPE_COMPANY = "company_name"
VALID_TARGET_TYPES = (TYPE_EMAIL, TYPE_DOMAIN, TYPE_URL, TYPE_COMPANY)

# Keywords that, if present in a match's context window, flag it as high signal.
HIGH_SIGNAL_KEYWORDS = (
    "leaked", "leak", "dump", "combo", "credentials", "database",
    "breach", "hacked", "for sale", "selling", "buy",
)

# Context window: characters kept on each side of a match.
CONTEXT_SIDE = 100

# Crawl behavior caps (module-level so tests can monkeypatch them).
MAX_DEPTH = 2                 # hops followed from a source's initial fetch
MAX_URLS_PER_SCAN = 100       # hard cap on URLs attempted per scan
PER_SOURCE_TIMEOUT = 30       # seconds per individual fetch
TOTAL_TIMEOUT = 600           # 10-minute hard cap on the whole scan
MAX_CONCURRENT = int(os.getenv("QUICK_SCAN_MAX_CONCURRENT", "4"))

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# label.tld, one or more labels, ascii TLD >= 2 chars. No scheme, no path.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)


def detect_target_type(raw: str) -> str:
    """Auto-detect the target type from the raw input string.

    Order (per spec):
      1. contains '@' and matches an email regex          -> email
      2. starts with http:// or https://                  -> url
      3. matches a domain (label.tld) regex               -> domain
      4. otherwise                                         -> company_name
    """
    value = (raw or "").strip()
    if "@" in value and _EMAIL_RE.match(value):
        return TYPE_EMAIL
    lowered = value.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return TYPE_URL
    if _DOMAIN_RE.match(value):
        return TYPE_DOMAIN
    return TYPE_COMPANY


def _dedupe(items) -> list:
    """Order-preserving de-duplication, dropping empties."""
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _apex_of(hostname: str) -> str:
    """Naive apex: the last two dot-labels. Does not handle multi-part TLDs
    (e.g. co.uk); acceptable for this iteration's variant expansion."""
    labels = hostname.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname


def normalize_url(raw: str) -> str:
    """Normalize a URL to 'hostname[/path]', dropping scheme, query and fragment."""
    parsed = urlparse(raw.strip())
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if path == "/":
        path = ""
    return f"{host}{path}"


def normalize_variants(target_value: str, target_type: str) -> list:
    """Return the ordered, de-duplicated list of strings to actually search for."""
    value = (target_value or "").strip()

    if target_type == TYPE_EMAIL:
        local, _, domain = value.partition("@")
        return _dedupe([value, local, domain])

    if target_type == TYPE_URL:
        normalized = normalize_url(value)
        host = normalized.split("/", 1)[0]
        return _dedupe([normalized, host])

    if target_type == TYPE_DOMAIN:
        host = value.lower()
        variants = [host]
        if not host.startswith("www."):
            variants.append("www." + host)
        # If this is a subdomain, also search the apex.
        apex = _apex_of(host)
        if apex != host:
            variants.append(apex)
        return _dedupe(variants)

    # company_name: exact string only, no fuzzy expansion at this stage.
    return _dedupe([value])


def is_high_signal(context: str) -> bool:
    """True if the context window contains any high-signal keyword (case-insensitive)."""
    if not context:
        return False
    lowered = context.lower()
    return any(keyword in lowered for keyword in HIGH_SIGNAL_KEYWORDS)


def extract_context(text: str, start: int, end: int) -> str:
    """Extract the 200-char window centered on a match: 100 before + match + 100 after."""
    lo = max(0, start - CONTEXT_SIDE)
    hi = min(len(text), end + CONTEXT_SIDE)
    return text[lo:hi]


def find_matches(text: str, variants: list) -> list:
    """Find the first occurrence of each variant in ``text`` (case-insensitive).

    Returns a list of dicts: {variant, context, high_signal}. One entry per variant
    that appears at least once, so a single page produces at most len(variants)
    findings regardless of repetition.

    TODO: LLM relevance scoring would plug in here — re-rank / filter these matches
    with a model call before they become findings.
    """
    if not text:
        return []
    haystack = text.lower()
    results = []
    for variant in variants:
        if not variant:
            continue
        idx = haystack.find(variant.lower())
        if idx == -1:
            continue
        context = extract_context(text, idx, idx + len(variant))
        results.append(
            {
                "variant": variant,
                "context": context,
                "high_signal": is_high_signal(context),
            }
        )
    return results


# ── Orchestration ────────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_cancelled(storage, session_id: int) -> bool:
    """Re-read the session and report whether it has been cancelled."""
    session = storage.get_quick_scan_session(session_id)
    return session is not None and session.status == "cancelled"


def _is_onion(url: str) -> bool:
    return (urlparse(url).hostname or "").endswith(".onion")


def _normalize_url(url: str) -> str:
    return urlparse(url)._replace(fragment="").geturl().rstrip("/")


def _rate_limit_delay() -> float:
    """Reuse the crawler's random-delay rate-limit approach.

    Reads the crawler's CRAWL_DELAY_* knobs so behavior matches the main crawler,
    with QUICK_SCAN_DELAY_* overrides (tests set these to 0 for speed).
    """
    lo = float(os.getenv("QUICK_SCAN_DELAY_MIN", os.getenv("CRAWL_DELAY_MIN", "2")))
    hi = float(os.getenv("QUICK_SCAN_DELAY_MAX", os.getenv("CRAWL_DELAY_MAX", "8")))
    if hi < lo:
        hi = lo
    return random.uniform(lo, hi)


def _extract_page_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return soup.get_text(separator=" ", strip=True)


def _extract_links(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html, "lxml")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "mailto:", "javascript:")):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme in ("http", "https"):
            links.append(_normalize_url(absolute))
    return links


async def _fetch_onion(url: str, tor_client) -> tuple:
    session = await tor_client.get_session()
    timeout = aiohttp.ClientTimeout(total=PER_SOURCE_TIMEOUT)
    async with session.get(url, ssl=False, allow_redirects=True, timeout=timeout) as resp:
        html = await resp.text(errors="replace")
        return resp.status, html


async def _fetch_clearnet(url: str) -> tuple:
    """Fetch a clearnet URL through safe_fetch (HTTPS-only, allowlisted, IP-blocked).

    Imported lazily and run in a thread since safe_fetch is synchronous.
    """
    from .dashboard.http_client import safe_fetch

    def _do():
        result = safe_fetch(url, timeout=PER_SOURCE_TIMEOUT, allow_redirects=True)
        body = result.get("body") or b""
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        return result.get("status", 0), body

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do)


async def _fetch(url: str, tor_client) -> tuple:
    """Return (status_code, html). Onion via Tor, clearnet via safe_fetch."""
    if _is_onion(url):
        return await _fetch_onion(url, tor_client)
    return await _fetch_clearnet(url)


async def run_quick_scan(session_id: int, storage, tor_client) -> None:
    """Run a quick scan end to end for a persisted session.

    Loads the session, marks it running, queries each configured source with the
    target value, fetches result pages (and links up to MAX_DEPTH), records findings
    whenever a normalized variant appears in page text, and finalizes the session.

    Per-URL errors are logged and skipped. A total-time overrun finalizes the session
    as ``completed`` with a warning in error_message. Only failures that prevent the
    scan from running at all mark it ``failed``. A cancel (status flipped to
    ``cancelled`` by the cancel endpoint) is honored at every source and fetch
    boundary: the scan stops early, syncs counters, and leaves status untouched.
    """
    from .quick_scan_sources import resolve_sources

    session = storage.get_quick_scan_session(session_id)
    if session is None:
        logger.warning("Quick scan session %s not found; aborting", session_id)
        return

    target_value = session.target_value
    variants = json.loads(session.normalized_variants or "[]")
    source_names = json.loads(session.sources_used or "[]")
    sources = resolve_sources(source_names)

    if session.status == "cancelled":
        logger.info("Quick scan %s: cancellation detected before start; aborting", session_id)
        return

    storage.update_quick_scan_session(session_id, status="running", started_at=_now())

    deadline = time.monotonic() + TOTAL_TIMEOUT
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    visited: set = set()
    counters = {"urls_visited": 0, "findings": 0}
    cancel_state = {"cancelled": False}
    timed_out = False

    def _cancel_requested() -> bool:
        """Check (and cache) whether the session has been cancelled."""
        if not cancel_state["cancelled"] and _is_cancelled(storage, session_id):
            cancel_state["cancelled"] = True
            logger.info("Quick scan %s: cancellation detected", session_id)
        return cancel_state["cancelled"]

    async def _process(url: str, depth: int, source_name: str) -> list:
        """Fetch one URL, record findings, return discovered links."""
        async with semaphore:
            if time.monotonic() > deadline:
                return []
            if _cancel_requested():
                return []
            await asyncio.sleep(_rate_limit_delay())
            logger.info(
                "Quick scan %s: fetch start %s (source %s, depth %d)",
                session_id, url, source_name, depth,
            )
            try:
                status, html = await asyncio.wait_for(
                    _fetch(url, tor_client), timeout=PER_SOURCE_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.info("Quick scan %s: fetch timed out for %s", session_id, url)
                return []
            except Exception as exc:  # noqa: BLE001 — per-URL errors must not abort the scan
                logger.info("Quick scan %s: fetch failed for %s: %s", session_id, url, exc)
                return []
            counters["urls_visited"] += 1
            logger.info("Quick scan %s: fetch complete %s (HTTP %s)", session_id, url, status)
            text = _extract_page_text(html)
            for match in find_matches(text, variants):
                storage.add_quick_scan_finding(
                    session_id=session_id,
                    source_name=source_name,
                    url=url,
                    matched_variant=match["variant"],
                    context=match["context"],
                    high_signal=match["high_signal"],
                )
                counters["findings"] += 1
                logger.info(
                    "Quick scan %s: finding created for variant %r at %s (high_signal=%s)",
                    session_id, match["variant"], url, match["high_signal"],
                )
            return _extract_links(html, url)

    # Seed the frontier with each enabled source's query URLs (depth 0).
    queue: list = []
    for source in sources:
        if _cancel_requested():
            break
        logger.info("Quick scan %s: source query start for %s", session_id, source.name)
        queued = 0
        for url in source.build_urls(target_value):
            norm = _normalize_url(url)
            if norm in visited:
                continue
            if len(visited) >= MAX_URLS_PER_SCAN:
                break
            visited.add(norm)
            queue.append((url, 0, source.name))
            queued += 1
        logger.info(
            "Quick scan %s: source query complete for %s (%d URLs queued)",
            session_id, source.name, queued,
        )

    try:
        while queue:
            if _cancel_requested():
                break
            if time.monotonic() > deadline:
                timed_out = True
                break
            batch = queue[:MAX_CONCURRENT]
            queue = queue[MAX_CONCURRENT:]
            results = await asyncio.gather(
                *[_process(url, depth, name) for url, depth, name in batch],
                return_exceptions=True,
            )
            for (url, depth, name), result in zip(batch, results):
                if isinstance(result, Exception):
                    logger.warning("Quick scan task error for %s: %s", url, result)
                    continue
                if depth >= MAX_DEPTH:
                    continue
                for link in result:
                    norm = _normalize_url(link)
                    if norm in visited:
                        continue
                    if len(visited) >= MAX_URLS_PER_SCAN:
                        break
                    visited.add(norm)
                    queue.append((link, depth + 1, name))
    except Exception as exc:  # noqa: BLE001 — finalize as failed on unexpected error
        logger.exception("Quick scan %s failed", session_id)
        storage.update_quick_scan_session(
            session_id,
            status="failed",
            completed_at=_now(),
            urls_visited=counters["urls_visited"],
            findings_count=counters["findings"],
            error_message=f"Scan failed: {type(exc).__name__}",
        )
        return

    if _cancel_requested():
        # The cancel endpoint owns status and completed_at; only sync the counters.
        storage.update_quick_scan_session(
            session_id,
            urls_visited=counters["urls_visited"],
            findings_count=counters["findings"],
        )
        logger.info(
            "Quick scan %s cancelled after %d URLs, %d findings",
            session_id,
            counters["urls_visited"],
            counters["findings"],
        )
        return

    warning = None
    if timed_out:
        warning = (
            f"Scan reached the {TOTAL_TIMEOUT}s total time cap before all sources "
            "were exhausted; results may be partial."
        )
    storage.update_quick_scan_session(
        session_id,
        status="completed",
        completed_at=_now(),
        urls_visited=counters["urls_visited"],
        findings_count=counters["findings"],
        error_message=warning,
    )
    logger.info(
        "Quick scan %s complete: %d URLs, %d findings%s",
        session_id,
        counters["urls_visited"],
        counters["findings"],
        " (timed out)" if timed_out else "",
    )
