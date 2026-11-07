"""
Investigations module — ad hoc targeted lookups.
Checks email addresses against HIBP, searches existing dark web hits,
and stores findings as named investigations.

HIBP wants its requests spaced out. The spacing is kept for the whole process
(HIBP_WINDOW) and is waited out only on a background thread: an investigation
that needs HIBP is started with jobs.start_background(), never run inside a
request. needs_hibp() tells the caller which kind it has.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

from .dashboard import jobs
from .dashboard.http_client import SafeFetchError, safe_fetch

logger = logging.getLogger(__name__)

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
# HIBP rate limit: 1 req/1.5s, for every investigation of this process together.
HIBP_WINDOW = jobs.RateWindow(1, per=1.5)


@dataclass
class BreachResult:
    email: str
    breach_name: str
    breach_date: str
    description: str
    data_classes: list[str]
    is_verified: bool
    is_sensitive: bool


@dataclass
class InvestigationResult:
    target: str
    target_type: str  # email | name | keyword
    breaches: list[BreachResult] = field(default_factory=list)
    darkweb_hits: list[dict] = field(default_factory=list)
    error: Optional[str] = None


class HIBPError(ValueError):
    """A failed HIBP check. ``message`` is written for the user and stored with the target."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def check_hibp(email: str, api_key: str) -> list[BreachResult]:
    """Check a single email against HIBP breach database.

    Goes through safe_fetch(): the key header is sent to haveibeenpwned.com
    and a redirect is not followed. Raises HIBPError.
    """
    if not api_key:
        raise HIBPError("HIBP_API_KEY not configured")

    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "DarkWebScanner-ThreatIntel/1.0",
    }

    url = f"{HIBP_API_BASE}/breachedaccount/{quote(email, safe='')}?truncateResponse=false"

    try:
        result = safe_fetch(url, headers=headers, timeout=10, max_bytes=8 * 1024 * 1024)
    except SafeFetchError as e:
        logger.warning("HIBP request failed: %s", e)
        raise HIBPError("Network error contacting HIBP") from None

    status = result["status"]
    if status == 404:
        return []  # No breaches found — good news
    if status == 401:
        raise HIBPError("Invalid HIBP API key")
    if status == 429:
        raise HIBPError("HIBP rate limit hit — wait 1 minute and retry")
    if status != 200:
        raise HIBPError(f"HIBP API error: HTTP {status}")

    try:
        data = json.loads(result["body"])
    except ValueError:
        raise HIBPError("HIBP sent an answer that could not be read") from None
    results = []
    for b in data:
        results.append(BreachResult(
            email=email,
            breach_name=b.get("Name", "Unknown"),
            breach_date=b.get("BreachDate", "Unknown"),
            description=b.get("Description", ""),
            data_classes=b.get("DataClasses", []),
            is_verified=b.get("IsVerified", False),
            is_sensitive=b.get("IsSensitive", False),
        ))
    return results


def needs_hibp(targets: list[dict], api_key: str = "") -> bool:
    """True when running these targets makes HIBP requests, which have to be spaced out."""
    return bool(api_key or HIBP_API_KEY) and any(t.get("type") == "email" for t in targets)


def run_investigation(
    name: str,
    targets: list[dict],  # [{"value": "...", "type": "email|name|keyword"}]
    storage,
    api_key: str = "",
) -> int:
    """
    Run a full investigation:
    1. For each email target: check HIBP
    2. For all targets: search existing dark web hits
    3. Save everything to DB, return investigation_id

    With needs_hibp() this waits between HIBP requests: call it from a
    background thread.
    """
    inv_id = storage.create_investigation(name=name, targets=targets)
    run_investigation_targets(inv_id, targets, storage, api_key)
    return inv_id


def run_investigation_targets(inv_id: int, targets: list[dict], storage, api_key: str = "") -> None:
    """Steps 1 to 3 of run_investigation() for an investigation that already has its row."""
    key = api_key or HIBP_API_KEY

    for target in targets:
        value = target["value"].strip()
        ttype = target["type"]
        breaches = []
        error = None

        # ── HIBP breach check ──
        if ttype == "email" and key:
            try:
                HIBP_WINDOW.wait_take()  # refuses to wait in a request thread
                breaches = check_hibp(value, key)
                logger.info(f"HIBP: {value} — {len(breaches)} breach(es)")
            except HIBPError as e:
                error = e.message
                logger.warning(f"HIBP check failed for {value}: {e}")
        elif ttype == "email" and not key:
            error = "HIBP_API_KEY not configured — skipping breach lookup"

        # ── Dark web DB search ──
        darkweb_hits = storage.search_hits(value)
        logger.info(f"Dark web search '{value}': {len(darkweb_hits)} hit(s)")

        # ── Save target results ──
        storage.save_investigation_target(
            investigation_id=inv_id,
            value=value,
            target_type=ttype,
            breaches=[{
                "breach_name": b.breach_name,
                "breach_date": b.breach_date,
                "description": b.description,
                "data_classes": b.data_classes,
                "is_verified": b.is_verified,
                "is_sensitive": b.is_sensitive,
            } for b in breaches],
            darkweb_hits=darkweb_hits,
            error=error,
        )

    storage.complete_investigation(inv_id)
