"""
Investigations module — ad hoc targeted lookups.
Checks email addresses against HIBP, searches existing dark web hits,
and stores findings as named investigations.
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")


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


async def check_hibp(email: str, api_key: str) -> list[BreachResult]:
    """Check a single email against HIBP breach database."""
    if not api_key:
        raise ValueError("HIBP_API_KEY not configured")

    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "DarkWebScanner-ThreatIntel/1.0",
    }

    url = f"{HIBP_API_BASE}/breachedaccount/{email}?truncateResponse=false"

    async with aiohttp.ClientSession() as client:
        try:
            async with client.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 404:
                    return []  # No breaches found — good news
                if resp.status == 401:
                    raise ValueError("Invalid HIBP API key")
                if resp.status == 429:
                    raise ValueError("HIBP rate limit hit — wait 1 minute and retry")
                if resp.status != 200:
                    raise ValueError(f"HIBP API error: HTTP {resp.status}")

                data = await resp.json()
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
        except aiohttp.ClientError as e:
            raise ValueError(f"Network error contacting HIBP: {e}")


async def run_investigation(
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
    """
    inv_id = storage.create_investigation(name=name, targets=targets)
    key = api_key or HIBP_API_KEY

    for target in targets:
        value = target["value"].strip()
        ttype = target["type"]
        breaches = []
        error = None

        # ── HIBP breach check ──
        if ttype == "email" and key:
            try:
                await asyncio.sleep(1.5)  # HIBP rate limit: 1 req/1.5s
                breaches = await check_hibp(value, key)
                logger.info(f"HIBP: {value} — {len(breaches)} breach(es)")
            except ValueError as e:
                error = str(e)
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
    return inv_id
