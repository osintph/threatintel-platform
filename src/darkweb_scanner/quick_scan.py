"""
Quick Scan — ad-hoc target investigation, independent of the project/IOC pipeline.

This module holds:
  1. Target auto-detection and normalization (pure functions).
  2. "High signal" classification and context-window extraction (pure functions).
  3. The async orchestrator ``run_quick_scan`` (added in a later change).

Detection and normalization are deliberately pure and side-effect free so they can
be unit-tested exhaustively without any network or database.
"""

import logging
import re
from urllib.parse import urlparse

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
