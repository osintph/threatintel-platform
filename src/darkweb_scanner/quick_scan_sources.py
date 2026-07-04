"""
Quick Scan source registry.

Plain-Python, typed source definitions for the ad-hoc "Quick Scan" feature.
Kept as code (not YAML/JSON) on purpose: adding, removing, or re-pointing a
source is a reviewable diff.

Transport model:
  - ``tor``      : fetched through the existing Tor SOCKS5 client (.onion hosts).
  - ``clearnet`` : fetched through ``dashboard.http_client.safe_fetch`` — HTTPS-only,
                   host-allowlisted, IP-blocklisted. Any clearnet source host MUST be
                   present in ALLOWED_EXTERNAL_HOSTS or the fetch is refused.

A source exposes one or more ``url_templates``. A template containing the literal
``{query}`` placeholder is a search endpoint (the URL-encoded target is substituted
in). A template with no placeholder is a fixed seed URL fetched as-is (used by leak
sites that have no search box).
"""

from dataclasses import dataclass
from urllib.parse import quote

from .ransomware_data import RANSOMWARE_ONION_SEEDS

# Transport identifiers
TRANSPORT_TOR = "tor"
TRANSPORT_CLEARNET = "clearnet"

# Source kinds
KIND_SEARCH_ENGINE = "search_engine"
KIND_LEAK_SITE = "leak_site"
KIND_PASTE = "paste"
KIND_FORUM = "forum"


@dataclass(frozen=True)
class QuickScanSource:
    """A single queryable Quick Scan source."""

    name: str                     # stable identifier used in sources_used and the API
    label: str                    # human-facing label for the UI checklist
    kind: str                     # one of the KIND_* constants
    transport: str                # TRANSPORT_TOR | TRANSPORT_CLEARNET
    url_templates: tuple          # tuple[str, ...]; "{query}" marks a search endpoint
    enabled: bool = True          # disabled sources are never queried

    @property
    def search_capable(self) -> bool:
        return any("{query}" in t for t in self.url_templates)

    def build_urls(self, query: str) -> list:
        """Return the concrete URLs to fetch for a given target query.

        Search templates get the URL-encoded query substituted; fixed seed
        templates are returned unchanged. A source with no templates yields an
        empty list and is therefore skipped cleanly by the orchestrator.
        """
        encoded = quote(query, safe="")
        urls = []
        for template in self.url_templates:
            if "{query}" in template:
                urls.append(template.replace("{query}", encoded))
            else:
                urls.append(template)
        return urls


# ── Dark web search engines (onion, via Tor) ────────────────────────────────────

_SEARCH_ENGINES = [
    QuickScanSource(
        name="ahmia",
        label="Ahmia",
        kind=KIND_SEARCH_ENGINE,
        transport=TRANSPORT_TOR,
        url_templates=(
            "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}",
        ),
    ),
    QuickScanSource(
        name="torch",
        label="Torch",
        kind=KIND_SEARCH_ENGINE,
        transport=TRANSPORT_TOR,
        url_templates=(
            "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/search?q={query}",
        ),
    ),
    QuickScanSource(
        name="haystak",
        label="Haystak",
        kind=KIND_SEARCH_ENGINE,
        transport=TRANSPORT_TOR,
        url_templates=(
            "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={query}",
        ),
    ),
]


# ── Ransomware leak sites (onion, via Tor) ───────────────────────────────────────
# Reuse the curated seed list as-is. These have no search box, so each seed page is
# fetched and crawled for the target rather than queried.

_RANSOMWARE_LEAKS = [
    QuickScanSource(
        name="ransomware_leaks",
        label="Ransomware Leak Sites",
        kind=KIND_LEAK_SITE,
        transport=TRANSPORT_TOR,
        url_templates=tuple(RANSOMWARE_ONION_SEEDS),
    ),
]


# ── Paste sites (clearnet, via safe_fetch) ───────────────────────────────────────
# Neither rentry.co nor dpaste.org exposes a documented public *search* endpoint, so
# both ship disabled (empty url_templates -> skipped cleanly). Populate a search
# template and flip enabled=True once an endpoint is confirmed. dpaste.org is kept in
# ALLOWED_EXTERNAL_HOSTS so enabling it is a one-line change, not a security review.

_PASTE_SITES = [
    QuickScanSource(
        name="dpaste",
        label="dpaste.org",
        kind=KIND_PASTE,
        transport=TRANSPORT_CLEARNET,
        url_templates=(),   # no public search endpoint yet; add "https://dpaste.org/...{query}"
        enabled=False,
    ),
    QuickScanSource(
        name="rentry",
        label="rentry.co",
        kind=KIND_PASTE,
        transport=TRANSPORT_CLEARNET,
        url_templates=(),   # no public search endpoint; skip cleanly
        enabled=False,
    ),
]


# ── Forum seed list (onion, curated) ─────────────────────────────────────────────
# Intentionally empty. Populate before enabling forum sources — forum onion addresses
# rotate frequently and stale hard-coded URLs are worse than none.

_FORUMS: list = [
    # QuickScanSource(name="...", label="...", kind=KIND_FORUM,
    #                 transport=TRANSPORT_TOR, url_templates=("http://...onion/search?q={query}",)),
]


# All registered sources, in display order.
ALL_SOURCES: tuple = tuple(_SEARCH_ENGINES + _RANSOMWARE_LEAKS + _PASTE_SITES + _FORUMS)

_BY_NAME = {s.name: s for s in ALL_SOURCES}


def get_source(name: str):
    """Return the source with the given name, or None."""
    return _BY_NAME.get(name)


def default_enabled_sources() -> list:
    """Sources used when the caller does not specify an explicit subset."""
    return [s for s in ALL_SOURCES if s.enabled]


def resolve_sources(names) -> list:
    """Resolve a list of requested source names to enabled QuickScanSource objects.

    Unknown or disabled names are dropped silently. ``None`` means "all enabled".
    """
    if names is None:
        return default_enabled_sources()
    resolved = []
    for name in names:
        source = _BY_NAME.get(name)
        if source is not None and source.enabled:
            resolved.append(source)
    return resolved
