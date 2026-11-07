"""
Keyword scanner — matches keywords/regex patterns against crawled page text
and returns structured hits with surrounding context.
"""

import logging
import re
from dataclasses import dataclass, field

import yaml

logger = logging.getLogger(__name__)

# Keywords are matched as literal text (re.escape), so a search is linear in
# the length of the page. These two bound what one page can cost.
MAX_SCAN_TEXT = 2_000_000  # characters of one page that are scanned
MAX_HITS_PER_KEYWORD = 100  # per page, when every occurrence is reported


@dataclass
class KeywordHit:
    url: str
    keyword: str
    category: str
    context: str  # surrounding text window
    position: int  # character offset in text
    depth: int = 0


@dataclass
class KeywordConfig:
    categories: dict[str, list[str]] = field(default_factory=dict)
    case_sensitive: bool = False
    context_window: int = 200  # chars on each side of hit
    alert_on_first_hit_only: bool = True

    @classmethod
    def from_yaml(cls, path: str) -> "KeywordConfig":
        with open(path) as f:
            raw = yaml.safe_load(f)

        settings = raw.get("settings", {})
        keywords = raw.get("keywords", {})

        return cls(
            categories=keywords,
            case_sensitive=settings.get("case_sensitive", False),
            context_window=settings.get("context_window", 200),
            alert_on_first_hit_only=settings.get("alert_on_first_hit_only", True),
        )

    @classmethod
    def from_list(cls, keywords: list[str], category: str = "default") -> "KeywordConfig":
        return cls(categories={category: keywords})


class Scanner:
    def __init__(self, config: KeywordConfig):
        self.config = config
        self._patterns: dict[str, tuple[str, re.Pattern]] = {}  # keyword -> (category, pattern)
        self._compile_patterns()

    def _compile_patterns(self):
        flags = 0 if self.config.case_sensitive else re.IGNORECASE
        for category, keywords in self.config.categories.items():
            for keyword in keywords:
                try:
                    pattern = re.compile(re.escape(keyword), flags)
                    self._patterns[keyword] = (category, pattern)
                except re.error as e:
                    logger.warning(f"Invalid keyword pattern '{keyword}': {e}")

    def _get_context(self, text: str, match: re.Match) -> str:
        start = max(0, match.start() - self.config.context_window)
        end = min(len(text), match.end() + self.config.context_window)
        snippet = text[start:end]
        # add ellipsis if truncated
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."
        return snippet.strip()

    def scan(self, url: str, text: str, depth: int = 0) -> list[KeywordHit]:
        """Scan text for all configured keywords. Returns list of hits."""
        if not text:
            return []
        if len(text) > MAX_SCAN_TEXT:
            logger.info(f"Scanning the first {MAX_SCAN_TEXT} characters of {url}")
            text = text[:MAX_SCAN_TEXT]

        hits = []

        for keyword, (category, pattern) in self._patterns.items():
            if self.config.alert_on_first_hit_only:
                # One search, not a list of every occurrence on the page.
                first = pattern.search(text)
                matches = [first] if first else []
            else:
                matches = []
                for match in pattern.finditer(text):
                    matches.append(match)
                    if len(matches) >= MAX_HITS_PER_KEYWORD:
                        break

            for match in matches:
                context = self._get_context(text, match)
                hits.append(
                    KeywordHit(
                        url=url,
                        keyword=keyword,
                        category=category,
                        context=context,
                        position=match.start(),
                        depth=depth,
                    )
                )

        if hits:
            logger.info(f"Found {len(hits)} keyword hit(s) on {url}")

        return hits

    def add_keyword(self, keyword: str, category: str = "custom"):
        """Dynamically add a keyword at runtime."""
        flags = 0 if self.config.case_sensitive else re.IGNORECASE
        try:
            pattern = re.compile(re.escape(keyword), flags)
            self._patterns[keyword] = (category, pattern)
            if category not in self.config.categories:
                self.config.categories[category] = []
            self.config.categories[category].append(keyword)
        except re.error as e:
            logger.warning(f"Could not add keyword '{keyword}': {e}")

    def remove_keyword(self, keyword: str):
        """Remove a keyword."""
        self._patterns.pop(keyword, None)
        for kws in self.config.categories.values():
            if keyword in kws:
                kws.remove(keyword)

    @property
    def keyword_count(self) -> int:
        return len(self._patterns)
