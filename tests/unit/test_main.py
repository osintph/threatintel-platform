"""Unit tests for main.run_scan orchestration."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call

from darkweb_scanner.main import run_scan
from darkweb_scanner.crawler import CrawlConfig
from darkweb_scanner.scanner import KeywordConfig


async def _empty_crawl(seeds):
    """Async generator that yields nothing (successful empty crawl)."""
    return
    yield  # noqa: unreachable — makes this an async generator


async def _raising_crawl(seeds):
    """Async generator that raises on first iteration."""
    raise RuntimeError("network error")
    yield  # noqa: unreachable


def _make_mocks():
    storage = MagicMock()
    storage.create_crawl_session.return_value = 99
    alerter = MagicMock()
    keyword_config = KeywordConfig.from_list(["test"])
    crawl_config = CrawlConfig()

    mock_tor = AsyncMock()
    mock_tor.close = AsyncMock()

    return storage, alerter, keyword_config, crawl_config, mock_tor


async def test_successful_scan_marks_completed():
    """COR-01: a scan that finishes without error must be marked 'completed'."""
    storage, alerter, kc, cc, mock_tor = _make_mocks()

    with patch("darkweb_scanner.main.create_tor_client", return_value=mock_tor), \
         patch("darkweb_scanner.main.Crawler") as mock_crawler_cls:

        mock_crawler_cls.return_value.crawl.return_value = _empty_crawl([])

        result = await run_scan(
            seeds=["http://test.onion"],
            keyword_config=kc,
            crawl_config=cc,
            storage=storage,
            alerter=alerter,
            check_tor=False,
        )

    storage.update_crawl_session.assert_called_once_with(99, 0, 0, status="completed")
    assert result["pages_crawled"] == 0


async def test_failed_scan_marks_failed_not_completed():
    """COR-01: when the crawler raises, the session must end as 'failed', not 'completed'."""
    storage, alerter, kc, cc, mock_tor = _make_mocks()

    with patch("darkweb_scanner.main.create_tor_client", return_value=mock_tor), \
         patch("darkweb_scanner.main.Crawler") as mock_crawler_cls:

        mock_crawler_cls.return_value.crawl.return_value = _raising_crawl([])

        with pytest.raises(RuntimeError, match="network error"):
            await run_scan(
                seeds=["http://test.onion"],
                keyword_config=kc,
                crawl_config=cc,
                storage=storage,
                alerter=alerter,
                check_tor=False,
            )

    storage.update_crawl_session.assert_called_once_with(99, 0, 0, status="failed")
