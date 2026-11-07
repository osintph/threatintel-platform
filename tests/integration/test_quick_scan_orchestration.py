"""
Integration tests for the Quick Scan orchestrator (run_quick_scan).

Tor is mocked to return canned HTML so the crawl logic — findings
persistence, URL cap, depth cap, and total-timeout handling — is exercised without
any network access.
"""

import asyncio
from unittest.mock import patch

import pytest

from darkweb_scanner import quick_scan as qs
from darkweb_scanner.storage import Storage


class _FakeTor:
    async def get_session(self):
        return None

    async def close(self):
        return None


# Canned pages. The search page links to two onion "hit" pages; each hit page links
# to a "deep" page one hop further, letting us probe the depth cap.
_SEARCH_HTML = (
    '<html><body>results '
    '<a href="http://aaaaaaaaaaaaaaaaaaaaaaaaaa.onion/hit1">r1</a> '
    '<a href="http://bbbbbbbbbbbbbbbbbbbbbbbbbb.onion/hit2">r2</a>'
    '</body></html>'
)
_HIT_HTML = (
    '<html><body>Records for acme.com credentials were leaked and are for sale '
    '<a href="http://cccccccccccccccccccccccccc.onion/deep">more</a>'
    '</body></html>'
)
_DEEP_HTML = '<html><body>deep page mentioning acme.com again</body></html>'


def _page_for(url: str):
    if "/hit" in url:
        return 200, _HIT_HTML
    if "/deep" in url:
        return 200, _DEEP_HTML
    return 200, _SEARCH_HTML


@pytest.fixture(autouse=True)
def _fast_delays(monkeypatch):
    monkeypatch.setenv("QUICK_SCAN_DELAY_MIN", "0")
    monkeypatch.setenv("QUICK_SCAN_DELAY_MAX", "0")


@pytest.fixture
def storage():
    return Storage("sqlite:///:memory:")


def _run(storage, session_id):
    async def _fake_fetch(url, tor_client):
        return _page_for(url)

    with patch.object(qs, "_fetch", _fake_fetch):
        asyncio.run(qs.run_quick_scan(session_id, storage, _FakeTor()))


def test_findings_written_with_correct_fields(storage):
    sid = storage.create_quick_scan_session(
        1, "acme.com", "domain", ["acme.com"], ["ahmia"]
    )
    _run(storage, sid)

    sess = storage.get_quick_scan_session(sid)
    assert sess.status == "completed"
    assert sess.error_message is None
    assert sess.urls_visited > 0
    assert sess.findings_count > 0

    findings = storage.list_quick_scan_findings(sid)
    assert findings, "expected at least one finding"
    f = findings[0]
    assert f.source_name == "ahmia"
    assert f.matched_variant == "acme.com"
    assert "acme.com" in f.context
    # "credentials", "leaked", "for sale" appear on the hit pages
    assert any(x.high_signal for x in findings)
    # findings_count column matches persisted rows
    assert sess.findings_count == len(findings)


def test_high_signal_only_filter(storage):
    sid = storage.create_quick_scan_session(
        1, "acme.com", "domain", ["acme.com"], ["ahmia"]
    )
    _run(storage, sid)
    all_f = storage.list_quick_scan_findings(sid)
    hi_f = storage.list_quick_scan_findings(sid, high_signal_only=True)
    assert len(hi_f) <= len(all_f)
    assert all(f.high_signal for f in hi_f)


def test_url_cap_is_respected(storage):
    sid = storage.create_quick_scan_session(
        1, "acme.com", "domain", ["acme.com"], ["ahmia"]
    )
    with patch.object(qs, "MAX_URLS_PER_SCAN", 2):
        _run(storage, sid)
    sess = storage.get_quick_scan_session(sid)
    assert sess.urls_visited <= 2


def test_depth_cap_is_respected(storage):
    # With MAX_DEPTH=1: search page (depth 0) + its two hit links (depth 1) are
    # fetched, but the "deep" pages (depth 2) linked from the hits are not.
    sid = storage.create_quick_scan_session(
        1, "acme.com", "domain", ["acme.com"], ["ahmia"]
    )
    with patch.object(qs, "MAX_DEPTH", 1):
        _run(storage, sid)
    findings = storage.list_quick_scan_findings(sid)
    urls = {f.url for f in findings}
    assert not any("/deep" in u for u in urls), "depth-2 page should not be fetched"
    sess = storage.get_quick_scan_session(sid)
    # 1 search + 2 hits = 3 pages attempted
    assert sess.urls_visited == 3


def test_total_timeout_marks_session_completed_with_warning(storage):
    sid = storage.create_quick_scan_session(
        1, "acme.com", "domain", ["acme.com"], ["ahmia"]
    )
    # A non-positive total timeout trips the deadline before any fetch.
    with patch.object(qs, "TOTAL_TIMEOUT", -1):
        _run(storage, sid)
    sess = storage.get_quick_scan_session(sid)
    assert sess.status == "completed"
    assert sess.error_message and "time cap" in sess.error_message
    assert sess.urls_visited == 0


class _FakeResp:
    def __init__(self, status=200, body=b"", headers=None):
        self.status = status
        self.headers = {"Content-Type": "text/html", **(headers or {})}
        self.charset = "utf-8"
        self.content = self
        self._body = body

    async def iter_chunked(self, _size):
        yield self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    """Records the requests made through the (fake) Tor session."""

    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.resp


class _SessionTor(_FakeTor):
    def __init__(self, session):
        self.session = session

    async def get_session(self):
        return self.session


def test_clearnet_path_goes_through_tor(storage):
    # NET-5: a clearnet source is fetched through Tor, not from the server's own address.
    session = _FakeSession(_FakeResp(body=b"acme.com leaked"))
    with patch("darkweb_scanner.dashboard.http_client.safe_fetch") as direct:
        status, html = asyncio.run(qs._fetch("https://dpaste.org/x", _SessionTor(session)))
    assert status == 200
    assert "acme.com" in html
    direct.assert_not_called()
    assert [url for url, _ in session.calls] == ["https://dpaste.org/x"]
    kwargs = session.calls[0][1]
    assert kwargs["allow_redirects"] is False
    assert "ssl" not in kwargs  # the certificate is checked


@pytest.mark.parametrize(
    "url",
    [
        "http://dpaste.org/x",  # not https
        "https://not-allowlisted.example/x",
        "https://user:pw@dpaste.org/x",  # credentials in the URL
    ],
)
def test_clearnet_path_applies_safe_fetch_policy_before_tor(storage, url):
    from darkweb_scanner.dashboard.http_client import SafeFetchError

    session = _FakeSession(_FakeResp())
    with pytest.raises(SafeFetchError):
        asyncio.run(qs._fetch(url, _SessionTor(session)))
    assert session.calls == []


def test_clearnet_path_does_not_follow_redirects(storage):
    session = _FakeSession(_FakeResp(status=302, headers={"Location": "https://dpaste.org/y"}))
    status, _html = asyncio.run(qs._fetch("https://dpaste.org/x", _SessionTor(session)))
    assert status == 302
    assert len(session.calls) == 1
