"""
XSS-1, XSS-2, XSS-3, AUTH-4 (2026-11 audit): the two dashboard pages, read as text.

The pages build their markup in the browser from API data. These checks keep
the patterns behind the findings from coming back: data inside an inline event
handler, an escaper that leaves quotes alone, links built from data without a
scheme check, write requests without the CSRF token, and sign-out as a link.
``tests/browser/xss_check.py`` runs the same pages in a browser against hostile
data.

XSS_CHECK_TEMPLATES=<dir> points the tests at another copy of the templates.
"""

import os
import re
from pathlib import Path

import pytest

TEMPLATES = Path(
    os.environ.get("XSS_CHECK_TEMPLATES")
    or Path(__file__).resolve().parents[2] / "src" / "darkweb_scanner" / "dashboard" / "templates"
)
PAGES = ["index.html", "quick_scan.html"]


def _read(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


@pytest.fixture(params=PAGES)
def page(request) -> str:
    return _read(request.param)


def _lines_matching(text: str, pattern: str) -> list[str]:
    rx = re.compile(pattern)
    return [
        f"line {n}: {line.strip()[:120]}"
        for n, line in enumerate(text.splitlines(), 1)
        if rx.search(line)
    ]


def _function_body(text: str, name: str) -> str:
    """Source of ``function <name>(...) { ... }`` up to its closing brace."""
    match = re.search(r"^( *)function " + re.escape(name) + r"\(.*?^\1\}", text, re.S | re.M)
    assert match, f"function {name} not found"
    return match.group(0)


# ── XSS-1 / XSS-2: no data in inline event handlers ────────────────────────────


def test_no_data_in_inline_event_handlers(page):
    """HTML decodes an attribute before the handler is parsed as script, so no
    escaping makes a value safe there. Values go into data-* attributes."""
    found = _lines_matching(page, r"""(?<![\w-])on[a-z]+\s*=\s*(?:"[^"]*|'[^']*)\$\{""")
    found += _lines_matching(page, r"""(?<![\w-])on[a-z]+\s*=\s*\\?"[^"]*'\s*\+\s*[A-Za-z_(]""")
    assert not found, "inline event handler built from data:\n" + "\n".join(found[:20])


def test_delegated_actions_are_registered():
    """Buttons built from data name a function in data-act; the click listener
    only calls names registered in ACTIONS."""
    text = _read("index.html")
    used = set(re.findall(r"\bact\('([A-Za-z_]\w*)'", text))
    assert used, "act() is not used"
    registry = re.search(r"Object\.assign\(ACTIONS, \{(.*?)\}\);", text, re.S)
    assert registry, "ACTIONS registry not found"
    registered = set(re.findall(r"^\s*([A-Za-z_]\w*),\s*$", registry.group(1), re.M))
    assert used <= registered, f"used in markup but not registered: {sorted(used - registered)}"
    undeclared = [
        n
        for n in sorted(registered)
        if not re.search(r"^\s*(?:async )?function " + n + r"\(", text, re.M)
    ]
    assert not undeclared, f"registered but not a declared function: {undeclared}"
    assert "hasOwnProperty.call(ACTIONS" in text, (
        "the listener must only call own entries of ACTIONS"
    )


# ── XSS-1..3: the escaper ──────────────────────────────────────────────────────


def test_escaper_covers_the_five_characters(page):
    body = _function_body(page, "esc")
    for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
        assert entity in body, f"esc() does not produce {entity}"
    assert "== null" in body, "esc() must turn null and undefined into ''"
    assert "!s" not in body, "esc() must not drop 0 or false"


# ── XSS-2: links and images built from data ────────────────────────────────────


def test_safe_url_allows_http_and_https_only(page):
    body = _function_body(page, "safeUrl")
    assert "'http:'" in body and "'https:'" in body
    assert "return '#'" in body or ": '#'" in body
    assert not re.search(r"javascript|data:|mailto", body), (
        "safeUrl() is an allowlist, not a denylist"
    )


def test_urls_built_from_data_go_through_safe_url(page):
    attrs = r"(?:href|src|action|formaction|poster|srcset)"
    # ${...} at the start of the value, and the same with string concatenation.
    found = _lines_matching(page, attrs + r"""\s*=\s*\\?["']\$\{(?!esc\(safeUrl\()""")
    found += _lines_matching(page, attrs + r"""\s*=\s*\\?"'\s*\+\s*(?!\s|esc\(safeUrl\()""")
    assert not found, "URL attribute built from data without esc(safeUrl(...)):\n" + "\n".join(
        found[:20]
    )


def test_new_tab_links_drop_the_opener(page):
    found = [
        f"line {n}: {line.strip()[:120]}"
        for n, line in enumerate(page.splitlines(), 1)
        if 'target="_blank"' in line and 'rel="noopener noreferrer"' not in line
    ]
    assert not found, 'target="_blank" without rel="noopener noreferrer":\n' + "\n".join(found[:20])


# ── AUTH-4: CSRF token and sign-out ────────────────────────────────────────────


def test_csrf_token_reaches_every_write_request(page):
    assert '<meta name="csrf-token" content="{{ csrf_token() }}"' in page
    wrapper = page.find("window.fetch = ")
    assert wrapper != -1, "window.fetch is not wrapped"
    assert "headers.set('X-CSRF-Token'" in page
    first_call = re.search(r"\bfetch\(\s*['`]/api/", page)
    assert first_call and wrapper < first_call.start(), (
        "the wrapper must be installed before the first API call"
    )
    assert "'/login?next='" in page, "401 from the API must lead to the sign-in page"
    assert "'admin required'" in page and "'Admin only'" in page


def test_sign_out_is_a_post_form_with_the_token(page):
    assert 'href="/logout"' not in page, "sign-out must not be a GET link"
    form = re.search(r'<form method="POST" action="/logout"[^>]*>(.*?)</form>', page, re.S)
    assert form, "no POST form to /logout"
    assert '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}"' in form.group(1)
    assert '<button type="submit"' in form.group(1)


def test_help_and_privacy_link(page):
    assert re.search(r'<a href="/help"[^>]*>Help &amp; privacy</a>', page)


# ── D-8 / D-11: what a non-admin is shown ──────────────────────────────────────


def test_admin_only_controls_are_hidden_from_other_users():
    text = _read("index.html")
    assert '<body{% if is_admin %} class="is-admin"{% endif %}>' in text
    assert re.search(r"body:not\(\.is-admin\) \.admin-only \{ display: none !important; \}", text)
    marked = [
        r'<button class="nav-tab admin-only"[^>]*switchTab\(\'channelmonitor\'',
        r'<div class="tab-panel admin-only" id="panel-channelmonitor"',
        r'<button class="nav-tab admin-only" id="tab-users"',
        r'<div class="tab-panel admin-only" id="panel-users"',
        r'<button class="btn-crawl admin-only" id="crawlBtn"',
        r'<button id="crawlStopBtn" class="admin-only"',
    ]
    for pattern in marked:
        assert re.search(pattern, text), f"not marked admin-only: {pattern}"
    # Remove and delete buttons the page builds for admin-only API calls.
    for action in (
        "deleteKeyword",
        "deleteSeed",
        "deleteClearnetSeed",
        "deletePasteSource",
        "deleteChannel",
        "deleteInvestigation",
        "deleteIPInv",
        "deleteDNS",
        "deleteIntel",
    ):
        buttons = re.findall(r"<button class=\"([^\"]*)\"[^>]*\$\{act\('" + action + "'", text)
        assert buttons, f"no button for {action}"
        assert all("admin-only" in classes.split() for classes in buttons), (
            f"{action} button is not admin-only"
        )
