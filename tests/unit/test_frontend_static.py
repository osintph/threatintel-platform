"""
XSS-1, XSS-2, XSS-3, XSS-5, AUTH-4, REL-1, REL-4, REL-9 (2026-11 audit): the
pages and their scripts, read as text.

The pages are served with ``script-src 'self'``: the templates hold no script
and no event handler, the scripts live in ``static/js`` and nothing is loaded
from another host. The scripts build their markup in the browser from API
data. These checks keep the patterns behind the findings from coming back:
inline script, data inside an event handler, an escaper that leaves quotes
alone, links built from data without a scheme check, write requests without
the CSRF token, sign-out as a link, a failed API call that says nothing.
``tests/browser/xss_check.py`` runs the same pages in a browser, with the
policy enforced, against hostile data.

XSS_CHECK_TEMPLATES=<dir> points the tests at another copy of the templates;
the scripts are then read from ``<dir>/../static``.
"""

import hashlib
import os
import re
from pathlib import Path

import pytest

TEMPLATES = Path(
    os.environ.get("XSS_CHECK_TEMPLATES")
    or Path(__file__).resolve().parents[2] / "src" / "darkweb_scanner" / "dashboard" / "templates"
)
STATIC = TEMPLATES.parent / "static"
# The two pages with a script, and the script each one loads.
PAGES = {"index.html": "js/dashboard.js", "quick_scan.html": "js/quick_scan.js"}
SERVED = sorted(p.name for p in TEMPLATES.glob("*.html"))
OWN_SCRIPTS = sorted(str(p.relative_to(STATIC)) for p in STATIC.glob("js/*.js"))
VENDOR_FILES = sorted(
    str(p.relative_to(STATIC))
    for p in STATIC.glob("vendor/**/*")
    if p.is_file() and p.name != "README.md"
)

EXTERNAL = r"""["'`]?\s*(?:https?:)?//"""


def _read(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def _static(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def _script(page_name: str) -> str:
    """The script of a page: the file it loads, or what is inline in the template."""
    path = STATIC / PAGES[page_name]
    if path.exists():
        return path.read_text(encoding="utf-8")
    return "\n".join(re.findall(r"<script\b[^>]*>(.*?)</script>", _read(page_name), re.S))


@pytest.fixture(params=sorted(PAGES))
def page_name(request) -> str:
    return request.param


@pytest.fixture
def page(page_name) -> str:
    """Template text."""
    return _read(page_name)


@pytest.fixture
def script(page_name) -> str:
    return _script(page_name)


def _lines_matching(text: str, pattern: str) -> list[str]:
    rx = re.compile(pattern)
    return [
        f"line {n}: {line.strip()[:120]}"
        for n, line in enumerate(text.splitlines(), 1)
        if rx.search(line)
    ]


def _function_body(text: str, name: str) -> str:
    """Source of ``function <name>(...) { ... }`` up to its closing brace."""
    match = re.search(
        r"^( *)(?:async )?function " + re.escape(name) + r"\(.*?^\1\}", text, re.S | re.M
    )
    assert match, f"function {name} not found"
    return match.group(0)


def _registry(script: str) -> set[str]:
    registry = re.search(r"Object\.assign\(ACTIONS, \{(.*?)\}\);", script, re.S)
    assert registry, "ACTIONS registry not found"
    return set(re.findall(r"^\s*([A-Za-z_]\w*),\s*$", registry.group(1), re.M))


# ── XSS-5: no inline script, no inline handler, nothing from another host ─────


def test_the_files_exist():
    assert SERVED, "no templates found"
    assert set(PAGES) <= set(SERVED)
    assert OWN_SCRIPTS == sorted(PAGES.values()), (
        "static/js holds exactly the scripts of the two pages"
    )
    assert VENDOR_FILES, "static/vendor is empty"


@pytest.mark.parametrize("name", SERVED)
def test_templates_hold_no_script(name):
    text = _read(name)
    for attrs, body in re.findall(r"<script\b([^>]*)>(.*?)</script>", text, re.S):
        assert body.strip() == "", f"{name}: inline script"
        assert re.search(r"""\bsrc="\{\{ asset_url\('js/[\w.-]+'\) \}\}\"""", attrs), (
            f"{name}: a script must come from static/js through asset_url(): <script{attrs}>"
        )
    assert "<script" not in re.sub(r"<script\b[^>]*></script>", "", text), (
        f"{name}: unclosed or odd script tag"
    )
    assert not re.search(r"""(?:href|src|action)\s*=\s*["']\s*javascript:""", text, re.I), (
        f"{name}: javascript: URL"
    )


@pytest.mark.parametrize("name", SERVED)
def test_templates_hold_no_inline_event_handler(name):
    """``script-src 'self'`` blocks them; a control names its function in data-act."""
    found = _lines_matching(_read(name), r"""(?<![\w-])on[a-z]+\s*=\s*["']""")
    assert not found, f"{name}: inline event handler:\n" + "\n".join(found[:20])


@pytest.mark.parametrize("name", OWN_SCRIPTS)
def test_scripts_build_no_inline_event_handler(name):
    """HTML decodes an attribute before the handler is parsed as script, so no
    escaping makes a value safe there, and the policy blocks it anyway."""
    text = _static(name)
    # on...=" in a string of markup. A property (el.onload = fn) is preceded by a dot.
    found = _lines_matching(text, r"""(?<![\w.-])on[a-z]+\s*=\s*\\?["'`]""")
    found += _lines_matching(text, r"""setAttribute\(\s*["'`]on""")
    assert not found, f"{name}: markup with an inline event handler:\n" + "\n".join(found[:20])


@pytest.mark.parametrize("name", OWN_SCRIPTS + [f for f in VENDOR_FILES if f.endswith(".js")])
def test_scripts_do_not_evaluate_strings(name):
    text = _static(name)
    for pattern, what in (
        (r"\beval\s*\(", "eval()"),
        (r"\bnew\s+Function\b", "new Function"),
        (r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]", "a timer with a string"),
        (r"\bdocument\.write(?:ln)?\s*\(", "document.write"),
    ):
        assert not re.search(pattern, text), f"{name}: {what}"


@pytest.mark.parametrize("name", OWN_SCRIPTS)
def test_scripts_hold_no_template_syntax(name):
    """Values from the server reach a script through <meta> and data- attributes."""
    text = _static(name)
    assert "{{" not in text and "{%" not in text, f"{name}: Jinja syntax in a static file"


@pytest.mark.parametrize("name", SERVED)
def test_templates_load_nothing_from_another_host(name):
    text = _read(name)
    patterns = (
        r"<script\b[^>]*\bsrc\s*=\s*" + EXTERNAL,
        r"<link\b[^>]*\bhref\s*=\s*" + EXTERNAL,
        r"<(?:img|iframe|frame|embed|video|audio|source|track|object)\b[^>]*\b(?:src|data)\s*=\s*"
        + EXTERNAL,
        r"@import\b",
        r"\burl\(\s*" + EXTERNAL,
    )
    found = [line for pattern in patterns for line in _lines_matching(text, pattern)]
    assert not found, f"{name}: external load:\n" + "\n".join(found[:20])
    for tag in re.findall(r"<link\b[^>]*rel=\"stylesheet\"[^>]*>", text):
        assert re.search(r"""href="\{\{ asset_url\('[\w./-]+'\) \}\}\"""", tag), f"{name}: {tag}"


@pytest.mark.parametrize("name", OWN_SCRIPTS + VENDOR_FILES)
def test_static_files_load_nothing_from_another_host(name):
    text = _static(name)
    patterns = (
        r"\.(?:src|href)\s*=\s*[\"'`]\s*(?:https?:)?//",  # script.src = '...', link.href = '...'
        r"<(?:script|img|iframe|link)\b[^>]*\b(?:src|href)\s*=\s*\\?[\"']\s*(?:https?:)?//",
        r"@import\b",
        r"\burl\(\s*" + EXTERNAL,
        r"\bimportScripts\s*\(",
        r"\bfetch\(\s*[\"'`]\s*(?:https?:)?//",
        r"\bnew\s+(?:WebSocket|EventSource|Worker)\b",
    )
    found = [line for pattern in patterns for line in _lines_matching(text, pattern)]
    assert not found, f"{name}: external load:\n" + "\n".join(found[:20])


def test_map_library_comes_from_static():
    page, script = _read("index.html"), _script("index.html")
    for meta, path in (
        ("jsvectormap-js", "vendor/jsvectormap/jsvectormap.min.js"),
        ("jsvectormap-world", "vendor/jsvectormap/world.js"),
    ):
        assert f"""<meta name="{meta}" content="{{{{ asset_url('{path}') }}}}"/>""" in page
        assert f"pageMeta('{meta}')" in script
        assert (STATIC / path).is_file()
    assert "jsdelivr" not in page and "jsdelivr" not in script


def test_vendor_readme_names_every_file_with_its_hash():
    readme = _static("vendor/README.md")
    assert "jsvectormap" in readme and "1.5.3" in readme and "MIT" in readme
    assert "https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/" in readme
    for name in VENDOR_FILES:
        digest = hashlib.sha256((STATIC / name).read_bytes()).hexdigest()
        row = [line for line in readme.splitlines() if f"`{name.removeprefix('vendor/')}`" in line]
        assert row, f"{name} is not listed in static/vendor/README.md"
        assert digest in row[0], f"{name}: SHA-256 in the README does not match the file"


def test_values_from_the_server_arrive_in_the_markup():
    page, script = _read("index.html"), _script("index.html")
    assert '<meta name="current-user" content="{{ username }}"/>' in page
    assert "const currentUsername = pageMeta('current-user');" in script
    assert "const isAdmin = document.body.classList.contains('is-admin');" in script


# ── XSS-1 / XSS-2: delegated actions ──────────────────────────────────────────


def test_delegated_actions_are_registered(page, script):
    """A control names a function in a data-act attribute; the listeners only
    call names registered in ACTIONS."""
    used = set(re.findall(r'data-act(?:-change|-input|-keydown)?="([A-Za-z_]\w*)"', page))
    used |= set(re.findall(r"\bact\('([A-Za-z_]\w*)'", script))
    assert used, "no delegated action is used"
    registered = _registry(script)
    assert used <= registered, f"used in markup but not registered: {sorted(used - registered)}"
    assert registered <= used, f"registered but not used by any markup: {sorted(registered - used)}"
    undeclared = [
        n
        for n in sorted(registered)
        if not re.search(r"^(?:async )?function " + n + r"\(", script, re.M)
    ]
    assert not undeclared, f"registered but not a declared function: {undeclared}"
    assert "hasOwnProperty.call(ACTIONS" in script, (
        "the listener must only call own entries of ACTIONS"
    )


def test_delegation_covers_the_events_the_markup_uses(page, script):
    for attr, event in (
        ("data-act", "click"),
        ("data-act-change", "change"),
        ("data-act-input", "input"),
        ("data-act-keydown", "keydown"),
    ):
        if re.search(attr + r'="', page) or (attr == "data-act" and "act('" in script):
            assert f"delegate('{event}', '{attr}');" in script, f"no listener for {attr}"


# ── XSS-1..3: the escaper ──────────────────────────────────────────────────────


def test_escaper_covers_the_five_characters(script):
    body = _function_body(script, "esc")
    for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
        assert entity in body, f"esc() does not produce {entity}"
    assert "== null" in body, "esc() must turn null and undefined into ''"
    assert "!s" not in body, "esc() must not drop 0 or false"


# ── XSS-2: links and images built from data ────────────────────────────────────


def test_safe_url_allows_http_and_https_only(script):
    body = _function_body(script, "safeUrl")
    assert "'http:'" in body and "'https:'" in body
    assert "return '#'" in body or ": '#'" in body
    assert not re.search(r"javascript|data:|mailto", body), (
        "safeUrl() is an allowlist, not a denylist"
    )


def test_urls_built_from_data_go_through_safe_url(script):
    attrs = r"(?:href|src|action|formaction|poster|srcset)"
    # ${...} at the start of the value, and the same with string concatenation.
    found = _lines_matching(script, attrs + r"""\s*=\s*\\?["']\$\{(?!esc\(safeUrl\()""")
    found += _lines_matching(script, attrs + r"""\s*=\s*\\?"'\s*\+\s*(?!\s|esc\(safeUrl\()""")
    assert not found, "URL attribute built from data without esc(safeUrl(...)):\n" + "\n".join(
        found[:20]
    )


def test_new_tab_links_drop_the_opener(page, script):
    found = [
        f"line {n}: {line.strip()[:120]}"
        for text in (page, script)
        for n, line in enumerate(text.splitlines(), 1)
        if 'target="_blank"' in line and 'rel="noopener noreferrer"' not in line
    ]
    assert not found, 'target="_blank" without rel="noopener noreferrer":\n' + "\n".join(found[:20])


# ── AUTH-4: CSRF token and sign-out ────────────────────────────────────────────


def test_csrf_token_reaches_every_write_request(page, script):
    assert '<meta name="csrf-token" content="{{ csrf_token() }}"' in page
    wrapper = script.find("window.fetch = ")
    assert wrapper != -1, "window.fetch is not wrapped"
    assert "headers.set('X-CSRF-Token'" in script
    first_call = re.search(r"\bfetch\(\s*['`]/api/", script)
    assert first_call and wrapper < first_call.start(), (
        "the wrapper must be installed before the first API call"
    )
    assert "'/login?next='" in script, "401 from the API must lead to the sign-in page"
    assert "'admin required'" in script and "'Admin only'" in script


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
    page, script = _read("index.html"), _script("index.html")
    assert '<body{% if is_admin %} class="is-admin"{% endif %}>' in page
    assert re.search(r"body:not\(\.is-admin\) \.admin-only \{ display: none !important; \}", page)
    marked = [
        r'<button class="nav-tab admin-only"[^>]*data-args=\'\["channelmonitor"\]\'',
        r'<div class="tab-panel admin-only" id="panel-channelmonitor"',
        r'<button class="nav-tab admin-only" id="tab-users"',
        r'<div class="tab-panel admin-only" id="panel-users"',
        r'<button class="btn-crawl admin-only" id="crawlBtn"',
        r'<button id="crawlStopBtn" class="admin-only"',
    ]
    for pattern in marked:
        assert re.search(pattern, page), f"not marked admin-only: {pattern}"
    # Remove and delete buttons the script builds for admin-only API calls.
    for action in (
        "deleteKeyword",
        "deleteSeed",
        "deleteInvestigation",
        "deleteIPInv",
        "deleteDNS",
        "deleteIntel",
    ):
        buttons = re.findall(r"<button class=\"([^\"]*)\"[^>]*\$\{act\('" + action + "'", script)
        assert buttons, f"no button for {action}"
        assert all("admin-only" in classes.split() for classes in buttons), (
            f"{action} button is not admin-only"
        )


# ── Errors: a failed API call says what the server said ───────────────────────


def test_api_errors_are_shown_with_their_error_id(script):
    wrapper = script[script.find("window.fetch = ") : script.find("})();")]
    assert "apiErrorText(data, res.status)" in wrapper, (
        "the fetch wrapper must build the error text"
    )
    assert "toast(error, 'error')" in wrapper and "init.quiet" in wrapper
    body = _function_body(script, "apiErrorText")
    assert "data.error" in body and "' (error id ' + data.error_id + ')'" in body
    assert "429" in body
    assert not re.search(r"""["']Network error["']""", script), (
        "a bare 'Network error' says nothing"
    )
    # An empty catch is left only around reading a body that may not be JSON
    # (and around one call into the map library).
    silent = [
        line
        for line in _lines_matching(script, r"catch\s*\(\w+\)\s*\{\s*\}")
        if ".json()" not in line and "_jvmInstance.destroy()" not in line
    ]
    assert not silent, "a failure that says nothing:\n" + "\n".join(silent)


# ── REL-1: Channel Monitor ────────────────────────────────────────────────────


def test_channel_monitor_has_one_state_function():
    page, script = _read("index.html"), _script("index.html")
    show = _function_body(script, "cmShowJob")
    # Heading, badge, note and download button are written in cmShowJob and nowhere else.
    for element in ("cmActiveState", "cmStatusBadge", "cmStatusNote", "cmDownloadBtn"):
        assert f'id="{element}"' in page
        assert (
            script.count(f"getElementById('{element}')")
            == show.count(f"getElementById('{element}')")
            > 0
        ), f"{element} is written outside cmShowJob"
    assert "Running:" not in page, "the heading must not be fixed text"
    statuses = re.search(r"const CM_STATUS = \{(.*?)\n\};", script, re.S)
    assert statuses and set(re.findall(r"^\s*(\w+):\s*\{", statuses.group(1), re.M)) == {
        "running",
        "completed",
        "error",
        "interrupted",
        "archived",
    }
    # Anything that is not "running" is a finished job, a status this page does not know included.
    assert "status !== 'running'" in show
    assert "'Finished (' + status + ')'" in _function_body(script, "cmStatusInfo")
    assert not re.search(r"status === 'completed' \|\| \w+\.status === 'error'", script)


def test_channel_monitor_poll_stops_on_any_answer_that_is_not_200():
    poll = _function_body(_script("index.html"), "cmPollLog")
    assert "res.status !== 200" in poll
    assert "res.status === 404" in poll and "res.status === 401" in poll
    assert "stopped(" in poll and "cmStopPoll();" in poll
    assert "Log updates stopped: " in poll, "the poll must say why it stopped"
    assert not re.search(r"catch\s*\(\w+\)\s*\{\s*\}\s*\n\s*\}, 1500\)", poll), (
        "errors must not be swallowed"
    )


def test_channel_monitor_form():
    page, script = _read("index.html"), _script("index.html")
    start = _function_body(script, "cmStartScan")
    assert re.search(r'<input type="checkbox" id="cmTranslate" checked />', page), (
        "translation is on by default"
    )
    assert "Translate messages with Google Translate" in page
    assert "text that is not English is sent to translate.google.com" in page
    assert "translate:    document.getElementById('cmTranslate').checked" in start
    assert "min_space_gb" not in script and "cmMinSpace" not in page + script
    assert "data.error" in start, "409 and 400 come with the text to show"
    limits = _function_body(script, "cmApplyLimits")
    for field in ("max_messages", "max_video_mb", "max_file_mb", "max_job_gb"):
        assert f"limits.{field}" in limits
    assert "cmApplyLimits(creds.limits)" in script


# ── REL-4: crawl ──────────────────────────────────────────────────────────────


def test_crawl_card_shows_how_the_last_crawl_ended():
    script = _script("index.html")
    assert not re.search(r"\bpollStatus\b", script), (
        "pollStatus() does not exist in the dashboard script"
    )
    toggle = _function_body(script, "toggleCrawl")
    assert "pollCrawlStatus();" in toggle
    assert toggle.count("toast(data.error ||") == 2, "start and stop show the server's error text"
    poll = _function_body(script, "pollCrawlStatus")
    assert "data.last_session" in poll
    assert "'failed'" in poll and "'interrupted'" in poll and "last.error" in poll
    assert "innerHTML" not in poll, "the error text is data: textContent only"


# ── REL-9 / D-10: what is gone ────────────────────────────────────────────────


def test_removed_features_are_gone():
    page, script = _read("index.html"), _script("index.html")
    both = page + script
    for pattern, what in (
        (r"/api/paste\b", "Paste Monitor API"),
        (r"panel-paste|Paste Monitor", "Paste Monitor tab"),
        (r"/api/seeds/(?:clearnet|paste)", "clearnet seeds and paste sources"),
        (r"seeds-panel-(?:clearnet|paste)", "clearnet seeds and paste sources panels"),
        (r"/api/telegram/channels", "Telegram channel list"),
        (r"/api/digest/subscribe(?!rs)", "public digest sign-up"),
        (r"/api/send-brief", "send-brief"),
        (
            r"triggerPortScan|/scan(?:/status)?[`'\"]|Run Port Scan|Run Dir Enum|Scan Ports",
            "DNS port and directory scan",
        ),
        (r"oauth_provider", "oauth_provider"),
    ):
        found = _lines_matching(both, pattern)
        assert not found, f"{what} is still referenced:\n" + "\n".join(found[:10])
    assert "/api/digest/subscribers" in script, "the admin subscriber list stays"
    telegram = re.search(r'<div id="seeds-panel-telegram".*?\n    </div>\n', page, re.S)
    assert (
        telegram
        and "reads its channels from <code>TELEGRAM_CHANNELS</code> in <code>.env</code>"
        in telegram.group(0)
    )
    assert "<input" not in telegram.group(0) and "<button" not in telegram.group(0)


def test_keyword_project_dropdown_reads_the_list():
    body = _function_body(_script("index.html"), "_populateKwProjectDropdown")
    assert "Array.isArray(data) ? data : " in body, "GET /api/projects answers with the list itself"
