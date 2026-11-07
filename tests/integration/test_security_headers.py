"""
XSS-5: the response headers the application sets itself.

Every response carries the Content-Security-Policy. Pages and /api/ answers
are not stored; a static file is kept for long under its versioned URL only.
The pages ask for their scripts and styles from /static/ with that version.
"""

import re

import pytest
from flask import Flask

from darkweb_scanner import __version__
from darkweb_scanner.dashboard.security_headers import (
    CONTENT_SECURITY_POLICY,
    STATIC_CACHE_CONTROL,
    init_security_headers,
)
from tests.helpers import make_user, sign_in

POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:; font-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


@pytest.fixture
def signed_in(full_app, db):
    client = full_app.test_client()
    sign_in(client, db, make_user(db, "boss", admin=True))
    return client


def test_the_policy_is_the_agreed_one():
    assert CONTENT_SECURITY_POLICY == POLICY
    directives = dict(d.split(" ", 1) for d in POLICY.split("; "))
    # No inline script, no eval, nothing from another host.
    assert directives["script-src"] == "'self'"
    assert "unsafe" not in directives["script-src"]
    assert directives["object-src"] == "'none'"
    assert directives["frame-ancestors"] == "'none'"


def test_pages_carry_the_policy_and_are_not_stored(signed_in):
    for path in ("/dashboard", "/quick-scan", "/help"):
        resp = signed_in.get(path)
        assert resp.status_code == 200, path
        assert resp.headers["Content-Security-Policy"] == POLICY, path
        assert resp.headers["Cache-Control"] == "no-store", path


def test_sign_in_page_and_redirects_carry_the_policy(client, db):
    make_user(db, "exists")  # otherwise /login redirects to first-admin setup
    resp = client.get("/login")
    assert resp.status_code == 200
    assert resp.headers["Content-Security-Policy"] == POLICY
    assert resp.headers["Cache-Control"] == "no-store"
    resp = client.get("/dashboard")
    assert resp.status_code == 302
    assert resp.headers["Content-Security-Policy"] == POLICY
    assert resp.headers["Cache-Control"] == "no-store"


def test_api_answers_are_not_stored(client, signed_in):
    resp = signed_in.get("/api/stats")
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["Content-Security-Policy"] == POLICY
    # An error answer too.
    resp = client.get("/api/stats")
    assert resp.status_code == 401
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["Content-Security-Policy"] == POLICY


@pytest.mark.parametrize(
    "path",
    [
        "js/dashboard.js",
        "js/quick_scan.js",
        "vendor/jsvectormap/jsvectormap.min.js",
        "vendor/jsvectormap/jsvectormap.min.css",
        "vendor/jsvectormap/world.js",
    ],
)
def test_static_files_are_kept_for_long_under_the_versioned_url(client, path):
    resp = client.get(f"/static/{path}?v={__version__}")
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == STATIC_CACHE_CONTROL
    assert "max-age=31536000" in STATIC_CACHE_CONTROL and "immutable" in STATIC_CACHE_CONTROL
    assert resp.headers["Content-Security-Policy"] == POLICY
    kind = "text/css" if path.endswith(".css") else "javascript"
    assert kind in resp.headers["Content-Type"]


@pytest.mark.parametrize("query", ["", "?v=0.0.0", "?v="])
def test_static_files_without_the_current_version_are_not_kept_for_long(client, query):
    resp = client.get("/static/js/dashboard.js" + query)
    assert resp.status_code == 200
    cache = resp.headers.get("Cache-Control", "")
    assert "immutable" not in cache and "31536000" not in cache


def test_a_missing_static_file_is_not_kept(client):
    resp = client.get(f"/static/js/nothing.js?v={__version__}")
    assert resp.status_code == 404
    assert "immutable" not in resp.headers.get("Cache-Control", "")
    assert resp.headers["Content-Security-Policy"] == POLICY


@pytest.mark.parametrize("path", ["/dashboard", "/quick-scan"])
def test_pages_load_scripts_and_styles_from_static_with_the_version(signed_in, path):
    body = signed_in.get(path).get_data(as_text=True)
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", body, re.S)
    assert scripts, "the page loads no script"
    for attrs, inline in scripts:
        assert inline.strip() == "", "inline script in the page"
        src = re.search(r'src="([^"]+)"', attrs)
        assert src, "script without src"
        assert src.group(1).startswith("/static/js/") and src.group(1).endswith(f"?v={__version__}")
        assert signed_in.get(src.group(1)).status_code == 200, src.group(1)
    for href in re.findall(r'<link rel="stylesheet" href="([^"]+)"', body):
        assert href.startswith("/static/") and href.endswith(f"?v={__version__}")
        assert signed_in.get(href).status_code == 200, href
    # Values the script reads from the head: every static URL there exists.
    for url in re.findall(r'<meta name="[\w-]+" content="(/static/[^"]+)"', body):
        assert url.endswith(f"?v={__version__}")
        assert signed_in.get(url).status_code == 200, url
    assert not re.search(r"""(?:src|href)=["']https?://""", body), (
        "the page loads something external"
    )


def test_username_reaches_the_script_escaped(full_app, db):
    client = full_app.test_client()
    sign_in(client, db, make_user(db, 'a"><script>alert(1)</script>'))
    body = client.get("/dashboard").get_data(as_text=True)
    assert (
        '<meta name="current-user" content="a&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"/>'
        in body
    )
    assert "<script>alert(1)" not in body


def test_headers_nginx_adds_are_not_repeated():
    app = Flask(__name__)
    init_security_headers(app)

    @app.route("/page")
    def page():
        return "<p>hello</p>"

    resp = app.test_client().get("/page")
    assert resp.headers["Content-Security-Policy"] == POLICY
    assert resp.headers["Cache-Control"] == "no-store"
    for name in (
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ):
        assert name not in resp.headers, name
