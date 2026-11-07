"""
Response headers the application sets itself (XSS-5), and the versioned URLs
of its static files.

nginx already adds Strict-Transport-Security, X-Frame-Options,
X-Content-Type-Options and Referrer-Policy to everything it proxies; those
are not repeated here.
"""

from flask import Flask, Response, request, url_for

from .. import __version__

# Scripts come from the application's own /static/ only: no inline script, no
# inline event handler, no eval. Styles still allow inline because the pages
# carry style attributes. Images allow https: for the profile pictures shown in
# OSINT user lookups and data: for the page icon and the 2FA QR code.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

# A static file may be kept for a year: its URL carries the application
# version, so a new release is a new URL.
STATIC_CACHE_CONTROL = "public, max-age=31536000, immutable"


def asset_url(filename: str) -> str:
    """URL of a file below static/, with the application version as its query."""
    return url_for("static", filename=filename, v=__version__)


def _set_headers(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    if request.endpoint == "static":
        # Only the versioned URL is kept for long. Any other request for a
        # static file keeps Flask's default (revalidate with the server).
        if response.status_code in (200, 304) and request.args.get("v") == __version__:
            response.headers["Cache-Control"] = STATIC_CACHE_CONTROL
    elif request.path.startswith("/api/") or response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store"
    return response


def init_security_headers(app: Flask) -> None:
    """Install the response headers and the ``asset_url()`` template helper."""
    app.after_request(_set_headers)
    app.jinja_env.globals["asset_url"] = asset_url
