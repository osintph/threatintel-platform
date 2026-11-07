"""
Flask application factory — wires up auth + dashboard blueprints.

Served by gunicorn (see docker-compose.yml):
    gunicorn 'darkweb_scanner.dashboard.app:create_app()'
"""

import logging
import os
from datetime import timedelta

from flask import Flask, flash, jsonify, redirect, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from ..auth import SESSION_MAX_AGE_SECONDS, client_ip, csrf_failure, csrf_token

logger = logging.getLogger(__name__)

MIN_SECRET_KEY_LENGTH = 32
_PLACEHOLDER_SECRETS = ("change-me-in-production", "change-me-to-a-long-random-string")

class _SkipHealthcheckLog(logging.Filter):
    """Keep the container healthcheck (one request every 15 s) out of the access log."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "GET /healthz" not in record.getMessage()


def _configure_logging() -> None:
    """Send the app's own log lines (including auth events) to the container log."""
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("darkweb_scanner").setLevel(logging.INFO)


def create_app() -> Flask:
    _configure_logging()
    app = Flask(__name__)

    _secret = os.getenv("DASHBOARD_SECRET_KEY", "")
    if not _secret or _secret in _PLACEHOLDER_SECRETS or len(_secret) < MIN_SECRET_KEY_LENGTH:
        raise RuntimeError(
            "DASHBOARD_SECRET_KEY is not set, still uses the placeholder value, or is shorter than "
            f"{MIN_SECRET_KEY_LENGTH} characters. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and set it in .env before starting the dashboard."
        )
    app.secret_key = _secret
    app.permanent_session_lifetime = timedelta(seconds=SESSION_MAX_AGE_SECONDS)

    # The dashboard is only ever served over HTTPS by nginx. DASHBOARD_ALLOW_HTTP=1 is
    # for running it on a developer's machine without TLS, and for nothing else.
    allow_http = os.getenv("DASHBOARD_ALLOW_HTTP", "").lower() in ("1", "true")
    app.config.update(
        SESSION_COOKIE_NAME="session" if allow_http else "__Host-session",
        SESSION_COOKIE_SECURE=not allow_http,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # The cookie's lifetime is not pushed forward by every response.
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    )
    if allow_http:
        logger.warning("DASHBOARD_ALLOW_HTTP is set: the session cookie is sent over plain HTTP")

    # nginx sets X-Forwarded-For (the visitor's address), -Proto and -Host itself
    # and never passes the client's values through; trust exactly one hop.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]

    app.jinja_env.globals["csrf_token"] = csrf_token

    from .auth_routes import auth_bp
    from .channel_monitor_routes import channel_monitor_bp
    from .dashboard_routes import dashboard_bp
    from .errors import install_error_handlers
    from .ransomware_live_routes import rw_live_bp
    from .security_headers import init_security_headers
    from .storage_helper import close_db, get_storage

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(channel_monitor_bp)
    app.register_blueprint(rw_live_bp)
    init_security_headers(app)
    install_error_handlers(app)
    app.teardown_appcontext(close_db)

    # Fail at start, not at the first request, when the database is not configured.
    storage = get_storage()
    try:
        storage.prune_auth_state()
    except Exception:
        logger.exception("could not prune old auth events")
    try:
        from .channel_monitor_routes import purge_expired_archives

        purge_expired_archives()
    except Exception:
        logger.exception("could not purge expired Channel Monitor archives")

    @app.before_request
    def _csrf_protect():
        reason = csrf_failure()
        if reason is None:
            return None
        logger.warning(
            "csrf check failed reason=%s method=%s path=%s ip=%s", reason, request.method, request.path, client_ip()
        )
        if request.path.startswith("/api/"):
            return jsonify({"error": "csrf", "detail": "missing or wrong CSRF token; reload the page"}), 403
        flash("That page expired. Please try again.", "error")
        return redirect(url_for("auth.login"))

    @app.route("/")
    def root():
        return redirect(url_for("dashboard.index"))

    @app.route("/healthz")
    def healthz():
        """Container healthcheck: 200 only when a query against the database works."""
        from sqlalchemy import text

        from .storage_helper import get_db

        try:
            get_db().execute(text("SELECT 1"))
        except Exception:
            logger.exception("healthz: database check failed")
            return {"status": "error", "database": "unreachable"}, 503
        return {"status": "ok", "database": "ok"}

    logging.getLogger("werkzeug").addFilter(_SkipHealthcheckLog())

    return app
