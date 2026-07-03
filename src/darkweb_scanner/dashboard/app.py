"""
Flask application factory — wires up auth + dashboard blueprints.
"""

import os
from datetime import timedelta

from flask import Flask, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix


def create_app() -> Flask:
    app = Flask(__name__)

    _secret = os.getenv("DASHBOARD_SECRET_KEY", "")
    _PLACEHOLDER = "change-me-in-production"
    if not _secret or _secret == _PLACEHOLDER or _secret == "change-me-to-a-long-random-string":
        raise RuntimeError(
            "DASHBOARD_SECRET_KEY is not set or still uses the placeholder value. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and set it in .env before starting the dashboard."
        )
    app.secret_key = _secret
    app.permanent_session_lifetime = timedelta(hours=12)

    # Trust X-Forwarded-Proto from nginx so url_for generates https:// URLs
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    from .auth_routes import auth_bp
    from .dashboard_routes import dashboard_bp
    from .channel_monitor_routes import channel_monitor_bp
    from .ransomware_live_routes import rw_live_bp
    from .storage_helper import close_db

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(channel_monitor_bp)
    app.register_blueprint(rw_live_bp)
    app.teardown_appcontext(close_db)

    @app.route("/")
    def root():
        return redirect(url_for("dashboard.index"))

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
