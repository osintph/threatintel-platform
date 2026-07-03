"""
Auth blueprint — login, register, TOTP setup/verify, OAuth, logout.
"""

import logging
import secrets
from urllib.parse import urlencode

import requests as http_requests
from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from ..auth import (
    check_password,
    generate_totp_qr_base64,
    generate_totp_secret,
    get_oauth_providers,
    hash_password,
    login_user,
    logout_user,
    validate_password_strength,
    verify_totp,
)
from .storage_helper import get_storage

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)


def _safe_next(next_url: str, default: str) -> str:
    """Return next_url only when it is a safe same-site path."""
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return default


# ── Registration ───────────────────────────────────────────────────────────────


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    storage = get_storage()
    if storage.count_users() > 0:
        flash("Registration is closed. Contact your administrator.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        err = validate_password_strength(password)
        if err:
            flash(err, "error")
            return render_template("register.html")

        if storage.get_user_by_username(username):
            flash("Username already taken.", "error")
            return render_template("register.html")

        user_id = storage.create_user(
            username=username,
            email=email or None,
            password_hash=hash_password(password),
            is_admin=True,
        )
        login_user(user_id, username)
        flash("Account created! Set up 2FA to secure your account.", "success")
        return redirect(url_for("auth.totp_setup"))

    return render_template("register.html")


# ── Login ──────────────────────────────────────────────────────────────────────


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard.index"))

    storage = get_storage()

    if storage.count_users() == 0:
        return redirect(url_for("auth.register"))

    oauth_providers = get_oauth_providers()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = storage.get_user_by_username(username)
        if not user or not user.password_hash:
            flash("Invalid username or password.", "error")
            return render_template("login.html", oauth_providers=oauth_providers)

        if not check_password(password, user.password_hash):
            flash("Invalid username or password.", "error")
            return render_template("login.html", oauth_providers=oauth_providers)

        if user.totp_enabled and user.totp_secret:
            session["totp_pending_user_id"] = user.id
            session["totp_pending_username"] = user.username
            return redirect(url_for("auth.totp_verify"))

        login_user(user.id, user.username)
        storage.update_user_login(user.id)
        # Force password change if set by admin
        if getattr(user, "must_change_password", False):
            session["must_change_password"] = True
            return redirect(url_for("auth.force_change_password"))
        next_url = _safe_next(request.args.get("next", ""), url_for("dashboard.index"))
        return redirect(next_url)

    return render_template("login.html", oauth_providers=oauth_providers)


# ── TOTP Setup ─────────────────────────────────────────────────────────────────


@auth_bp.route("/totp/setup", methods=["GET", "POST"])
def totp_setup():
    if not session.get("logged_in"):
        return redirect(url_for("auth.login"))

    storage = get_storage()
    user_id = session["user_id"]
    username = session["username"]

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("totp_setup_secret")

        if not secret:
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("auth.totp_setup"))

        if not verify_totp(secret, code):
            flash("Invalid code. Please try again.", "error")
            qr = generate_totp_qr_base64(secret, username)
            return render_template("totp_setup.html", qr_code=qr, secret=secret)

        storage.enable_totp(user_id, secret)
        session.pop("totp_setup_secret", None)
        session.pop("must_setup_mfa", None)
        flash("Two-factor authentication enabled! Your account is now secure.", "success")
        return redirect(url_for("dashboard.index"))

    secret = generate_totp_secret()
    session["totp_setup_secret"] = secret
    qr = generate_totp_qr_base64(secret, username)
    return render_template("totp_setup.html", qr_code=qr, secret=secret)


# ── TOTP Verify ────────────────────────────────────────────────────────────────


@auth_bp.route("/totp/verify", methods=["GET", "POST"])
def totp_verify():
    pending_id = session.get("totp_pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    storage = get_storage()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user = storage.get_user_by_id(pending_id)

        if not user or not user.totp_secret:
            flash("Session expired.", "error")
            return redirect(url_for("auth.login"))

        if not verify_totp(user.totp_secret, code):
            flash("Invalid code. Please try again.", "error")
            return render_template(
                "totp_verify.html", username=session.get("totp_pending_username")
            )

        login_user(user.id, user.username)
        storage.update_user_login(user.id)
        next_url = _safe_next(request.args.get("next", ""), url_for("dashboard.index"))
        return redirect(next_url)

    return render_template("totp_verify.html", username=session.get("totp_pending_username"))


# ── OAuth ──────────────────────────────────────────────────────────────────────


@auth_bp.route("/oauth/<provider>")
def oauth_redirect(provider):
    providers = get_oauth_providers()
    if provider not in providers:
        flash("OAuth provider not configured.", "error")
        return redirect(url_for("auth.login"))

    p = providers[provider]
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session["oauth_provider"] = provider

    callback_url = url_for("auth.oauth_callback", provider=provider, _external=True)
    params = {
        "client_id": p["client_id"],
        "redirect_uri": callback_url,
        "scope": p["scope"],
        "response_type": "code",
        "state": state,
    }
    return redirect(p["authorize_url"] + "?" + urlencode(params))


@auth_bp.route("/oauth/<provider>/callback")
def oauth_callback(provider):
    providers = get_oauth_providers()
    if provider not in providers:
        flash("Unknown OAuth provider.", "error")
        return redirect(url_for("auth.login"))

    if request.args.get("state") != session.pop("oauth_state", None):
        flash("OAuth state mismatch. Please try again.", "error")
        return redirect(url_for("auth.login"))

    code = request.args.get("code")
    if not code:
        flash("OAuth login failed — no code received.", "error")
        return redirect(url_for("auth.login"))

    p = providers[provider]
    callback_url = url_for("auth.oauth_callback", provider=provider, _external=True)

    try:
        token_resp = http_requests.post(
            p["token_url"],
            data={
                "client_id": p["client_id"],
                "client_secret": p["client_secret"],
                "code": code,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        access_token = token_resp.json().get("access_token")
    except Exception as e:
        logger.error(f"OAuth token exchange failed: {e}")
        flash("OAuth login failed. Please try again.", "error")
        return redirect(url_for("auth.login"))

    if not access_token:
        flash("OAuth login failed — no access token.", "error")
        return redirect(url_for("auth.login"))

    # Apple sends user info in the ID token, not a userinfo endpoint
    if provider == "apple":
        import base64, json as _json
        id_token = token_resp.json().get("id_token", "")
        try:
            payload = id_token.split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            userinfo = _json.loads(base64.urlsafe_b64decode(payload))
        except Exception:
            userinfo = {}
    elif p.get("userinfo_url"):
        try:
            userinfo = http_requests.get(
                p["userinfo_url"],
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout=10,
            ).json()
        except Exception as e:
            logger.error(f"OAuth userinfo failed: {e}")
            flash("OAuth login failed — could not fetch user info.", "error")
            return redirect(url_for("auth.login"))
    else:
        userinfo = {}

    if provider == "google":
        oauth_id = userinfo.get("sub")
        email = userinfo.get("email")
        username = email.split("@")[0] if email else f"google_{str(oauth_id)[:8]}"
    elif provider == "github":
        oauth_id = str(userinfo.get("id"))
        email = userinfo.get("email")
        username = userinfo.get("login") or f"github_{oauth_id[:8]}"
    elif provider == "microsoft":
        oauth_id = userinfo.get("id") or userinfo.get("sub")
        email = userinfo.get("mail") or userinfo.get("userPrincipalName") or userinfo.get("email")
        username = (email.split("@")[0] if email else None) or f"ms_{str(oauth_id)[:8]}"
    elif provider == "apple":
        oauth_id = userinfo.get("sub")
        email = userinfo.get("email")
        username = email.split("@")[0] if email else f"apple_{str(oauth_id)[:8]}"
    else:
        flash("Unknown provider.", "error")
        return redirect(url_for("auth.login"))

    if not oauth_id:
        flash("Could not retrieve user identity from OAuth provider.", "error")
        return redirect(url_for("auth.login"))

    storage = get_storage()

    if storage.count_users() == 0:
        flash("Please create a local admin account first.", "error")
        return redirect(url_for("auth.register"))

    user = storage.get_user_by_oauth(provider, oauth_id)
    if not user and email:
        user = storage.get_user_by_email(email)

    if not user:
        base_username = username
        counter = 1
        while storage.get_user_by_username(username):
            username = f"{base_username}{counter}"
            counter += 1

        user_id = storage.create_user(
            username=username,
            email=email,
            oauth_provider=provider,
            oauth_id=oauth_id,
            is_admin=False,
        )
        user = storage.get_user_by_id(user_id)

    login_user(user.id, user.username)
    storage.update_user_login(user.id)
    return redirect(url_for("dashboard.index"))



# ── Force Password Change ──────────────────────────────────────────────────────


@auth_bp.route("/force-change-password", methods=["GET", "POST"])
def force_change_password():
    if not session.get("logged_in"):
        return redirect(url_for("auth.login"))

    if not session.get("must_change_password"):
        return redirect(url_for("dashboard.index"))

    storage = get_storage()
    user_id = session["user_id"]

    if request.method == "POST":
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if new_pw != confirm:
            flash("Passwords do not match.", "error")
            return render_template("force_change_password.html")

        err = validate_password_strength(new_pw)
        if err:
            flash(err, "error")
            return render_template("force_change_password.html")

        storage.update_user_password(user_id, hash_password(new_pw))
        storage.set_must_change_password(user_id, False)
        session.pop("must_change_password", None)
        session["must_setup_mfa"] = True  # force MFA setup next
        flash("Password updated. Now set up two-factor authentication to continue.", "success")
        return redirect(url_for("auth.totp_setup"))

    return render_template("force_change_password.html")


# ── Logout ─────────────────────────────────────────────────────────────────────


@auth_bp.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
