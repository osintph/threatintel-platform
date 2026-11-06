"""
Auth blueprint — first-admin setup, login, TOTP setup/verify, forced password change, logout.
"""

import logging
import time

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from ..auth import (
    FAILURE_WINDOW_SECONDS,
    LOCK_SECONDS,
    MAX_FAILURES_PER_IP,
    MFA_PENDING_SECONDS,
    PASSWORD_POLICY,
    PENDING_TOTP_SECRET_SECONDS,
    account_key,
    check_password,
    clear_failures,
    current_user,
    generate_totp_qr_base64,
    generate_totp_secret,
    hash_password,
    ip_key,
    locked_for,
    login_user,
    logout_user,
    match_totp_step,
    note_password_failure,
    note_totp_failure,
    record_auth_event,
    reissue_session,
    setup_token_configured,
    setup_token_matches,
    totp_key,
    use_totp_code,
    validate_password_strength,
)
from . import validation as v
from .storage_helper import get_storage

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)

_MFA_UID = "mfa_uid"
_MFA_AT = "mfa_at"


def _safe_next(next_url: str, default: str) -> str:
    """Return next_url only when it is a safe same-site path."""
    if (
        next_url
        and next_url.startswith("/")
        and not next_url.startswith("//")
        and "\\" not in next_url
        and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in next_url)
    ):
        return next_url
    return default


def _minutes(seconds: int) -> str:
    minutes = max(1, (seconds + 59) // 60)
    return f"{minutes} minute{'s' if minutes != 1 else ''}"


def _drop_mfa_pending() -> None:
    session.pop(_MFA_UID, None)
    session.pop(_MFA_AT, None)


# ── First administrator ────────────────────────────────────────────────────────


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Create the first administrator. Open only while there are no users, and
    only to someone who holds SETUP_TOKEN from the server's .env."""
    storage = get_storage()
    if storage.count_users() > 0:
        flash("Registration is closed. Contact your administrator.", "error")
        return redirect(url_for("auth.login"))

    if not setup_token_configured():
        return render_template("register.html", setup_disabled=True, password_policy=PASSWORD_POLICY), 403

    def form(status: int = 200):
        return render_template("register.html", setup_disabled=False, password_policy=PASSWORD_POLICY), status

    if request.method == "POST":
        wait = locked_for(ip_key())
        if wait:
            flash(f"Too many attempts. Try again in {_minutes(wait)}.", "error")
            return form(429)

        if not setup_token_matches(request.form.get("setup_token", "")):
            get_storage().throttle_fail(ip_key(), MAX_FAILURES_PER_IP, FAILURE_WINDOW_SECONDS, LOCK_SECONDS)
            record_auth_event("setup_failed", request.form.get("username", ""), None, "wrong setup token")
            flash("The setup token is not correct.", "error")
            return form(403)

        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        try:
            username = v.username(request.form.get("username", ""))
            email = v.email(request.form.get("email", ""), required=False)
        except v.Invalid as err:
            flash(str(err), "error")
            return form(400)

        if password != confirm:
            flash("Passwords do not match.", "error")
            return form(400)

        err = validate_password_strength(password)
        if err:
            flash(err, "error")
            return form(400)

        user_id = storage.create_user(
            username=username,
            email=email,
            password_hash=hash_password(password),
            is_admin=True,
        )
        user = storage.get_user_by_id(user_id)
        login_user(user)
        storage.update_user_login(user.id)
        record_auth_event("admin_created", username, user_id, "first administrator, via setup token")
        flash("Account created. Set up two-factor authentication to continue.", "success")
        return redirect(url_for("auth.totp_setup"))

    return form()


# ── Login ──────────────────────────────────────────────────────────────────────


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user() is not None:
        return redirect(url_for("dashboard.index"))

    storage = get_storage()

    if storage.count_users() == 0:
        return redirect(url_for("auth.register"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()[:100]
        password = request.form.get("password", "")

        wait = locked_for(account_key(username), ip_key())
        if wait:
            record_auth_event("login_blocked", username, None, "locked")
            flash(f"Too many failed attempts. Try again in {_minutes(wait)}.", "error")
            return render_template("login.html"), 429

        user = storage.get_user_by_username(username)
        # One bcrypt check either way, so timing does not show which names exist.
        if not check_password(password, user.password_hash if user else None):
            note_password_failure(username)
            record_auth_event("login_failed", username, user.id if user else None, "wrong password or unknown user")
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        clear_failures(account_key(username))

        if user.totp_enabled and user.totp_secret:
            # Password accepted; the session starts only after the second factor.
            session.pop("user_id", None)
            session.pop("sv", None)
            session[_MFA_UID] = user.id
            session[_MFA_AT] = int(time.time())
            return redirect(url_for("auth.totp_verify", next=request.args.get("next", "")))

        # No second factor yet: sign in, and require_login sends the user to
        # the password change and to enrolment before anything else.
        login_user(user)
        storage.update_user_login(user.id)
        record_auth_event("login_ok", user.username, user.id, "password only, enrolment pending")
        return redirect(_safe_next(request.args.get("next", ""), url_for("dashboard.index")))

    return render_template("login.html")


# ── TOTP Verify ────────────────────────────────────────────────────────────────


@auth_bp.route("/totp/verify", methods=["GET", "POST"])
def totp_verify():
    pending_id = session.get(_MFA_UID)
    started = session.get(_MFA_AT) or 0
    if not isinstance(pending_id, int) or time.time() - started > MFA_PENDING_SECONDS:
        _drop_mfa_pending()
        return redirect(url_for("auth.login"))

    storage = get_storage()
    user = storage.get_user_by_id(pending_id)
    if not user or not (user.totp_enabled and user.totp_secret):
        _drop_mfa_pending()
        flash("Session expired.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        wait = locked_for(totp_key(user.id), ip_key())
        if wait:
            _drop_mfa_pending()
            record_auth_event("mfa_blocked", user.username, user.id, "locked")
            flash(f"Too many wrong codes. Sign in again in {_minutes(wait)}.", "error")
            return redirect(url_for("auth.login"))

        if not use_totp_code(user, request.form.get("code", "")):
            now_locked = note_totp_failure(user.id)
            record_auth_event("mfa_failed", user.username, user.id, "locked" if now_locked else "wrong or reused code")
            if now_locked:
                # The password step has to be repeated; a kept cookie does not help,
                # because the lock is held on the server.
                _drop_mfa_pending()
                flash(f"Too many wrong codes. Sign in again in {_minutes(LOCK_SECONDS)}.", "error")
                return redirect(url_for("auth.login"))
            flash("Invalid code. Please try again.", "error")
            return render_template("totp_verify.html", username=user.username)

        clear_failures(totp_key(user.id))
        login_user(user)
        storage.update_user_login(user.id)
        record_auth_event("login_ok", user.username, user.id, "password and code")
        return redirect(_safe_next(request.args.get("next", ""), url_for("dashboard.index")))

    return render_template("totp_verify.html", username=user.username)


# ── TOTP Setup ─────────────────────────────────────────────────────────────────


@auth_bp.route("/totp/setup", methods=["GET", "POST"])
def totp_setup():
    """Enrol a second factor, or replace it. Replacing needs a code from the current one."""
    user = current_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if user.must_change_password:
        return redirect(url_for("auth.force_change_password"))

    storage = get_storage()
    replacing = bool(user.totp_enabled and user.totp_secret)

    # The secret being enrolled is held on the server, not in the cookie.
    secret = storage.get_pending_totp_secret(user.id, PENDING_TOTP_SECRET_SECONDS)
    if secret is None:
        secret = generate_totp_secret()
        storage.set_pending_totp_secret(user.id, secret)
        if request.method == "POST":
            flash("That setup page expired. Scan the new code and try again.", "error")
            return redirect(url_for("auth.totp_setup"))

    def form(status: int = 200):
        qr = generate_totp_qr_base64(secret, user.username)
        return render_template("totp_setup.html", qr_code=qr, secret=secret, replacing=replacing), status

    if request.method == "POST":
        if replacing:
            wait = locked_for(totp_key(user.id))
            if wait:
                flash(f"Too many wrong codes. Try again in {_minutes(wait)}.", "error")
                return form(429)
            if not use_totp_code(user, request.form.get("current_code", "")):
                note_totp_failure(user.id)
                record_auth_event("mfa_change_failed", user.username, user.id, "wrong current code")
                flash("The code from your current authenticator is not correct.", "error")
                return form(400)

        step = match_totp_step(secret, request.form.get("code", ""))
        if step is None:
            flash("Invalid code. Please try again.", "error")
            return form(400)

        storage.enable_totp(user.id, secret, step)
        reissue_session(user)  # ends the user's other sessions, keeps this one
        record_auth_event("mfa_replaced" if replacing else "mfa_enrolled", user.username, user.id)
        flash("Two-factor authentication enabled. Your account is now secure.", "success")
        return redirect(url_for("dashboard.index"))

    return form()


# ── Force Password Change ──────────────────────────────────────────────────────


@auth_bp.route("/force-change-password", methods=["GET", "POST"])
def force_change_password():
    user = current_user()
    if user is None:
        return redirect(url_for("auth.login"))

    if not user.must_change_password:
        return redirect(url_for("dashboard.index"))

    storage = get_storage()

    def form(status: int = 200):
        return render_template("force_change_password.html", password_policy=PASSWORD_POLICY), status

    if request.method == "POST":
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if new_pw != confirm:
            flash("Passwords do not match.", "error")
            return form(400)

        err = validate_password_strength(new_pw)
        if err:
            flash(err, "error")
            return form(400)

        if check_password(new_pw, user.password_hash):
            flash("Choose a password that differs from the temporary one.", "error")
            return form(400)

        storage.update_user_password(user.id, hash_password(new_pw))
        storage.set_must_change_password(user.id, False)
        reissue_session(user)
        record_auth_event("password_changed", user.username, user.id, "temporary password replaced")
        flash("Password updated. Now set up two-factor authentication to continue.", "success")
        # require_login decides from the database what is still missing.
        return redirect(url_for("dashboard.index"))

    return form()


# ── Logout ─────────────────────────────────────────────────────────────────────


@auth_bp.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    if user is not None:
        record_auth_event("logout", user.username, user.id)
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
