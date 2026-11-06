"""
Authentication — local accounts with bcrypt passwords and TOTP.

The session cookie carries a user id and a session version, nothing else that
is trusted. Every request loads the user from the database (``current_user``),
so deleting a user, signing out, or changing a password or the second factor
ends every session issued before it. Whether a user still has to change a
temporary password or enrol a second factor is read from the database too.
"""

import base64
import hmac
import logging
import os
import secrets
import time
from functools import wraps
from io import BytesIO
from typing import Optional
from urllib.parse import urlsplit

import bcrypt
import pyotp
import qrcode
from flask import g, jsonify, redirect, request, session, url_for

logger = logging.getLogger(__name__)
auth_log = logging.getLogger("darkweb_scanner.auth_events")

# ── Limits ─────────────────────────────────────────────────────────────────────

FAILURE_WINDOW_SECONDS = 15 * 60
LOCK_SECONDS = 15 * 60
MAX_PASSWORD_FAILURES_PER_ACCOUNT = 10
MAX_FAILURES_PER_IP = 20
MAX_TOTP_FAILURES = 5
MFA_PENDING_SECONDS = 5 * 60
# A session ends 12 hours after sign-in, however active it is.
SESSION_MAX_AGE_SECONDS = 12 * 60 * 60
PENDING_TOTP_SECRET_SECONDS = 15 * 60
TOTP_STEP_SECONDS = 30

CSRF_HEADER = "X-CSRF-Token"
CSRF_FIELD = "csrf_token"
_CSRF_SESSION_KEY = "_csrf"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _storage():
    # Looked up through the module so tests can swap storage_helper._storage.
    from .dashboard import storage_helper

    return storage_helper.get_storage()


# ── Session ────────────────────────────────────────────────────────────────────


def login_user(user) -> None:
    """Start a session for ``user`` (a storage.User). Drops whatever the cookie held."""
    csrf = session.get(_CSRF_SESSION_KEY)
    session.clear()
    if csrf:
        session[_CSRF_SESSION_KEY] = csrf
    session.permanent = True
    session["user_id"] = user.id
    session["username"] = user.username
    session["sv"] = _storage().ensure_session_version(user.id)
    session["iat"] = int(time.time())
    g.pop("_current_user", None)


def logout_user() -> None:
    """End the session, and with it every other session of the same user."""
    user = current_user()
    if user is not None:
        _storage().bump_session_version(user.id)
    session.clear()
    g.pop("_current_user", None)


def reissue_session(user) -> None:
    """After a password or MFA change: end the user's other sessions, keep this one."""
    session["sv"] = _storage().bump_session_version(user.id)
    g.pop("_current_user", None)


def current_user():
    """The signed-in user, loaded from the database once per request, or None."""
    if "_current_user" in g:
        return g._current_user
    user = None
    uid = session.get("user_id")
    issued = session.get("iat")
    fresh = isinstance(issued, int) and 0 <= time.time() - issued <= SESSION_MAX_AGE_SECONDS
    if isinstance(uid, int) and fresh:
        storage = _storage()
        candidate = storage.get_user_by_id(uid)
        if candidate is not None:
            version = storage.get_session_version(uid)
            if version is not None and session.get("sv") == version:
                user = candidate
    g._current_user = user
    return user


def current_user_id() -> Optional[int]:
    user = current_user()
    return user.id if user is not None else None


def is_authenticated() -> bool:
    return current_user() is not None


def _wants_json() -> bool:
    return request.path.startswith("/api/")


def _deny(status: int, error: str, location: str):
    if _wants_json():
        return jsonify({"error": error}), status
    return redirect(location)


def _gate(user):
    """Response that stops ``user`` from going further, or None."""
    if user is None:
        return _deny(401, "unauthorized", url_for("auth.login", next=request.path))
    if user.must_change_password:
        return _deny(403, "password_change_required", url_for("auth.force_change_password"))
    if not (user.totp_enabled and user.totp_secret):
        return _deny(403, "mfa_setup_required", url_for("auth.totp_setup"))
    return None


def require_login(f):
    """Signed in, temporary password changed, second factor enrolled."""

    @wraps(f)
    def decorated(*args, **kwargs):
        denied = _gate(current_user())
        if denied is not None:
            return denied
        return f(*args, **kwargs)

    return decorated


def require_admin(f):
    """``require_login`` plus the admin flag, read from the database."""

    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        denied = _gate(user)
        if denied is not None:
            return denied
        if not user.is_admin:
            return jsonify({"error": "admin required"}), 403
        return f(*args, **kwargs)

    return decorated


# ── CSRF ───────────────────────────────────────────────────────────────────────


def csrf_token() -> str:
    """Per-session token; templates put it in a hidden field or a meta tag."""
    token = session.get(_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSRF_SESSION_KEY] = token
    return token


def csrf_failure() -> Optional[str]:
    """Why the current request fails the CSRF check, or None when it passes.

    Every request that is not GET, HEAD or OPTIONS must carry the session's
    token in the ``X-CSRF-Token`` header or the ``csrf_token`` form field, and
    an ``Origin`` header, when the browser sends one, must name this host.
    """
    if request.method in _SAFE_METHODS:
        return None
    origin = request.headers.get("Origin")
    if origin:
        if (urlsplit(origin).hostname or "") != request.host.split(":")[0].lower():
            return "origin"
    expected = session.get(_CSRF_SESSION_KEY)
    sent = request.headers.get(CSRF_HEADER) or request.form.get(CSRF_FIELD)
    if not expected or not sent or not hmac.compare_digest(str(expected), str(sent)):
        return "token"
    return None


# ── Throttling and the event log ───────────────────────────────────────────────


def client_ip() -> str:
    return (request.remote_addr or "unknown")[:45]


def _clean(value) -> str:
    """One printable line, for the log."""
    return "".join(c if c.isprintable() else "?" for c in str(value or ""))[:100]


def record_auth_event(event: str, username: str = "", user_id: Optional[int] = None, detail: str = "") -> None:
    """Write one line to the log and one row to ``auth_events``. Never raises."""
    ip = client_ip()
    auth_log.info(
        "auth event=%s user=%r user_id=%s ip=%s detail=%r", event, _clean(username), user_id, ip, _clean(detail)
    )
    try:
        _storage().add_auth_event(event, _clean(username), user_id, ip, _clean(detail))
    except Exception:
        logger.exception("could not store auth event %s", event)


def account_key(username: str) -> str:
    # Keyed on what was typed, not on whether the account exists, so the
    # "too many attempts" answer says nothing about which names are real.
    return "user:" + username.strip().lower()[:100]


def ip_key(address: Optional[str] = None) -> str:
    return "ip:" + (address or client_ip())[:45]


def totp_key(user_id: int) -> str:
    return f"totp:{user_id}"


def locked_for(*keys: str) -> int:
    """Seconds until the longest lock on any of ``keys`` ends; 0 when none is locked."""
    storage = _storage()
    return max((storage.throttle_locked_seconds(k) for k in keys), default=0)


def note_password_failure(username: str) -> None:
    storage = _storage()
    storage.throttle_fail(account_key(username), MAX_PASSWORD_FAILURES_PER_ACCOUNT, FAILURE_WINDOW_SECONDS, LOCK_SECONDS)
    storage.throttle_fail(ip_key(), MAX_FAILURES_PER_IP, FAILURE_WINDOW_SECONDS, LOCK_SECONDS)


def note_totp_failure(user_id: int) -> bool:
    """Count a wrong code. True when the user's second factor is now locked."""
    storage = _storage()
    storage.throttle_fail(ip_key(), MAX_FAILURES_PER_IP, FAILURE_WINDOW_SECONDS, LOCK_SECONDS)
    return storage.throttle_fail(totp_key(user_id), MAX_TOTP_FAILURES, FAILURE_WINDOW_SECONDS, LOCK_SECONDS)


def clear_failures(*keys: str) -> None:
    storage = _storage()
    for key in keys:
        storage.throttle_clear(key)


# ── Password helpers ───────────────────────────────────────────────────────────

# Compared against when the user name is unknown, so both paths cost one bcrypt check.
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt()).decode()


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def check_password(plain: str, hashed: Optional[str]) -> bool:
    """Constant-work check: an account without a password still costs one bcrypt run."""
    try:
        ok = bcrypt.checkpw(plain.encode(), (hashed or _DUMMY_HASH).encode())
    except Exception:
        return False
    return bool(ok and hashed)


PASSWORD_POLICY = "At least 12 characters, with an uppercase letter, a lowercase letter, a number and a symbol."


def validate_password_strength(password: str) -> Optional[str]:
    """Returns error message or None if valid."""
    if len(password) < 12:
        return "Password must be at least 12 characters."
    if len(password.encode()) > 72:
        return "Password must be at most 72 bytes."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."
    if all(c.isalnum() for c in password):
        return "Password must contain at least one symbol."
    return None


# ── TOTP helpers ───────────────────────────────────────────────────────────────


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="DarkWebScanner",
    )


def match_totp_step(secret: str, code: str, now: Optional[float] = None) -> Optional[int]:
    """The 30-second step ``code`` belongs to (previous, current or next), or None."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // TOTP_STEP_SECONDS)
    found = None
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * TOTP_STEP_SECONDS), code):
            found = step
    return found


def verify_totp(secret: str, code: str) -> bool:
    """True when ``code`` is valid now. Does not guard against replay; see ``use_totp_code``."""
    return match_totp_step(secret, code) is not None


def use_totp_code(user, code: str) -> bool:
    """Check ``code`` against the user's secret and spend it: a code works once."""
    if not (user.totp_enabled and user.totp_secret):
        return False
    step = match_totp_step(user.totp_secret, code)
    if step is None:
        return False
    return _storage().accept_totp_step(user.id, step)


def generate_totp_qr_base64(secret: str, username: str) -> str:
    """Returns base64-encoded PNG QR code."""
    uri = get_totp_uri(secret, username)
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ── First administrator ────────────────────────────────────────────────────────

MIN_SETUP_TOKEN_LENGTH = 24


def setup_token_configured() -> bool:
    return len(os.getenv("SETUP_TOKEN", "")) >= MIN_SETUP_TOKEN_LENGTH


def setup_token_matches(sent: str) -> bool:
    expected = os.getenv("SETUP_TOKEN", "")
    if len(expected) < MIN_SETUP_TOKEN_LENGTH:
        return False
    return hmac.compare_digest(expected.encode(), (sent or "").strip().encode())
