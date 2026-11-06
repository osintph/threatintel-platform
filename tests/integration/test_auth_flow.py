"""
Sign-in, sessions and the second factor, through the real application (create_app).

Covers AUTH-1 (throttling and lockout, event log), AUTH-2 (MFA enforced from the
database), AUTH-3 (sessions can be ended), AUTH-4 (cookie flags and CSRF),
AUTH-5 (re-enrolment needs a current code, codes work once, pending secret held
on the server), AUTH-6 (first admin needs a setup token; no silent database
fallback) and AUTH-8 (smaller gaps).
"""

import re
import time

import pyotp
import pytest

from darkweb_scanner import auth
from darkweb_scanner.dashboard.auth_routes import _safe_next
from darkweb_scanner.storage import Storage
from tests.helpers import CSRF, TOTP_SECRET, make_user, sign_in
from tests.integration._app_fixtures import SETUP_TOKEN

PASSWORD = "Correct-Horse-9!"


def _token(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _form_token(client, path: str = "/login") -> str:
    return _token(client.get(path).get_data(as_text=True))


def _code(offset_steps: int = 0, secret: str = TOTP_SECRET) -> str:
    return pyotp.TOTP(secret).at(time.time() + 30 * offset_steps)


def _password_step(client, username: str = "tester", password: str = PASSWORD):
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": _form_token(client)},
    )


def _events(db) -> list[str]:
    return [e["event"] for e in db.list_auth_events()]


# ── AUTH-6: first administrator ────────────────────────────────────────────────


def test_first_admin_needs_the_setup_token(client, db):
    token = _form_token(client, "/register")
    form = {
        "username": "admin",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
        "csrf_token": token,
    }

    assert client.post("/register", data=form).status_code == 403
    assert client.post("/register", data={**form, "setup_token": "wrong-token"}).status_code == 403
    assert db.count_users() == 0
    assert "setup_failed" in _events(db)

    resp = client.post("/register", data={**form, "setup_token": SETUP_TOKEN})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/totp/setup")
    user = db.get_user_by_username("admin")
    assert user.is_admin and not user.totp_enabled


def test_registration_is_off_without_a_configured_token(client, db, monkeypatch):
    monkeypatch.delenv("SETUP_TOKEN")
    page = client.get("/register")
    assert page.status_code == 403
    assert "SETUP_TOKEN" in page.get_data(as_text=True)
    with client.session_transaction() as sess:
        sess["_csrf"] = CSRF
    form = {
        "username": "admin",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
        "csrf_token": CSRF,
    }
    assert client.post("/register", data={**form, "setup_token": ""}).status_code == 403
    assert db.count_users() == 0


def test_registration_is_closed_once_a_user_exists(client, db):
    make_user(db, "someone")
    token = _form_token(client)
    resp = client.post(
        "/register",
        data={
            "username": "evil",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "setup_token": SETUP_TOKEN,
            "csrf_token": token,
        },
    )
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")
    assert db.get_user_by_username("evil") is None


def test_no_database_url_is_an_error_not_an_empty_sqlite_file(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        Storage()


# ── AUTH-1: throttling, lockout, event log ─────────────────────────────────────


def test_wrong_passwords_lock_the_account_and_the_right_one_is_then_refused(client, db):
    make_user(db)
    for _ in range(auth.MAX_PASSWORD_FAILURES_PER_ACCOUNT):
        assert _password_step(client, password="wrong").status_code == 200

    locked = _password_step(client)  # the right password
    assert locked.status_code == 429
    assert "Too many failed attempts" in locked.get_data(as_text=True)
    events = db.list_auth_events()
    assert [e["event"] for e in events].count(
        "login_failed"
    ) == auth.MAX_PASSWORD_FAILURES_PER_ACCOUNT
    assert events[0]["event"] == "login_blocked"
    assert all(e["ip"] == "127.0.0.1" for e in events)


def test_lockout_answer_is_the_same_for_names_that_do_not_exist(client, db):
    make_user(db)
    for _ in range(auth.MAX_PASSWORD_FAILURES_PER_ACCOUNT):
        assert _password_step(client, username="nobody", password="wrong").status_code == 200
    assert _password_step(client, username="nobody", password="wrong").status_code == 429


def test_failures_from_one_address_block_that_address(client, db):
    make_user(db)
    for i in range(auth.MAX_FAILURES_PER_IP):
        _password_step(client, username=f"name{i}", password="wrong")
    assert _password_step(client).status_code == 429  # right password, other account, same address
    assert (
        _password_step_from(client, "203.0.113.9").status_code == 302
    )  # another address is not affected


def _password_step_from(client, ip: str):
    token = _form_token(client)
    return client.post(
        "/login",
        data={"username": "tester", "password": PASSWORD, "csrf_token": token},
        environ_overrides={"REMOTE_ADDR": ip},
    )


def test_a_lock_ends_after_the_lock_period(client, db, monkeypatch):
    make_user(db)
    for _ in range(auth.MAX_PASSWORD_FAILURES_PER_ACCOUNT):
        _password_step(client, password="wrong")
    assert _password_step(client).status_code == 429

    from darkweb_scanner import storage as storage_module

    real_now = storage_module._utcnow
    from datetime import timedelta

    monkeypatch.setattr(
        storage_module, "_utcnow", lambda: real_now() + timedelta(seconds=auth.LOCK_SECONDS + 1)
    )
    assert _password_step(client).status_code == 302


def test_five_wrong_codes_drop_the_pending_sign_in_and_lock_the_second_step(client, db):
    uid = make_user(db)
    assert _password_step(client).headers["Location"].startswith("/totp/verify")
    token = _form_token(client, "/totp/verify")

    for attempt in range(auth.MAX_TOTP_FAILURES):
        resp = client.post("/totp/verify", data={"code": "000000", "csrf_token": token})
    # The last wrong code ends the pending state: back to the password step.
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")
    assert client.get("/totp/verify").status_code == 302

    # During the lock a correct password plus a correct code does not get in.
    assert _password_step(client).headers["Location"].startswith("/totp/verify")
    token = _form_token(client, "/totp/verify")
    resp = client.post("/totp/verify", data={"code": _code(), "csrf_token": token})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")
    assert client.get("/api/stats").status_code == 401
    assert db.throttle_locked_seconds(auth.totp_key(uid)) > 0
    assert {"mfa_failed", "mfa_blocked"} <= set(_events(db))


def test_successful_sign_in_is_logged_with_the_client_address(client, db):
    make_user(db)
    _password_step(client)
    token = _form_token(client, "/totp/verify")
    resp = client.post(
        "/totp/verify",
        data={"code": _code(), "csrf_token": token},
        headers={"X-Forwarded-For": "198.51.100.7"},
    )
    assert resp.status_code == 302
    event = db.list_auth_events()[0]
    assert (event["event"], event["username"], event["ip"]) == (
        "login_ok",
        "tester",
        "198.51.100.7",
    )


# ── AUTH-2: MFA is enforced from the database ──────────────────────────────────


def test_enrolment_cannot_be_skipped_by_signing_in_again(client, db):
    make_user(db, mfa=False)
    assert _password_step(client).status_code == 302
    assert client.get("/dashboard").headers["Location"].endswith("/totp/setup")
    assert client.get("/api/stats").get_json() == {"error": "mfa_setup_required"}

    client.post("/logout", data={"csrf_token": _form_token(client, "/totp/setup")})
    assert _password_step(client).status_code == 302
    assert client.get("/dashboard").headers["Location"].endswith("/totp/setup")
    assert client.get("/api/stats").status_code == 403


def test_setup_page_has_no_skip_link(client, db):
    make_user(db, mfa=False)
    _password_step(client)
    page = client.get("/totp/setup").get_data(as_text=True)
    assert "Skip" not in page


def test_temporary_password_must_be_changed_before_anything_else(client, db):
    uid = make_user(db, admin=True, must_change_password=True)
    headers = sign_in(client, db, uid)
    assert client.get("/dashboard").headers["Location"].endswith("/force-change-password")
    # require_admin applies the same gates as require_login.
    assert client.get("/api/users").get_json() == {"error": "password_change_required"}
    resp = client.post(
        "/api/users", json={"username": "x-user", "password": PASSWORD}, headers=headers
    )
    assert resp.status_code == 403 and db.get_user_by_username("x-user") is None


def test_disabling_mfa_needs_password_and_a_current_code(client, db):
    uid = make_user(db)
    headers = sign_in(client, db, uid)
    url = "/api/settings/totp/disable"

    assert client.post(url, json={"password": PASSWORD}, headers=headers).status_code == 400
    assert client.post(url, json={"totp_code": _code()}, headers=headers).status_code == 400
    assert db.get_user_by_id(uid).totp_enabled

    # The password is checked first, so the code above was not spent by that attempt.
    assert (
        client.post(
            url, json={"password": PASSWORD, "totp_code": _code()}, headers=headers
        ).status_code
        == 200
    )
    assert not db.get_user_by_id(uid).totp_enabled
    # MFA is mandatory: the same session is now sent to enrolment.
    assert client.get("/api/stats").get_json() == {"error": "mfa_setup_required"}


# ── AUTH-3: sessions can be ended ──────────────────────────────────────────────


def _clone_session(full_app, client):
    """A second client carrying a copy of the first client's session cookie."""
    other = full_app.test_client()
    cookie = client.get_cookie("__Host-session")
    other.set_cookie("__Host-session", cookie.value)
    return other


def test_deleting_a_user_ends_their_session(full_app, client, db):
    admin = make_user(db, "boss", admin=True)
    victim = make_user(db, "leaver")
    leaver = full_app.test_client()
    sign_in(leaver, db, victim)
    assert leaver.get("/api/stats").status_code == 200

    headers = sign_in(client, db, admin)
    assert client.delete(f"/api/users/{victim}", headers=headers).status_code == 200
    assert leaver.get("/api/stats").status_code == 401
    assert (
        leaver.post(
            "/api/keywords", json={"keyword": "x"}, headers={"X-CSRF-Token": CSRF}
        ).status_code
        == 401
    )


def test_a_cookie_saved_before_sign_out_is_dead(full_app, client, db):
    uid = make_user(db)
    headers = sign_in(client, db, uid)
    saved = _clone_session(full_app, client)
    assert saved.get("/api/stats").status_code == 200

    assert client.post("/logout", headers=headers).status_code == 302
    assert saved.get("/api/stats").status_code == 401


def test_password_change_ends_other_sessions_and_keeps_this_one(full_app, client, db):
    uid = make_user(db)
    headers = sign_in(client, db, uid)
    other = _clone_session(full_app, client)

    resp = client.post(
        "/api/settings/password",
        json={
            "current_password": PASSWORD,
            "new_password": "Another-Horse-10!",
            "confirm_password": "Another-Horse-10!",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    assert client.get("/api/stats").status_code == 200
    assert other.get("/api/stats").status_code == 401


def test_password_change_needs_the_current_password(client, db):
    uid = make_user(db)
    headers = sign_in(client, db, uid)
    resp = client.post(
        "/api/settings/password",
        json={
            "current_password": "wrong",
            "new_password": "Another-Horse-10!",
            "confirm_password": "Another-Horse-10!",
        },
        headers=headers,
    )
    assert resp.status_code == 400
    assert auth.check_password(PASSWORD, db.get_user_by_id(uid).password_hash)


def test_session_ends_twelve_hours_after_sign_in(client, db):
    uid = make_user(db)
    sign_in(client, db, uid)
    with client.session_transaction() as sess:
        sess["iat"] = int(time.time()) - auth.SESSION_MAX_AGE_SECONDS - 5
    assert client.get("/api/stats").status_code == 401


def test_cookie_from_before_the_upgrade_is_not_a_session(client, db):
    uid = make_user(db)
    with client.session_transaction() as sess:  # what 1.1.x stored
        sess["logged_in"] = True
        sess["user_id"] = uid
        sess["username"] = "tester"
    assert client.get("/api/stats").status_code == 401


def test_admin_flag_is_read_from_the_database_on_every_request(client, db):
    uid = make_user(db, admin=True)
    sign_in(client, db, uid)
    assert client.get("/api/users").status_code == 200
    with db.get_session() as session:
        from darkweb_scanner.storage import User

        session.get(User, uid).is_admin = False
        session.commit()
    assert client.get("/api/users").status_code == 403


# ── AUTH-4: cookie flags and CSRF ──────────────────────────────────────────────


def test_session_cookie_flags(client, db):
    make_user(db)
    cookie = client.get("/login").headers["Set-Cookie"]
    assert cookie.startswith("__Host-session=")
    for flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
        assert flag in cookie
    assert "Domain=" not in cookie


@pytest.mark.parametrize(
    "path", ["/api/crawl/stop", "/api/paste/scan", "/api/keywords/import", "/api/proxy/urlhaus"]
)
def test_state_changing_requests_need_the_token(client, db, path):
    sign_in(client, db, make_user(db, admin=True))
    resp = client.post(path)
    assert resp.status_code == 403 and resp.get_json()["error"] == "csrf"
    assert client.post(path, headers={"X-CSRF-Token": "not-the-token"}).status_code == 403


def test_a_request_from_another_origin_is_refused_even_with_the_token(client, db, data_dir):
    headers = sign_in(client, db, make_user(db, admin=True))
    evil = client.post(
        "/api/crawl/stop", headers={**headers, "Origin": "https://webcheck.osintph.info"}
    )
    assert evil.status_code == 403
    assert not (data_dir / "crawl.stop").exists()
    same = client.post("/api/crawl/stop", headers={**headers, "Origin": "http://localhost"})
    assert same.status_code == 200


def test_logout_is_post_only(client, db):
    sign_in(client, db, make_user(db))
    assert client.get("/logout").status_code == 405
    assert client.get("/api/stats").status_code == 200


def test_login_form_needs_the_token(client, db):
    make_user(db, mfa=False)
    client.get("/login")
    resp = client.post("/login", data={"username": "tester", "password": PASSWORD})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")
    assert client.get("/api/stats").status_code == 401


# ── AUTH-5: re-enrolment, replay, pending secret ───────────────────────────────


def test_a_code_works_once(full_app, client, db):
    make_user(db)
    code = _code()
    _password_step(client)
    token = _form_token(client, "/totp/verify")
    assert (
        client.post("/totp/verify", data={"code": code, "csrf_token": token}).headers["Location"]
        == "/dashboard"
    )

    second = full_app.test_client()
    _password_step(second)
    token = _form_token(second, "/totp/verify")
    replay = second.post("/totp/verify", data={"code": code, "csrf_token": token})
    assert replay.status_code == 200 and "Invalid code" in replay.get_data(as_text=True)
    assert second.get("/api/stats").status_code == 401


def test_replacing_the_second_factor_needs_a_code_from_the_current_one(client, db):
    uid = make_user(db)
    sign_in(client, db, uid)
    page = client.get("/totp/setup").get_data(as_text=True)
    new_secret = re.search(r'class="secret-box">([A-Z2-7]+)<', page).group(1)
    token = _token(page)
    assert 'name="current_code"' in page

    without = client.post(
        "/totp/setup", data={"code": _code(secret=new_secret), "csrf_token": token}
    )
    assert without.status_code == 400
    assert db.get_user_by_id(uid).totp_secret == TOTP_SECRET

    with_current = client.post(
        "/totp/setup",
        data={"current_code": _code(), "code": _code(secret=new_secret), "csrf_token": token},
    )
    assert with_current.status_code == 302
    assert db.get_user_by_id(uid).totp_secret == new_secret
    assert "mfa_replaced" in _events(db)


def test_pending_secret_is_not_in_the_cookie(client, db):
    uid = make_user(db, mfa=False)
    sign_in(client, db, uid)
    page = client.get("/totp/setup").get_data(as_text=True)
    secret = re.search(r'class="secret-box">([A-Z2-7]+)<', page).group(1)
    with client.session_transaction() as sess:
        assert "totp_setup_secret" not in sess
        assert secret not in repr(dict(sess))
    assert db.get_pending_totp_secret(uid, 60) == secret
    # A reload shows the same secret instead of issuing another one.
    assert secret in client.get("/totp/setup").get_data(as_text=True)


def test_enrolment_code_cannot_be_reused_to_sign_in(full_app, client, db):
    uid = make_user(db, mfa=False)
    sign_in(client, db, uid)
    page = client.get("/totp/setup").get_data(as_text=True)
    secret = re.search(r'class="secret-box">([A-Z2-7]+)<', page).group(1)
    code = _code(secret=secret)
    assert (
        client.post("/totp/setup", data={"code": code, "csrf_token": _token(page)}).status_code
        == 302
    )

    other = full_app.test_client()
    _password_step(other)
    token = _form_token(other, "/totp/verify")
    assert other.post("/totp/verify", data={"code": code, "csrf_token": token}).status_code == 200
    assert other.get("/api/stats").status_code == 401


# ── AUTH-8: smaller gaps ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "next_url",
    ["/\\evil.example", "/\\\\evil.example", "/x\ny", "//evil.example", "https://evil.example"],
)
def test_safe_next_rejects_paths_a_browser_reads_as_another_host(next_url):
    assert _safe_next(next_url, "/default") == "/default"


@pytest.mark.parametrize(
    "password,ok",
    [
        ("Correct-Horse-9!", True),
        ("Short-9!a", False),  # under 12 characters
        ("correct-horse-99!", False),  # no uppercase
        ("CORRECT-HORSE-99!", False),  # no lowercase
        ("Correct-Horse-!!", False),  # no digit
        ("CorrectHorse999", False),  # no symbol
    ],
)
def test_password_policy_matches_what_the_pages_promise(password, ok):
    assert (auth.validate_password_strength(password) is None) is ok


def test_unknown_user_costs_one_bcrypt_check_like_a_known_one(monkeypatch):
    calls = []
    real = auth.bcrypt.checkpw
    monkeypatch.setattr(auth.bcrypt, "checkpw", lambda p, h: calls.append(1) or real(p, h))
    assert auth.check_password("whatever", None) is False
    assert calls == [1]


def test_short_secret_key_is_refused(monkeypatch):
    monkeypatch.setenv("DASHBOARD_SECRET_KEY", "short-secret")
    from darkweb_scanner.dashboard.app import create_app

    with pytest.raises(RuntimeError, match="DASHBOARD_SECRET_KEY"):
        create_app()
