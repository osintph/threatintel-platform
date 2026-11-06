"""The server-side account commands: list, unlock, reset a second factor."""

import pytest
from click.testing import CliRunner

from darkweb_scanner import main as cli_main
from darkweb_scanner.auth import (
    FAILURE_WINDOW_SECONDS,
    LOCK_SECONDS,
    MAX_PASSWORD_FAILURES_PER_ACCOUNT,
    MAX_TOTP_FAILURES,
    account_key,
    ip_key,
    totp_key,
)
from tests.helpers import TOTP_SECRET, make_user


@pytest.fixture
def run(monkeypatch, db):
    monkeypatch.setattr(cli_main, "Storage", lambda: db)
    runner = CliRunner()
    return lambda *args: runner.invoke(cli_main.cli, list(args))


def _lock(db, key, limit):
    for _ in range(limit):
        db.throttle_fail(key, limit, FAILURE_WINDOW_SECONDS, LOCK_SECONDS)
    assert db.throttle_locked_seconds(key) > 0


def test_user_list_shows_accounts_and_locks_but_no_secrets(run, db):
    uid = make_user(db, "alice", admin=True)
    make_user(db, "bob", mfa=False, must_change_password=True)
    _lock(db, account_key("alice"), MAX_PASSWORD_FAILURES_PER_ACCOUNT)

    result = run("user-list")

    assert result.exit_code == 0, result.output
    assert "alice" in result.output and "bob" in result.output
    assert "password, user name alice" in result.output
    user = db.get_user_by_id(uid)
    assert TOTP_SECRET not in result.output and user.password_hash not in result.output


def test_user_unlock_lifts_password_code_and_address_locks(run, db):
    uid = make_user(db, "Alice")
    _lock(db, account_key("alice"), MAX_PASSWORD_FAILURES_PER_ACCOUNT)
    _lock(db, totp_key(uid), MAX_TOTP_FAILURES)
    _lock(db, ip_key("203.0.113.9"), 3)

    result = run("user-unlock", "Alice", "--address", "203.0.113.9")

    assert result.exit_code == 0, result.output
    assert db.throttle_locks() == []
    assert db.list_auth_events()[0]["event"] == "unlock"


def test_user_unlock_leaves_other_locks_alone(run, db):
    make_user(db, "alice")
    _lock(db, account_key("mallory"), MAX_PASSWORD_FAILURES_PER_ACCOUNT)
    _lock(db, ip_key("203.0.113.9"), 3)

    assert run("user-unlock", "alice").exit_code == 0
    assert {lock["key"] for lock in db.throttle_locks()} == {"user:mallory", "ip:203.0.113.9"}


def test_user_reset_mfa_removes_the_factor_and_ends_sessions(run, db):
    uid = make_user(db, "alice")
    before = db.ensure_session_version(uid)
    _lock(db, totp_key(uid), MAX_TOTP_FAILURES)

    result = run("user-reset-mfa", "alice", "--yes")

    assert result.exit_code == 0, result.output
    user = db.get_user_by_id(uid)
    assert not user.totp_enabled and user.totp_secret is None
    assert db.get_session_version(uid) != before
    assert db.throttle_locked_seconds(totp_key(uid)) == 0
    assert db.list_auth_events()[0]["event"] == "mfa_reset"


def test_user_reset_mfa_asks_first(run, db):
    uid = make_user(db, "alice")
    result = run("user-reset-mfa", "alice")  # no --yes and no terminal: aborted
    assert result.exit_code != 0
    assert db.get_user_by_id(uid).totp_enabled


@pytest.mark.parametrize(
    "command", [("user-unlock", "nobody"), ("user-reset-mfa", "nobody", "--yes")]
)
def test_unknown_user_is_an_error(run, command):
    result = run(*command)
    assert result.exit_code == 1
    assert "No user named" in result.output
