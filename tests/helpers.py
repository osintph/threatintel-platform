"""Shared helpers for tests that need a signed-in user."""

import time

from darkweb_scanner.dashboard import storage_helper
from darkweb_scanner.storage import Storage

CSRF = "test-csrf-token"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def use_storage(monkeypatch, storage: Storage) -> Storage:
    """Make ``storage`` the one the app and the auth layer use."""
    monkeypatch.setattr(storage_helper, "_storage", storage)
    return storage


def make_user(
    storage: Storage,
    username: str = "tester",
    admin: bool = False,
    mfa: bool = True,
    must_change_password: bool = False,
) -> int:
    """Create a user as the app would hold one after enrolment. Returns the id."""
    from darkweb_scanner.auth import hash_password

    user_id = storage.create_user(
        username=username,
        password_hash=hash_password("Correct-Horse-9!"),
        is_admin=admin,
        must_change_password=must_change_password,
    )
    if mfa:
        storage.enable_totp(user_id, TOTP_SECRET)
    return user_id


def sign_in(client, storage: Storage, user_id: int) -> dict:
    """Give ``client`` a valid session for ``user_id``. Returns headers that carry the CSRF token."""
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = storage.get_user_by_id(user_id).username
        sess["sv"] = storage.ensure_session_version(user_id)
        sess["iat"] = int(time.time())
        sess["_csrf"] = CSRF
    return {"X-CSRF-Token": CSRF}


def login_as(client, storage: Storage | None = None, user_id: int = 1, admin: bool = True) -> dict:
    """Sign ``client`` in as the user with ``user_id``, creating users up to that id when missing."""
    storage = storage or storage_helper.get_storage()
    while storage.get_user_by_id(user_id) is None:
        make_user(storage, username=f"user{storage.count_users() + 1}", admin=admin)
    return sign_in(client, storage, user_id)
