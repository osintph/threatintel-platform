"""
Channel Monitor routes: AZ-1 (public channels only), AZ-2 (jobs have an owner),
D-11 (admin-only, archives deleted after 90 days).

No Telegram and no translator are involved: the worker thread is replaced, and
where the worker itself is under test the Telegram client is a stand-in.
"""

import os
import time
from types import SimpleNamespace

import pytest
import telethon
from flask import Blueprint, Flask
from telethon.tl.types import User

from darkweb_scanner import channel_monitor as cm
from darkweb_scanner.dashboard import channel_monitor_routes as routes
from darkweb_scanner.dashboard.storage_helper import close_db
from darkweb_scanner.storage import Storage
from tests.helpers import make_user, sign_in, use_storage

DAY = 86400
JOB_ROUTES = [
    ("GET", "/api/channel-monitor/credentials"),
    ("GET", "/api/channel-monitor/jobs"),
    ("GET", "/api/channel-monitor/jobs/0123456789ab"),
    ("GET", "/api/channel-monitor/jobs/0123456789ab/log"),
    ("GET", "/api/channel-monitor/jobs/0123456789ab/download"),
    ("DELETE", "/api/channel-monitor/jobs/0123456789ab"),
    ("POST", "/api/channel-monitor/start"),
]


@pytest.fixture
def storage(monkeypatch):
    return use_storage(monkeypatch, Storage("sqlite:///:memory:"))


@pytest.fixture
def started(monkeypatch):
    """Arguments of every worker start; no thread is created."""
    calls = []
    monkeypatch.setattr(routes, "_start_worker", lambda *args: calls.append(args))
    return calls


@pytest.fixture
def cm_dir(tmp_path, monkeypatch, started):
    """An empty Channel Monitor folder and job store, and fixed credentials."""
    folder = tmp_path / "channel_monitor"
    monkeypatch.setattr(routes, "CHANNEL_MONITOR_DIR", folder)
    monkeypatch.setattr(routes, "_jobs", {})
    monkeypatch.setattr(routes, "_last_purge", None)
    monkeypatch.setattr(
        routes,
        "_get_telegram_creds",
        lambda: {"api_id": "1", "api_hash": "h", "phone": "+10000000000"},
    )
    return folder


@pytest.fixture
def app(storage, cm_dir):
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-channel-monitor-secret"
    flask_app.teardown_appcontext(close_db)

    # Stub auth blueprint so the redirect targets of the auth decorators resolve.
    auth_bp = Blueprint("auth", __name__)
    for name in ("login", "force_change_password", "totp_setup"):
        auth_bp.add_url_rule(f"/{name}", name, lambda: ("", 200))

    flask_app.register_blueprint(auth_bp)
    flask_app.register_blueprint(routes.channel_monitor_bp)
    return flask_app


@pytest.fixture
def admin(app, storage):
    client = app.test_client()
    user_id = make_user(storage, "admin", admin=True)
    client.headers = sign_in(client, storage, user_id)
    client.user_id = user_id
    return client


def _start(client, **body):
    return client.post("/api/channel-monitor/start", json=body, headers=client.headers)


def _add_job(job_id, owner_id, status="completed", channel="durov"):
    folder = routes.CHANNEL_MONITOR_DIR / job_id
    (folder / channel).mkdir(parents=True)
    (folder / channel / "messages.json").write_text("[]")
    routes._jobs[job_id] = {
        "status": status,
        "config": {"channel": channel},
        "owner_id": owner_id,
        "owner": f"user{owner_id}",
        "output_dir": str(folder),
        "started_at": "2026-11-06T00:00:00",
        "ended_at": None,
        "log": ["line 1", "line 2"],
        "error": None,
    }
    return folder


def _age(path, days):
    then = time.time() - days * DAY
    for p in [path, *path.rglob("*")] if path.is_dir() else [path]:
        os.utime(p, (then, then))


# ── D-11: admin only ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("method,path", JOB_ROUTES)
def test_signed_out_requests_get_401(app, method, path):
    resp = app.test_client().open(path, method=method, json={})
    assert resp.status_code == 401


@pytest.mark.parametrize("method,path", JOB_ROUTES)
def test_non_admin_gets_403_on_every_route(app, storage, cm_dir, started, method, path):
    client = app.test_client()
    user_id = make_user(storage, "analyst", admin=False)
    headers = sign_in(client, storage, user_id)
    _add_job("0123456789ab", owner_id=user_id)

    resp = client.open(path, method=method, json={"channel": "durov"}, headers=headers)

    assert resp.status_code == 403
    assert resp.get_json() == {"error": "admin required"}
    assert started == [] and (cm_dir / "0123456789ab").exists()


def test_status_endpoint_states_the_policy(admin):
    data = admin.get("/api/channel-monitor/credentials").get_json()
    assert data["configured"] is True
    assert data["translation"] == "google"
    assert data["retention_days"] == 90 == routes.RETENTION_DAYS
    assert data["public_channels_only"] is True


# ── AZ-1: public channels only ─────────────────────────────────────────────────


@pytest.mark.parametrize("ref", ["@durov", "durov", "https://t.me/durov", "t.me/s/durov"])
def test_public_channel_starts_a_job_owned_by_the_caller(admin, started, ref):
    resp = _start(admin, channel=ref)

    assert resp.status_code == 200
    job_id = resp.get_json()["job_id"]
    job = routes._jobs[job_id]
    assert job["config"]["channel"] == "durov"
    assert (job["owner_id"], job["owner"]) == (admin.user_id, "admin")
    assert len(started) == 1 and started[0][0] == job_id


@pytest.mark.parametrize(
    "ref",
    [
        "me",
        "+79990000000",
        "https://t.me/+AbCd",
        "https://t.me/joinchat/x",
        "-1001234567890",
        "12345",
        12345,
        "a b",
        "a" * 300,
        "",
        None,
    ],
)
def test_anything_but_a_public_channel_is_refused(admin, cm_dir, started, ref):
    resp = _start(admin, channel=ref)

    assert resp.status_code == 400
    assert "public channel" in resp.get_json()["error"]
    assert routes._jobs == {} and started == []
    assert not cm_dir.exists(), "no job folder is created for a refused request"


@pytest.mark.parametrize(
    "field,value",
    [
        ("limit", "abc"),
        ("limit", "200"),
        ("limit", True),
        ("limit", 1.5),
        ("days", "soon"),
        ("max_video_mb", [50]),
        ("min_space_gb", "1"),
        ("min_space_gb", True),
        ("lang", "xx"),
        ("lang", 5),
        ("skip_english", "false"),
        ("translate", 0),
    ],
)
def test_wrong_types_are_refused(admin, cm_dir, field, value):
    resp = _start(admin, channel="durov", **{field: value})
    assert resp.status_code == 400
    assert field in resp.get_json()["error"]
    assert routes._jobs == {}


@pytest.mark.parametrize("body", [[1, 2], "durov", None])
def test_body_must_be_a_json_object(admin, body):
    resp = admin.post("/api/channel-monitor/start", json=body, headers=admin.headers)
    assert resp.status_code == 400


def test_numbers_are_clamped_and_defaults_applied(admin):
    resp = _start(
        admin,
        channel="durov",
        limit=10**8,
        days=0,
        max_video_mb=99999,
        min_space_gb=0.01,
        lang="RU",
        skip_english=True,
        translate=False,
    )
    config = routes._jobs[resp.get_json()["job_id"]]["config"]
    assert config == {
        "channel": "durov",
        "limit": routes.MAX_LIMIT,
        "days": None,
        "lang": "ru",
        "max_video_mb": routes.MAX_VIDEO_MB,
        "min_space_gb": routes.MIN_SPACE_GB,
        "skip_english": True,
        "translate": False,
    }

    resp = _start(admin, channel="durov")
    config = routes._jobs[resp.get_json()["job_id"]]["config"]
    assert (config["limit"], config["days"], config["lang"], config["max_video_mb"]) == (
        200,
        None,
        None,
        50,
    )
    assert (config["min_space_gb"], config["skip_english"], config["translate"]) == (
        1.0,
        False,
        True,
    )


class _FakeTelegramClient:
    """What the worker needs from TelegramClient; resolves every name to ``entity``."""

    entity = None
    read = 0

    def __init__(self, *args, **kwargs):
        pass

    async def start(self, phone=None):
        return self

    async def get_me(self):
        return SimpleNamespace(username="monitor_account", first_name="Monitor")

    async def get_entity(self, ref):
        return type(self).entity

    async def iter_messages(self, channel, limit=None):
        type(self).read += 1
        yield None

    async def disconnect(self):
        pass


async def test_job_fails_before_reading_when_the_name_is_not_a_public_channel(cm_dir, monkeypatch):
    _FakeTelegramClient.entity = User(id=1, username="alice_account")
    _FakeTelegramClient.read = 0
    monkeypatch.setattr(telethon, "TelegramClient", _FakeTelegramClient)
    folder = _add_job("0123456789ab", owner_id=1, status="running", channel="alice_account")
    config = {
        "channel": "alice_account",
        "limit": 10,
        "days": None,
        "lang": None,
        "max_video_mb": 50,
        "min_space_gb": 1.0,
        "skip_english": False,
        "translate": True,
    }

    await routes._run_channel_monitor("0123456789ab", config, folder, routes._get_telegram_creds())

    job = routes._jobs["0123456789ab"]
    assert job["status"] == "error"
    assert "not a channel" in job["error"] and "Only public channels" in job["error"]
    assert _FakeTelegramClient.read == 0
    assert not any("Traceback" in line for line in job["log"])


# ── AZ-2: jobs have an owner ───────────────────────────────────────────────────


def test_job_access_is_owner_or_admin():
    job = {"owner_id": 7}
    assert routes._can_access(job, SimpleNamespace(id=7, is_admin=False))
    assert routes._can_access(job, SimpleNamespace(id=8, is_admin=True))
    assert not routes._can_access(job, SimpleNamespace(id=8, is_admin=False))
    assert not routes._can_access(job, None)
    assert not routes._can_access({}, SimpleNamespace(id=8, is_admin=False))


def test_another_users_job_is_hidden_from_a_non_owner(cm_dir, monkeypatch):
    _add_job("0123456789ab", owner_id=7)
    monkeypatch.setattr(routes, "current_user", lambda: SimpleNamespace(id=8, is_admin=False))
    assert routes._get_job("0123456789ab") is None
    monkeypatch.setattr(routes, "current_user", lambda: SimpleNamespace(id=7, is_admin=False))
    assert routes._get_job("0123456789ab")["owner_id"] == 7


def test_admin_sees_other_admins_jobs_with_their_owner(admin, cm_dir):
    _add_job("0123456789ab", owner_id=admin.user_id + 1)

    listed = admin.get("/api/channel-monitor/jobs").get_json()
    assert [(j["id"], j["owner"]) for j in listed] == [("0123456789ab", f"user{admin.user_id + 1}")]
    assert (
        admin.get("/api/channel-monitor/jobs/0123456789ab").get_json()["owner"]
        == f"user{admin.user_id + 1}"
    )


def test_running_job_cannot_be_deleted(admin, cm_dir):
    folder = _add_job("0123456789ab", owner_id=admin.user_id, status="running")

    resp = admin.delete("/api/channel-monitor/jobs/0123456789ab", headers=admin.headers)

    assert resp.status_code == 409
    assert folder.exists() and "0123456789ab" in routes._jobs

    routes._jobs["0123456789ab"]["status"] = "completed"
    resp = admin.delete("/api/channel-monitor/jobs/0123456789ab", headers=admin.headers)
    assert resp.status_code == 200
    assert not folder.exists() and routes._jobs == {}


@pytest.mark.parametrize(
    "job_id", ["..", "ABCDEFABCDEF", "0123456789abc", "0123456789a", "zzzzzzzzzzzz", "fedcba987654"]
)
@pytest.mark.parametrize(
    "suffix,method", [("", "GET"), ("/log", "GET"), ("/download", "GET"), ("", "DELETE")]
)
def test_malformed_or_unknown_job_id_is_404(admin, cm_dir, job_id, suffix, method):
    _add_job("0123456789ab", owner_id=admin.user_id)
    # A job stored under a name that is not a job id must stay out of reach.
    routes._jobs[".."] = dict(routes._jobs["0123456789ab"], output_dir=str(cm_dir))

    resp = admin.open(
        f"/api/channel-monitor/jobs/{job_id}{suffix}", method=method, headers=admin.headers
    )

    assert resp.status_code == 404
    assert cm_dir.exists() and (cm_dir / "0123456789ab").exists()


def test_log_offset_that_is_not_a_number_is_ignored(admin, cm_dir):
    _add_job("0123456789ab", owner_id=admin.user_id)
    resp = admin.get("/api/channel-monitor/jobs/0123456789ab/log?since=abc")
    assert resp.status_code == 200
    assert resp.get_json()["log"] == ["line 1", "line 2"]
    assert admin.get("/api/channel-monitor/jobs/0123456789ab/log?since=-5").get_json()["log"] == [
        "line 1",
        "line 2",
    ]


# ── D-11: retention ────────────────────────────────────────────────────────────


def test_archives_older_than_90_days_are_deleted(cm_dir):
    expired = _add_job("aaaaaaaaaaaa", owner_id=1)
    recent = _add_job("bbbbbbbbbbbb", owner_id=1)
    running = _add_job("cccccccccccc", owner_id=1, status="running")
    orphan = cm_dir / "dddddddddddd" / "durov"  # left on disk by an earlier process, no job entry
    orphan.mkdir(parents=True)
    touched = _add_job("eeeeeeeeeeee", owner_id=1)
    session = cm_dir / "channel_monitor.session"
    session.write_text("session")
    other = cm_dir / "notes"
    other.mkdir()
    old_zip = cm_dir / "cm_download_old.zip"
    old_zip.write_text("zip")
    new_zip = cm_dir / "cm_download_new.zip"
    new_zip.write_text("zip")

    for path, days in [
        (expired, 91),
        (recent, 89),
        (running, 91),
        (orphan.parent, 400),
        (touched, 91),
        (session, 400),
        (other, 400),
        (old_zip, 91),
        (new_zip, 1),
    ]:
        _age(path, days)
    (touched / "durov" / "messages.json").write_text(
        "[1]"
    )  # a file changed yesterday keeps the folder

    removed = routes.purge_expired_archives()

    assert sorted(removed) == ["aaaaaaaaaaaa", "cm_download_old.zip", "dddddddddddd"]
    assert not expired.exists() and not orphan.parent.exists() and not old_zip.exists()
    for kept in (recent, running, touched, session, other, new_zip):
        assert kept.exists(), kept.name
    assert sorted(routes._jobs) == ["bbbbbbbbbbbb", "cccccccccccc", "eeeeeeeeeeee"]


def test_sweep_runs_with_the_job_list_at_most_once_an_hour(admin, cm_dir, monkeypatch):
    expired = _add_job("aaaaaaaaaaaa", owner_id=admin.user_id)
    _age(expired, 91)

    assert admin.get("/api/channel-monitor/jobs").get_json() == []
    assert not expired.exists()

    calls = []
    monkeypatch.setattr(routes, "purge_expired_archives", lambda: calls.append(1))
    admin.get("/api/channel-monitor/jobs")
    _start(admin, channel="durov")
    assert calls == []

    monkeypatch.setattr(
        routes, "_last_purge", time.monotonic() - routes._PURGE_INTERVAL_SECONDS - 1
    )
    _start(admin, channel="durov")
    assert calls == [1]


def test_sweep_with_no_folder_does_nothing(cm_dir):
    assert not cm_dir.exists()
    assert routes.purge_expired_archives() == []


def test_retention_period_can_be_set_in_the_environment(monkeypatch):
    monkeypatch.setenv("CHANNEL_MONITOR_RETENTION_DAYS", "30")
    assert routes._env_int("CHANNEL_MONITOR_RETENTION_DAYS", 90, minimum=1) == 30
    monkeypatch.setenv("CHANNEL_MONITOR_RETENTION_DAYS", "0")
    assert routes._env_int("CHANNEL_MONITOR_RETENTION_DAYS", 90, minimum=1) == 1
    monkeypatch.setenv("CHANNEL_MONITOR_RETENTION_DAYS", "forever")
    assert routes._env_int("CHANNEL_MONITOR_RETENTION_DAYS", 90, minimum=1) == 90


def test_module_exposes_what_the_app_imports():
    assert isinstance(routes.RETENTION_DAYS, int)
    assert callable(routes.purge_expired_archives)
    assert cm.SUPPORTED_LANGUAGES
