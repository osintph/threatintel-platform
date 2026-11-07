"""
Channel Monitor routes: AZ-1 (public channels only), AZ-2 (jobs have an owner),
D-11 (admin-only, archives deleted after 90 days).

No Telegram and no translator are involved: the worker thread is replaced, and
where the worker itself is under test the Telegram client is a stand-in. Job
state, limits and the download ZIP are in test_channel_monitor_jobs.py.
"""

import os
import time
from types import SimpleNamespace

import pytest
from telethon.tl.types import User

from darkweb_scanner import channel_monitor as cm
from darkweb_scanner.dashboard import channel_monitor_routes as routes
from tests.helpers import make_user, sign_in
from tests.integration import _channel_monitor as h

storage, cm_dir, started, app, admin, telegram = (
    h.storage,
    h.cm_dir,
    h.started,
    h.app,
    h.admin,
    h.telegram,
)

JOB_ROUTES = [
    ("GET", "/api/channel-monitor/credentials"),
    ("GET", "/api/channel-monitor/jobs"),
    ("GET", "/api/channel-monitor/jobs/0123456789ab"),
    ("GET", "/api/channel-monitor/jobs/0123456789ab/log"),
    ("GET", "/api/channel-monitor/jobs/0123456789ab/download"),
    ("DELETE", "/api/channel-monitor/jobs/0123456789ab"),
    ("POST", "/api/channel-monitor/start"),
]


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
    h.add_job("0123456789ab", owner_id=user_id)

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
    resp = h.start(admin, channel=ref)

    assert resp.status_code == 200
    job_id = resp.get_json()["job_id"]
    job = h.job_file(job_id)
    assert job["config"]["channel"] == "durov" == job["channel"]
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
    resp = h.start(admin, channel=ref)

    assert resp.status_code == 400
    assert "public channel" in resp.get_json()["error"]
    assert routes._active is None and started == []
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
        ("lang", "xx"),
        ("lang", 5),
        ("skip_english", "false"),
        ("translate", 0),
    ],
)
def test_wrong_types_are_refused(admin, cm_dir, started, field, value):
    resp = h.start(admin, channel="durov", **{field: value})
    assert resp.status_code == 400
    assert field in resp.get_json()["error"]
    assert routes._active is None and started == [] and not cm_dir.exists()


@pytest.mark.parametrize("body", [[1, 2], "durov", None])
def test_body_must_be_a_json_object(admin, body):
    resp = admin.post("/api/channel-monitor/start", json=body, headers=admin.headers)
    assert resp.status_code == 400


def test_numbers_are_clamped_and_defaults_applied(admin, started, monkeypatch):
    resp = h.start(
        admin,
        channel="durov",
        limit=10**8,
        days=0,
        max_video_mb=99999,
        lang="RU",
        skip_english=True,
        translate=False,
    )
    assert h.job_file(resp.get_json()["job_id"])["config"] == {
        "channel": "durov",
        "limit": routes.MAX_MESSAGES,
        "days": None,
        "lang": "ru",
        "max_video_mb": routes.MAX_VIDEO_MB,
        "skip_english": True,
        "translate": False,
    }

    monkeypatch.setattr(routes, "_active", None)  # as if that job had ended
    resp = h.start(admin, channel="durov")
    assert h.job_file(resp.get_json()["job_id"])["config"] == {
        "channel": "durov",
        "limit": 200,
        "days": None,
        "lang": None,
        "max_video_mb": 50,
        "skip_english": False,
        "translate": True,
    }


def test_job_fails_before_reading_when_the_name_is_not_a_public_channel(admin, telegram):
    telegram.entity = User(id=1, username="alice_account")
    telegram.messages = [h.message(1, "private text")]

    job = h.run(admin, channel="alice_account")

    assert job["status"] == "error" and job["ended_at"]
    assert "not a channel" in job["error"] and "Only public channels" in job["error"]
    assert "iter_messages" not in telegram.calls
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
    h.add_job("0123456789ab", owner_id=7)
    h.add_archive("aaaaaaaaaaaa")  # no owner: administrators only
    monkeypatch.setattr(routes, "current_user", lambda: SimpleNamespace(id=8, is_admin=False))
    assert routes._get_job("0123456789ab") is None
    assert routes._get_job("aaaaaaaaaaaa") is None
    monkeypatch.setattr(routes, "current_user", lambda: SimpleNamespace(id=7, is_admin=False))
    assert routes._get_job("0123456789ab")["owner_id"] == 7
    assert routes._get_job("aaaaaaaaaaaa") is None


def test_admin_sees_other_admins_jobs_with_their_owner(admin, cm_dir):
    h.add_job("0123456789ab", owner_id=admin.user_id + 1)

    listed = admin.get("/api/channel-monitor/jobs").get_json()
    assert [(j["id"], j["owner"]) for j in listed] == [("0123456789ab", f"user{admin.user_id + 1}")]
    assert (
        admin.get("/api/channel-monitor/jobs/0123456789ab").get_json()["owner"]
        == f"user{admin.user_id + 1}"
    )


def test_running_job_cannot_be_deleted(admin, cm_dir, monkeypatch):
    folder = h.make_running(monkeypatch, "0123456789ab", owner_id=admin.user_id)

    resp = admin.delete("/api/channel-monitor/jobs/0123456789ab", headers=admin.headers)

    assert resp.status_code == 409
    assert folder.exists() and routes._active["id"] == "0123456789ab"

    routes._finish_job(routes._active, "completed", None)
    resp = admin.delete("/api/channel-monitor/jobs/0123456789ab", headers=admin.headers)
    assert resp.status_code == 200
    assert not folder.exists() and admin.get("/api/channel-monitor/jobs").get_json() == []


@pytest.mark.parametrize(
    "job_id", ["..", "ABCDEFABCDEF", "0123456789abc", "0123456789a", "zzzzzzzzzzzz", "fedcba987654"]
)
@pytest.mark.parametrize(
    "suffix,method", [("", "GET"), ("/log", "GET"), ("/download", "GET"), ("", "DELETE")]
)
def test_malformed_or_unknown_job_id_is_404(admin, cm_dir, tmp_path, job_id, suffix, method):
    h.add_job("0123456789ab", owner_id=admin.user_id)
    # A folder whose name is not a job id must stay out of reach, and so must
    # a job id that is a link to somewhere else.
    for name in ("ABCDEFABCDEF", "0123456789abc", "zzzzzzzzzzzz"):
        h.add_job(name, owner_id=admin.user_id)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    os.symlink(outside, cm_dir / "fedcba987654")

    resp = admin.open(
        f"/api/channel-monitor/jobs/{job_id}{suffix}", method=method, headers=admin.headers
    )

    assert resp.status_code == 404
    assert cm_dir.exists() and (cm_dir / "0123456789ab").exists()
    assert (cm_dir / "ABCDEFABCDEF").exists() and (outside / "keep.txt").exists()
    assert [j["id"] for j in admin.get("/api/channel-monitor/jobs").get_json()] == ["0123456789ab"]


def test_log_offset_that_is_not_a_number_is_ignored(admin, cm_dir):
    h.add_job("0123456789ab", owner_id=admin.user_id)
    resp = admin.get("/api/channel-monitor/jobs/0123456789ab/log?since=abc")
    assert resp.status_code == 200
    assert resp.get_json()["log"] == ["line 1", "line 2"]
    assert admin.get("/api/channel-monitor/jobs/0123456789ab/log?since=-5").get_json()["log"] == [
        "line 1",
        "line 2",
    ]
    assert admin.get("/api/channel-monitor/jobs/0123456789ab/log?since=1").get_json() == {
        "status": "completed",
        "log": ["line 2"],
        "total": 2,
    }


# ── D-11: retention ────────────────────────────────────────────────────────────


def test_archives_older_than_90_days_are_deleted(cm_dir, monkeypatch):
    expired = h.add_job("aaaaaaaaaaaa")
    recent = h.add_job("bbbbbbbbbbbb")
    running = h.make_running(monkeypatch, "cccccccccccc")
    old_export = h.add_archive("dddddddddddd")  # made before 1.3.0: no job.json
    touched = h.add_job("eeeeeeeeeeee")
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
        (old_export, 400),
        (touched, 91),
        (session, 400),
        (other, 400),
        (old_zip, 91),
        (new_zip, 1),
    ]:
        h.age(path, days)
    (touched / "durov" / "messages.json").write_text(
        "[1]"
    )  # a file changed yesterday keeps the folder

    removed = routes.purge_expired_archives()

    assert sorted(removed) == ["aaaaaaaaaaaa", "cm_download_old.zip", "dddddddddddd"]
    assert not expired.exists() and not old_export.exists() and not old_zip.exists()
    for kept in (recent, running, touched, session, other, new_zip):
        assert kept.exists(), kept.name
    assert sorted(j["id"] for j in routes.load_jobs()) == [
        "bbbbbbbbbbbb",
        "cccccccccccc",
        "eeeeeeeeeeee",
    ]


def test_sweep_runs_with_the_job_list_at_most_once_an_hour(admin, cm_dir, started, monkeypatch):
    expired = h.add_job("aaaaaaaaaaaa", owner_id=admin.user_id)
    h.age(expired, 91)

    assert admin.get("/api/channel-monitor/jobs").get_json() == []
    assert not expired.exists()

    calls = []
    monkeypatch.setattr(routes, "purge_expired_archives", lambda: calls.append(1))
    admin.get("/api/channel-monitor/jobs")
    assert h.start(admin, channel="durov").status_code == 200
    assert calls == []

    monkeypatch.setattr(routes, "_active", None)  # as if that job had ended
    monkeypatch.setattr(
        routes, "_last_purge", time.monotonic() - routes._PURGE_INTERVAL_SECONDS - 1
    )
    assert h.start(admin, channel="durov").status_code == 200
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
    assert callable(routes.purge_expired_archives) and callable(routes.load_jobs)
    assert cm.SUPPORTED_LANGUAGES
