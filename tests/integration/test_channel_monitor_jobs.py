"""
Channel Monitor jobs: REL-1 (state that survives a restart and always ends),
REL-5 (limits set by the server, one ZIP per job), REL-6 (one job at a time, no
interactive login from a job) and REL-8 (no exception text in a log or answer).

No Telegram and no Google: the Telegram client is a stand-in (see
_channel_monitor.py) and the translator is replaced.
"""

import asyncio
import builtins
import io
import json
import logging
import os
import re
import stat
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone

import pytest
from telethon.errors import FloodWaitError

from darkweb_scanner import channel_monitor as cm
from darkweb_scanner.dashboard import channel_monitor_routes as routes
from darkweb_scanner.storage import Storage
from tests.helpers import use_storage
from tests.integration import _channel_monitor as h

storage, cm_dir, started, app, admin, telegram = (
    h.storage,
    h.cm_dir,
    h.started,
    h.app,
    h.admin,
    h.telegram,
)

JOBS = "/api/channel-monitor/jobs"
JOB = "/api/channel-monitor/jobs/0123456789ab"
ERROR_ID = r"[0-9a-f]{8}"


def _zip_names(data):
    return sorted(zipfile.ZipFile(io.BytesIO(data)).namelist())


def _seconds_from(iso, timestamp):
    then = datetime.fromisoformat(iso).replace(tzinfo=timezone.utc).timestamp()
    return abs(then - timestamp)


# ── REL-1: job state is in the job folder ──────────────────────────────────────


def test_job_state_is_written_to_the_job_folder_at_start(admin, cm_dir, started):
    job_id = h.start(admin, channel="durov", limit=10).get_json()["job_id"]

    state = h.job_file(job_id)
    assert set(state) == {
        "id",
        "status",
        "channel",
        "owner_id",
        "owner",
        "config",
        "started_at",
        "ended_at",
        "error",
        "log_lines",
    }
    assert (state["id"], state["status"], state["channel"]) == (job_id, "running", "durov")
    assert (state["owner_id"], state["owner"]) == (admin.user_id, "admin")
    assert state["config"]["limit"] == 10 and state["started_at"] and state["ended_at"] is None
    assert [p.name for p in (cm_dir / job_id).iterdir()] == ["job.json"], "no temp file stays"


def test_finished_job_is_read_back_from_its_folder(admin, cm_dir, telegram):
    telegram.messages = [h.message(1, "hello there, this is a message in English")]

    job = h.run(admin, channel="durov")

    assert (job["status"], job["error"]) == ("completed", None) and job["ended_at"]
    assert job["log"][0] == "[+] Starting channel monitor for: @durov"
    assert job["log"][-1].startswith("[✓] Scan completed")
    assert routes._active is None, "nothing of an ended job is kept in memory"
    stored = h.job_file(job["id"])
    assert (stored["status"], stored["ended_at"]) == ("completed", job["ended_at"])
    assert stored["log_lines"] == len(job["log"])
    on_disk = (cm_dir / job["id"] / "job.log").read_text(encoding="utf-8").splitlines()
    assert on_disk == job["log"]
    listed = admin.get(JOBS).get_json()
    assert [(j["id"], j["status"], j["log_lines"]) for j in listed] == [
        (job["id"], "completed", len(job["log"]))
    ]


def test_job_that_was_running_when_the_server_stopped_is_interrupted(admin, cm_dir):
    folder = h.add_job(
        "0123456789ab", owner_id=admin.user_id, status="running", log=("[+] Starting", "  [MSG 5]")
    )
    last_write = time.time() - 3600
    os.utime(folder / "job.json", (last_write - 60, last_write - 60))
    os.utime(folder / "job.log", (last_write, last_write))

    listed = admin.get(JOBS).get_json()

    assert [(j["id"], j["status"], j["owner"]) for j in listed] == [
        ("0123456789ab", "interrupted", f"user{admin.user_id}")
    ]
    assert "restarted" in listed[0]["error"]
    assert _seconds_from(listed[0]["ended_at"], last_write) < 1, "ended when it last wrote"
    stored = h.job_file("0123456789ab")
    assert (stored["status"], stored["ended_at"]) == ("interrupted", listed[0]["ended_at"])
    detail = admin.get(JOB).get_json()
    assert detail["log"][:2] == ["[+] Starting", "  [MSG 5]"]
    assert detail["log"][-1].startswith("[✗]") and "restarted" in detail["log"][-1]
    assert listed[0]["log_lines"] == len(detail["log"]) == 3

    # It is final: it can be downloaded and deleted from the page.
    assert admin.get(f"{JOB}/download").status_code == 200
    assert admin.delete(JOB, headers=admin.headers).status_code == 200
    assert not folder.exists()


def test_sweep_at_application_start_settles_interrupted_jobs(cm_dir):
    h.add_job("0123456789ab", status="running")

    assert routes.purge_expired_archives() == []  # what create_app() calls

    assert h.job_file("0123456789ab")["status"] == "interrupted"
    assert h.job_file("0123456789ab")["ended_at"]


def test_application_start_settles_interrupted_jobs(cm_dir, request):
    h.add_job("0123456789ab", status="running")

    request.getfixturevalue("full_app")  # the real create_app()

    assert h.job_file("0123456789ab")["status"] == "interrupted"


def test_folder_without_job_json_is_archived_and_can_be_downloaded_and_deleted(admin, cm_dir):
    folder = h.add_archive("0123456789ab", channel="durov")
    h.age(folder, 30)
    before = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*"))

    listed = admin.get(JOBS).get_json()

    assert len(listed) == 1
    job = listed[0]
    assert (job["id"], job["status"], job["channel"]) == ("0123456789ab", "archived", "durov")
    assert (job["owner"], job["error"], job["log_lines"]) == (None, None, 0)
    assert _seconds_from(job["started_at"], time.time() - 30 * h.DAY) < 60
    assert _seconds_from(job["ended_at"], time.time() - 30 * h.DAY) < 60
    detail = admin.get(JOB).get_json()
    assert (detail["status"], detail["log"], detail["config"]) == (
        "archived",
        [],
        {"channel": "durov"},
    )
    assert admin.get(f"{JOB}/log").get_json() == {"status": "archived", "log": [], "total": 0}
    # Showing it writes nothing into the old folder: its 90 days keep counting.
    assert sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*")) == before
    assert time.time() - folder.stat().st_mtime > 29 * h.DAY

    resp = admin.get(f"{JOB}/download")
    assert resp.status_code == 200
    assert _zip_names(resp.data) == [
        "0123456789ab/durov/media/1.jpg",
        "0123456789ab/durov/messages.html",
        "0123456789ab/durov/messages.json",
    ]
    assert admin.delete(JOB, headers=admin.headers).status_code == 200
    assert not folder.exists() and admin.get(JOBS).get_json() == []
    assert list(cm_dir.glob("cm_download_*")) == []


@pytest.mark.parametrize(
    "subfolders,channel",
    [
        (["durov"], "durov"),
        (["Новости_дня_24"], "Новости_дня_24"),  # older exports: the title, made safe
        (["Some Title"], ""),
        (["a.b"], ""),
        (['<b id="x">'], ""),
        (["x" * 129], ""),
        (["one", "two"], ""),
        ([], ""),
    ],
)
def test_archived_channel_is_only_a_plain_folder_name(admin, cm_dir, subfolders, channel):
    folder = cm_dir / "0123456789ab"
    folder.mkdir(parents=True)
    for name in subfolders:
        (folder / name).mkdir()

    job = admin.get(JOBS).get_json()[0]

    assert (job["status"], job["channel"], job["owner"]) == ("archived", channel, None)


@pytest.mark.parametrize("content", ["{not json", "[]", '{"status": "paused"}', ""])
def test_job_json_that_cannot_be_used_is_listed_as_archived(admin, cm_dir, content):
    folder = h.add_job("0123456789ab", owner_id=admin.user_id)
    (folder / "job.json").write_text(content)

    job = admin.get(JOBS).get_json()[0]

    assert (job["status"], job["channel"], job["owner"]) == ("archived", "durov", None)
    assert admin.delete(JOB, headers=admin.headers).status_code == 200


class _Stop(BaseException):
    """Not an Exception: what an ``except Exception`` does not see."""


@pytest.mark.parametrize(
    "raised",
    [asyncio.CancelledError(), SystemExit(3), KeyboardInterrupt(), _Stop()],
    ids=["cancelled", "SystemExit", "KeyboardInterrupt", "BaseException"],
)
def test_cancellation_and_baseexception_end_the_job(admin, telegram, raised):
    telegram.messages = [h.message(1), raised]

    job = h.run(admin, channel="durov")

    assert job["status"] == "interrupted" and job["ended_at"]
    assert re.fullmatch(rf"The job was stopped before it finished\. Error id: {ERROR_ID}", job["error"])
    assert job["log"][-1] == f"[✗] {job['error']}"
    stored = h.job_file(job["id"])
    assert (stored["status"], stored["ended_at"]) == ("interrupted", job["ended_at"])
    assert "disconnect" in telegram.calls
    # The slot is free again.
    assert routes._active is None
    assert h.start(admin, channel="durov").status_code == 200


def test_job_whose_final_state_cannot_be_stored_still_ends(admin, telegram, monkeypatch):
    telegram.gate = threading.Event()
    job_id = h.start(admin, channel="durov").get_json()["job_id"]
    assert telegram.reading.wait(10)

    def disk_full(job):
        raise OSError(28, "No space left on device")

    real_write = routes._write_job
    monkeypatch.setattr(routes, "_write_job", disk_full)
    telegram.gate.set()
    h.wait_for(job_id)

    assert routes._active is None, "the next job can start"
    monkeypatch.setattr(routes, "_write_job", real_write)
    job = admin.get(f"{JOBS}/{job_id}").get_json()
    assert job["status"] == "interrupted" and job["ended_at"]


def test_log_keeps_a_bounded_number_of_lines_of_bounded_length(admin, cm_dir, telegram, monkeypatch):
    monkeypatch.setattr(routes, "MAX_LOG_LINES", 8)
    monkeypatch.setattr(routes, "MAX_LOG_LINE_CHARS", 100)
    telegram.entity = h.channel(title="T" * 500)
    telegram.messages = [h.message(i) for i in range(1, 31)]

    job = h.run(admin, channel="durov")

    assert job["status"] == "completed"
    assert len(job["log"]) == 8 + 2, "the first 8 lines, one notice, the closing line"
    assert job["log"][8].startswith("[i] Log limit reached")
    assert job["log"][-1].startswith("[✓] Scan completed")
    assert max(len(line) for line in job["log"]) == 100
    assert any(line.startswith("[+] Processing: TTT") and line.endswith("…") for line in job["log"])
    on_disk = (cm_dir / job["id"] / "job.log").read_text(encoding="utf-8").splitlines()
    assert on_disk == job["log"]
    assert admin.get(f"{JOBS}/{job['id']}/log?since=9").get_json()["total"] == 10


def test_default_log_limits():
    assert (routes.MAX_LOG_LINES, routes.MAX_LOG_LINE_CHARS) == (20_000, 500)


def test_a_log_entry_is_one_line_whatever_the_channel_sends(admin, cm_dir, telegram):
    telegram.entity = h.channel(title="News\n[✓] Scan completed successfully\r\x1b[31m‮ x")
    telegram.messages = [h.message(1)]

    job = h.run(admin, channel="durov")

    line = next(line for line in job["log"] if line.startswith("[+] Processing:"))
    assert "News [✓] Scan completed successfully" in line
    assert not any(c in "".join(job["log"]) for c in "\n\r\x1b‮ ")
    assert sum(line.startswith("[✓] Scan completed") for line in job["log"]) == 1
    on_disk = (cm_dir / job["id"] / "job.log").read_text(encoding="utf-8").split("\n")
    assert on_disk == job["log"] + [""]


# ── REL-6: one job at a time, no interactive login from a job ──────────────────


def test_second_start_is_refused_while_a_job_runs(admin, app, storage, cm_dir, started):
    first = h.start(admin, channel="durov").get_json()["job_id"]
    other = h.signed_in(app, storage, "second_admin")

    resp = h.start(other, channel="telegram")

    assert resp.status_code == 409
    error = resp.get_json()["error"]
    started_at = h.job_file(first)["started_at"][:16].replace("T", " ")
    assert "@durov" in error and f"started {started_at} UTC" in error and "by admin" in error
    assert len(started) == 1
    assert [p.name for p in cm_dir.iterdir()] == [first], "no folder for the refused job"

    # Once it has ended, the next one is accepted.
    routes._finish_job(routes._active, "completed", None)
    assert h.start(other, channel="telegram").status_code == 200


def test_one_job_at_a_time_and_print_is_left_alone(admin, telegram):
    original_print = builtins.print
    telegram.gate = threading.Event()
    telegram.messages = [h.message(1, "the text of a message in the first job")]
    first = h.start(admin, channel="durov").get_json()["job_id"]
    assert telegram.reading.wait(10)
    try:
        # The job is reading now. Nothing process-wide has been replaced ...
        assert builtins.print is original_print
        print("a line printed by some other part of the application")
        # ... and no second job can run next to it and write into the same log.
        second = h.start(admin, channel="telegram")
        assert second.status_code == 409
    finally:
        telegram.gate.set()
        h.wait_for(first)

    job = admin.get(f"{JOBS}/{first}").get_json()
    assert job["status"] == "completed"
    assert telegram.print_seen == [original_print]
    assert not any("some other part" in line for line in job["log"])
    assert any(line.startswith("  [MSG 1]") for line in job["log"])
    assert [j["id"] for j in admin.get(JOBS).get_json()] == [first]


def test_session_that_is_not_signed_in_ends_the_job_with_the_command(admin, telegram):
    telegram.authorized = False
    telegram.messages = [h.message(1)]

    job = h.run(admin, channel="durov")

    assert job["status"] == "error" and job["ended_at"]
    assert job["error"] == (
        "The Telegram session is not signed in. On the server, run: "
        "docker compose exec dashboard python -m darkweb_scanner.main channel-monitor-auth"
    )
    assert job["log"][-1] == f"[✗] {job['error']}"
    # connect() and is_user_authorized() only: nothing that makes Telegram send a code.
    assert telegram.calls == ["init", "connect", "is_user_authorized", "disconnect"]


def test_missing_session_file_ends_the_job_with_the_command(admin, cm_dir, telegram):
    (cm_dir / "channel_monitor.session").unlink()

    job = h.run(admin, channel="durov")

    assert job["status"] == "error" and "channel-monitor-auth" in job["error"]
    assert telegram.calls == [], "no client is opened, so no empty session file is created"
    assert not (cm_dir / "channel_monitor.session").exists()


def test_job_sets_the_session_file_to_owner_only(admin, cm_dir, telegram):
    session = cm_dir / "channel_monitor.session"
    os.chmod(session, 0o644)

    assert h.run(admin, channel="durov")["status"] == "completed"

    assert stat.S_IMODE(session.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "creds,word",
    [
        ({"api_id": "", "api_hash": "h", "phone": "+1"}, "TELEGRAM_API_ID"),
        ({"api_id": "1", "api_hash": "", "phone": "+1"}, "TELEGRAM_API_HASH"),
        ({"api_id": "12ab", "api_hash": "h", "phone": "+1"}, "must be a number"),
    ],
)
def test_missing_or_malformed_telegram_settings_are_a_400(admin, cm_dir, started, monkeypatch, creds, word):
    monkeypatch.setattr(routes, "_get_telegram_creds", lambda: creds)

    resp = h.start(admin, channel="durov")

    assert resp.status_code == 400 and word in resp.get_json()["error"]
    assert started == [] and not cm_dir.exists()


# ── REL-5: limits set by the server ────────────────────────────────────────────


@pytest.mark.parametrize(
    "sent,expected",
    [
        ({}, 200),
        ({"limit": 0}, 200),
        ({"limit": ""}, 200),
        ({"limit": None}, 200),
        ({"limit": -5}, 200),
        ({"limit": 1}, 1),
        ({"limit": 4999}, 4999),
        ({"limit": 5000.0}, 5000),
        ({"limit": 5001}, 5000),
        ({"limit": 10**9}, 5000),
    ],
)
def test_message_limit_is_one_to_the_servers_maximum(admin, started, sent, expected):
    assert routes.MAX_MESSAGES == 5000
    job_id = h.start(admin, channel="durov", **sent).get_json()["job_id"]
    assert h.job_file(job_id)["config"]["limit"] == expected


def test_default_message_limit_stays_under_a_lower_maximum(admin, started, monkeypatch):
    monkeypatch.setattr(routes, "MAX_MESSAGES", 50)
    job_id = h.start(admin, channel="durov").get_json()["job_id"]
    assert h.job_file(job_id)["config"]["limit"] == 50


@pytest.mark.parametrize("min_space_gb", [0.001, "lots", True, None])
def test_video_limit_is_clamped_and_free_space_is_not_for_the_request_to_set(
    admin, started, min_space_gb
):
    resp = h.start(admin, channel="durov", max_video_mb=10**6, min_space_gb=min_space_gb)

    assert resp.status_code == 200
    config = h.job_file(resp.get_json()["job_id"])["config"]
    assert config["max_video_mb"] == routes.MAX_VIDEO_MB == 200
    assert "min_space_gb" not in config


def test_job_runs_under_the_servers_limits(admin, telegram, monkeypatch):
    seen = {}

    async def process_channel(**kwargs):
        seen.update(kwargs)
        return {"messages": 0, "media_files": 0, "media_bytes": 0, "stopped": None}

    monkeypatch.setattr(cm, "process_channel", process_channel)

    job = h.run(admin, channel="durov", limit=10**9, max_video_mb=10**6, min_space_gb=0.001)

    assert job["status"] == "completed"
    assert (seen["limit"], seen["max_video_mb"], seen["max_file_mb"]) == (5000, 200, 50)
    assert (seen["max_job_gb"], seen["min_space_gb"]) == (2.0, 5.0)
    assert callable(seen["log"])
    assert any(
        "files up to 50 MB, videos up to 200 MB, media up to 2 GB per job" in line
        and "less than 5 GB" in line
        for line in job["log"]
    )


def test_no_job_starts_when_free_disk_space_is_under_the_minimum(admin, cm_dir, started, monkeypatch):
    monkeypatch.setattr(routes, "_free_gb", lambda: 4.9)

    resp = h.start(admin, channel="durov", min_space_gb=0.001)

    assert resp.status_code == 507
    assert "4.9 GB are free" in resp.get_json()["error"] and "5 GB" in resp.get_json()["error"]
    assert started == [] and routes._active is None
    assert list(cm_dir.iterdir()) == [], "no job folder"


def test_job_stops_when_free_disk_space_falls_under_the_minimum(admin, cm_dir, telegram, monkeypatch):
    telegram.messages = [h.message(i, f"message number {i}, written in English") for i in range(1, 6)]
    asked = []

    def assert_disk_space(min_gb, path, log=print):
        asked.append(min_gb)
        if len(asked) > 2:
            log("[✗] CRITICAL: Disk space dropped. Stopping.")
            return False
        return True

    monkeypatch.setattr(cm, "assert_disk_space", assert_disk_space)

    job = h.run(admin, channel="durov", min_space_gb=0.001)

    assert job["status"] == "error" and job["ended_at"]
    assert job["error"].startswith("Stopped: less than 5 GB of disk space is free")
    assert set(asked) == {5.0}, "the server's minimum, not the request's"
    exported = json.loads((cm_dir / job["id"] / "durov" / "messages.json").read_text())
    assert [m["id"] for m in exported] == [1, 2], "what was read until then is kept"
    assert admin.get(f"{JOBS}/{job['id']}/download").status_code == 200


def test_credentials_answer_carries_the_limits(admin):
    data = admin.get("/api/channel-monitor/credentials").get_json()
    assert data["limits"] == {
        "max_messages": 5000,
        "max_video_mb": 200,
        "max_file_mb": 50,
        "max_job_gb": 2.0,
    }
    assert data["retention_days"] == 90 and data["configured"] is True


def test_limits_are_read_from_the_environment_with_minimums(monkeypatch):
    for value, expected in [("0.5", 0.5), ("0", 0.1), ("-3", 0.1), ("lots", 2.0), ("nan", 2.0), ("inf", 2.0), ("", 2.0)]:
        monkeypatch.setenv("CM_TEST_VALUE", value)
        assert routes._env_float("CM_TEST_VALUE", 2.0, minimum=0.1) == expected, value
    monkeypatch.delenv("CM_TEST_VALUE")
    assert routes._env_float("CM_TEST_VALUE", 2.0, minimum=0.1) == 2.0

    code = (
        "from darkweb_scanner.dashboard import channel_monitor_routes as r;"
        "print(r.MAX_MESSAGES, r.MAX_FILE_MB, r.MAX_VIDEO_MB, r.MAX_JOB_GB, r.MIN_FREE_GB,"
        " r.MAX_DOWNLOAD_SOURCE_BYTES // r.GB, r.RETENTION_DAYS)"
    )
    env = dict(
        os.environ,
        PYTHONPATH=os.pathsep.join(p for p in sys.path if p),
        CHANNEL_MONITOR_MAX_MESSAGES="0",
        CHANNEL_MONITOR_MAX_FILE_MB="7",
        CHANNEL_MONITOR_MAX_VIDEO_MB="0",
        CHANNEL_MONITOR_MAX_JOB_GB="0.5",
        CHANNEL_MONITOR_MIN_FREE_GB="0.2",
        CHANNEL_MONITOR_MAX_DOWNLOAD_GB="oops",
        CHANNEL_MONITOR_RETENTION_DAYS="30",
    )
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert out.stdout.split() == ["1", "7", "0", "0.5", "1.0", "5", "30"], out.stderr


# ── REL-5: one ZIP per job ─────────────────────────────────────────────────────


def test_zip_is_built_once_reused_rebuilt_after_a_change_and_deleted_with_the_job(admin, cm_dir):
    folder = h.add_job("0123456789ab", owner_id=admin.user_id)
    h.age(folder, 1)
    zip_path = cm_dir / "cm_download_0123456789ab.zip"

    first = admin.get(f"{JOB}/download")

    assert first.status_code == 200 and zip_path.is_file()
    assert int(first.headers["Content-Length"]) == zip_path.stat().st_size == len(first.data)
    assert first.headers["Content-Disposition"].startswith("attachment; filename=channel_monitor_durov_")
    # The log is in the ZIP; job.json, which names the owner, is not.
    assert _zip_names(first.data) == ["0123456789ab/durov/messages.json", "0123456789ab/job.log"]
    built = (zip_path.stat().st_ino, zip_path.stat().st_mtime_ns)

    second = admin.get(f"{JOB}/download")

    assert second.data == first.data
    assert (zip_path.stat().st_ino, zip_path.stat().st_mtime_ns) == built, "the same file again"
    assert [p.name for p in cm_dir.glob("cm_download_*")] == [zip_path.name]

    (folder / "durov" / "note.txt").write_text("added later")
    third = admin.get(f"{JOB}/download")

    assert "0123456789ab/durov/note.txt" in _zip_names(third.data)
    assert (zip_path.stat().st_ino, zip_path.stat().st_mtime_ns) != built, "built again"
    assert [p.name for p in cm_dir.glob("cm_download_*")] == [zip_path.name]

    assert admin.delete(JOB, headers=admin.headers).status_code == 200
    assert not folder.exists() and list(cm_dir.glob("cm_download_*")) == []


def test_range_request_is_answered_from_the_kept_zip(admin, cm_dir):
    h.age(h.add_job("0123456789ab", owner_id=admin.user_id), 1)
    whole = admin.get(f"{JOB}/download").data

    part = admin.get(f"{JOB}/download", headers={"Range": "bytes=10-"})

    assert part.status_code == 206 and part.data == whole[10:]


class _WatchedLock:
    """routes._zip_lock that also says when a second caller is waiting for it."""

    def __init__(self):
        self._lock = threading.Lock()
        self.waiting = threading.Event()

    def __enter__(self):
        if not self._lock.acquire(blocking=False):
            self.waiting.set()
            self._lock.acquire()

    def __exit__(self, *exc):
        self._lock.release()


def test_two_downloads_at_once_build_one_zip(app, cm_dir, tmp_path, monkeypatch):
    # The two requests run in threads of their own: a database file, because
    # an in-memory SQLite database belongs to one thread.
    db = use_storage(monkeypatch, Storage(f"sqlite:///{tmp_path / 'users.db'}"))
    clients = {"first": h.signed_in(app, db, "admin"), "second": h.signed_in(app, db, "second_admin")}
    h.age(h.add_job("0123456789ab"), 1)
    zip_path = cm_dir / "cm_download_0123456789ab.zip"

    lock = _WatchedLock()
    monkeypatch.setattr(routes, "_zip_lock", lock)
    builds, building, release = [], threading.Event(), threading.Event()
    real_build = routes._build_zip

    def slow_build(*args):
        builds.append(args[0])
        building.set()
        assert release.wait(10)
        return real_build(*args)

    monkeypatch.setattr(routes, "_build_zip", slow_build)
    answers = {}

    def download(name):
        resp = clients[name].get(f"{JOB}/download")
        answers[name] = (resp.status_code, resp.data)

    threads = [threading.Thread(target=download, args=(name,)) for name in clients]
    threads[0].start()
    assert building.wait(10)
    threads[1].start()
    assert lock.waiting.wait(10), "the second request waits for the build of the first"
    assert not zip_path.exists(), "nothing half-written under the name that is served"
    release.set()
    for thread in threads:
        thread.join(10)

    assert builds == ["0123456789ab"], "one build for two downloads"
    assert answers["first"][0] == answers["second"][0] == 200
    assert answers["first"][1] == answers["second"][1] == zip_path.read_bytes()
    assert zipfile.ZipFile(io.BytesIO(answers["second"][1])).testzip() is None
    assert [p.name for p in cm_dir.glob("cm_download_*")] == [zip_path.name]


def test_zip_is_not_built_over_the_download_cap_or_into_the_last_free_space(admin, cm_dir, monkeypatch):
    h.age(h.add_job("0123456789ab", owner_id=admin.user_id), 1)

    monkeypatch.setattr(routes, "MAX_DOWNLOAD_SOURCE_BYTES", 1)
    resp = admin.get(f"{JOB}/download")
    assert resp.status_code == 413 and "download cap" in resp.get_json()["error"]

    monkeypatch.setattr(routes, "MAX_DOWNLOAD_SOURCE_BYTES", 5 * routes.GB)
    monkeypatch.setattr(routes, "_free_gb", lambda: 5.0)
    resp = admin.get(f"{JOB}/download")
    assert resp.status_code == 507 and "5 GB must stay free" in resp.get_json()["error"]

    assert list(cm_dir.glob("cm_download_*")) == []


def test_sweep_removes_a_zip_with_its_job_folder(admin, cm_dir):
    expired = h.add_job("aaaaaaaaaaaa", owner_id=admin.user_id)
    kept = h.add_job("cccccccccccc", owner_id=admin.user_id)
    for folder in (expired, kept):
        h.age(folder, 1)
        assert admin.get(f"{JOBS}/{folder.name}/download").status_code == 200
    h.age(expired, 91)  # its ZIP was built today
    left_behind = cm_dir / "cm_download_bbbbbbbbbbbb.zip"  # the folder of this one is gone
    left_behind.write_bytes(b"zip")
    half_built = cm_dir / "cm_download_dddddddddddd.part.zip"
    half_built.write_bytes(b"zi")

    removed = routes.purge_expired_archives()

    assert sorted(removed) == [
        "aaaaaaaaaaaa",
        "cm_download_aaaaaaaaaaaa.zip",
        "cm_download_bbbbbbbbbbbb.zip",
        "cm_download_dddddddddddd.part.zip",
    ]
    assert sorted(p.name for p in cm_dir.iterdir()) == ["cccccccccccc", "cm_download_cccccccccccc.zip"]


# ── REL-8: an error id instead of the exception ────────────────────────────────


def test_unexpected_error_in_a_job_shows_an_error_id_not_the_exception(admin, telegram, caplog):
    telegram.messages = [h.message(1), RuntimeError("secret-detail in /app/data/channel_monitor")]

    with caplog.at_level(logging.ERROR):
        job = h.run(admin, channel="durov")

    assert job["status"] == "error" and job["ended_at"]
    match = re.fullmatch(rf"The scan stopped on an unexpected error\. Error id: ({ERROR_ID})", job["error"])
    assert match, job["error"]
    assert job["log"][-1] == f"[✗] {job['error']}"
    shown = json.dumps(job) + admin.get(f"{JOBS}/{job['id']}/log").get_data(as_text=True)
    shown += json.dumps(admin.get(JOBS).get_json()) + json.dumps(h.job_file(job["id"]))
    for leaked in ("Traceback", "secret-detail", "RuntimeError", "/app/data", 'File "'):
        assert leaked not in shown, leaked
    # The server log has the traceback under the same id.
    record = next(r for r in caplog.records if match.group(1) in r.getMessage())
    assert record.exc_info and "secret-detail" in str(record.exc_info[1])


def test_connection_failure_shows_an_error_id_not_the_exception(admin, telegram, caplog):
    telegram.connect_error = OSError("Connect call failed ('149.154.167.51', 443)")

    with caplog.at_level(logging.ERROR):
        job = h.run(admin, channel="durov")

    assert job["status"] == "error"
    match = re.fullmatch(rf"Could not connect to Telegram\. Error id: ({ERROR_ID})", job["error"])
    assert match, job["error"]
    assert "149.154" not in json.dumps(job)
    assert any(match.group(1) in r.getMessage() and r.exc_info for r in caplog.records)
    assert telegram.calls == ["init", "connect", "disconnect"]


@pytest.mark.parametrize(
    "failure,where,expected",
    [
        (ValueError('No user has "durov" as username'), "entity", "Telegram has no public channel or group named @durov."),
        (FloodWaitError(request=None, capture=1234), "entity", "Telegram asked this account to wait 1234 seconds before more requests. Try again later."),
        (FloodWaitError(request=None, capture=77), "messages", "Telegram asked this account to wait 77 seconds before more requests. Try again later."),
    ],
    ids=["unknown-name", "flood-wait-at-start", "flood-wait-while-reading"],
)
def test_telegram_errors_an_administrator_can_act_on_are_plain_sentences(
    admin, telegram, failure, where, expected
):
    if where == "entity":
        telegram.entity = failure
    else:
        telegram.messages = [h.message(1), failure]

    job = h.run(admin, channel="durov")

    assert (job["status"], job["error"]) == ("error", expected)
    assert job["log"][-1] == f"[✗] {expected}"


def test_zip_failure_answers_with_an_error_id(admin, cm_dir, monkeypatch, caplog):
    h.age(h.add_job("0123456789ab", owner_id=admin.user_id), 1)

    def no_space(*args):
        raise OSError(28, "No space left on device", "/app/data/channel_monitor/x.zip")

    monkeypatch.setattr(routes, "_build_zip", no_space)

    with caplog.at_level(logging.ERROR):
        resp = admin.get(f"{JOB}/download")

    assert resp.status_code == 500
    body = resp.get_json()
    assert set(body) == {"error", "error_id"} and body["error"] == "The ZIP could not be built."
    assert re.fullmatch(ERROR_ID, body["error_id"])
    assert "No space" not in resp.get_data(as_text=True) and "/app/data" not in resp.get_data(as_text=True)
    assert any(body["error_id"] in r.getMessage() and r.exc_info for r in caplog.records)


def test_delete_failure_answers_with_an_error_id(admin, cm_dir, monkeypatch):
    folder = h.add_job("0123456789ab", owner_id=admin.user_id)

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(routes.shutil, "rmtree", denied)

    resp = admin.delete(JOB, headers=admin.headers)

    assert resp.status_code == 500
    body = resp.get_json()
    assert body["error"] == "The job folder could not be deleted." and re.fullmatch(ERROR_ID, body["error_id"])
    assert "Permission" not in resp.get_data(as_text=True) and str(cm_dir) not in resp.get_data(as_text=True)
    assert folder.exists()
