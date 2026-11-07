"""
What the Channel Monitor tests share: a temp job folder, a small app with only
this blueprint and a signed-in administrator, job folders on disk, and a
stand-in for the Telegram client. Nothing here reaches Telegram or Google.

Fixtures are taken into a test module by assignment:
    cm_dir, app, admin = h.cm_dir, h.app, h.admin
"""

import asyncio
import json
import os
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import telethon
from flask import Blueprint, Flask
from telethon.tl.types import (
    Channel,
    ChatPhotoEmpty,
    Document,
    MessageMediaDocument,
    MessageMediaPhoto,
    Photo,
    PhotoSize,
)

from darkweb_scanner import channel_monitor as cm
from darkweb_scanner.dashboard import channel_monitor_routes as routes
from darkweb_scanner.dashboard.storage_helper import close_db
from darkweb_scanner.storage import Storage
from tests.helpers import make_user, sign_in, use_storage

DAY = 86400
CREDS = {"api_id": "1", "api_hash": "h", "phone": "+10000000000"}


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def storage(monkeypatch):
    return use_storage(monkeypatch, Storage("sqlite:///:memory:"))


@pytest.fixture
def cm_dir(tmp_path, monkeypatch):
    """An empty Channel Monitor folder, no running job, fixed credentials, enough free disk."""
    folder = tmp_path / "channel_monitor"
    monkeypatch.setattr(routes, "CHANNEL_MONITOR_DIR", folder)
    monkeypatch.setattr(routes, "_last_purge", None)
    monkeypatch.setattr(routes, "_get_telegram_creds", lambda: dict(CREDS))
    # raising=False: each of these exists either from 1.3.0 on or only before it,
    # and the tests are also run against the older code to show what it did.
    monkeypatch.setattr(routes, "_active", None, raising=False)
    monkeypatch.setattr(routes, "_jobs", {}, raising=False)
    monkeypatch.setattr(routes, "_free_gb", lambda: 100.0, raising=False)
    return folder


@pytest.fixture
def started(monkeypatch):
    """Arguments of every worker start. No thread is created, so the job stays running."""
    calls = []
    monkeypatch.setattr(routes, "_start_worker", lambda *args: calls.append(args))
    return calls


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


def signed_in(app, storage, username, admin=True):
    """A test client with a session for a new user."""
    client = app.test_client()
    user_id = make_user(storage, username, admin=admin)
    client.headers = sign_in(client, storage, user_id)
    client.user_id = user_id
    return client


@pytest.fixture
def admin(app, storage):
    return signed_in(app, storage, "admin")


@pytest.fixture
def telegram(monkeypatch, cm_dir):
    """The worker's TelegramClient replaced by a stand-in; a session file in place; no Google.

    Returns the box the stand-in reads its script from and records its calls in.
    """
    box = SimpleNamespace(
        calls=[],
        authorized=True,
        connect_error=None,  # raised by connect()
        entity=channel(),  # what every name resolves to; an exception is raised instead
        messages=[],  # yielded in order; an exception in the list is raised instead
        gate=None,  # a threading.Event: reading waits until it is set
        reading=threading.Event(),  # set once the job has started to read messages
        print_seen=[],  # builtins.print as the job saw it while reading
    )
    monkeypatch.setattr(telethon, "TelegramClient", type("Client", (FakeTelegram,), {"box": box}))
    monkeypatch.setattr(cm, "translate_text", lambda text, lang: "translated")
    monkeypatch.setattr(cm, "assert_disk_space", lambda *a, **k: True)
    cm_dir.mkdir(parents=True, exist_ok=True)
    (cm_dir / "channel_monitor.session").write_bytes(b"")
    return box


# ── The stand-in for telethon.TelegramClient ───────────────────────────────────


class FakeTelegram:
    """What Channel Monitor needs from TelegramClient. No network; every call is recorded."""

    box: SimpleNamespace

    def __init__(self, session, api_id, api_hash):
        self.box.calls.append("init")

    async def connect(self):
        self.box.calls.append("connect")
        if self.box.connect_error is not None:
            raise self.box.connect_error

    async def is_user_authorized(self):
        self.box.calls.append("is_user_authorized")
        return self.box.authorized

    # The interactive login. A job must never get here.
    async def start(self, *args, **kwargs):
        self.box.calls.append("start")
        return self

    async def send_code_request(self, *args, **kwargs):
        self.box.calls.append("send_code_request")

    async def sign_in(self, *args, **kwargs):
        self.box.calls.append("sign_in")

    async def get_me(self):
        return SimpleNamespace(username="monitor_account", first_name="Monitor")

    async def get_entity(self, ref):
        self.box.calls.append(f"get_entity:{ref}")
        if isinstance(self.box.entity, BaseException):
            raise self.box.entity
        return self.box.entity

    async def iter_messages(self, channel, limit=None):
        import builtins

        self.box.calls.append("iter_messages")
        self.box.print_seen.append(builtins.print)
        self.box.reading.set()
        deadline = time.monotonic() + 10
        while self.box.gate is not None and not self.box.gate.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        for item in self.box.messages:
            if isinstance(item, BaseException):
                raise item
            yield item

    async def download_media(self, message, file=None):
        self.box.calls.append(f"download:{os.path.basename(file)}")
        with open(file, "wb") as fh:
            fh.truncate(getattr(message, "bytes_on_disk", 1))
        return file

    async def disconnect(self):
        self.box.calls.append("disconnect")


def channel(**kw):
    args = dict(id=1, title="Title", photo=ChatPhotoEmpty(), date=None, broadcast=True, username="durov")
    args.update(kw)
    return Channel(**args)


def message(mid, text="", media=None, bytes_on_disk=None):
    """A Telegram message. ``bytes_on_disk`` is what a download of its media really writes."""
    m = SimpleNamespace(
        id=mid,
        date=datetime(2026, 11, 6, 1, 2, 3, tzinfo=timezone.utc),
        raw_text=text,
        text=text,
        entities=None,
        media=media,
        views=1,
        forwards=0,
        reply_to=None,
        reply_to_msg_id=None,
    )
    if bytes_on_disk is not None:
        m.bytes_on_disk = bytes_on_disk
    return m


def document(mime, size):
    return MessageMediaDocument(
        document=Document(
            id=1,
            access_hash=1,
            file_reference=b"",
            date=None,
            mime_type=mime,
            size=size,
            dc_id=1,
            attributes=[],
        )
    )


def photo(size=None):
    sizes = [PhotoSize(type="y", w=1, h=1, size=size)] if size else []
    return MessageMediaPhoto(
        photo=Photo(id=1, access_hash=1, file_reference=b"", date=None, sizes=sizes, dc_id=1)
    )


# ── Jobs on disk ───────────────────────────────────────────────────────────────


def add_job(job_id, owner_id=1, status="completed", channel="durov", log=("line 1", "line 2")):
    """A job folder as 1.3.0 leaves it: job.json, job.log and one exported channel."""
    folder = routes.CHANNEL_MONITOR_DIR / job_id
    (folder / channel).mkdir(parents=True)
    (folder / channel / "messages.json").write_text("[]")
    (folder / "job.log").write_text("".join(f"{line}\n" for line in log), encoding="utf-8")
    state = {
        "id": job_id,
        "status": status,
        "channel": channel,
        "owner_id": owner_id,
        "owner": f"user{owner_id}",
        "config": {"channel": channel, "limit": 200},
        "started_at": "2026-11-06T00:00:00",
        "ended_at": None if status == "running" else "2026-11-06T00:05:00",
        "error": None,
        "log_lines": len(log),
    }
    (folder / "job.json").write_text(json.dumps(state), encoding="utf-8")
    return folder


def add_archive(job_id, channel="durov"):
    """A job folder as 1.2.0 and earlier left it: the export, no job.json, no log."""
    folder = routes.CHANNEL_MONITOR_DIR / job_id
    (folder / channel / "media").mkdir(parents=True)
    (folder / channel / "messages.json").write_text("[]")
    (folder / channel / "messages.html").write_text("<html></html>")
    (folder / channel / "media" / "1.jpg").write_bytes(b"jpeg")
    return folder


def make_running(monkeypatch, job_id, owner_id=1, channel="durov"):
    """A job that this process is running (as far as the routes can tell; there is no thread)."""
    folder = add_job(job_id, owner_id=owner_id, status="running", channel=channel)
    job = dict(job_file(job_id), output_dir=str(folder), log=["line 1", "line 2"])
    job.pop("log_lines")
    monkeypatch.setattr(routes, "_active", job)
    return folder


def job_file(job_id):
    path = routes.CHANNEL_MONITOR_DIR / job_id / "job.json"
    return json.loads(path.read_text(encoding="utf-8"))


def age(path, days):
    """Set the modification time of ``path`` and everything under it to ``days`` ago."""
    then = time.time() - days * DAY
    for p in [path, *path.rglob("*")] if path.is_dir() else [path]:
        os.utime(p, (then, then))


# ── Requests ───────────────────────────────────────────────────────────────────


def start(client, **body):
    return client.post("/api/channel-monitor/start", json=body, headers=client.headers)


def wait_for(job_id, timeout=10):
    """Wait for the worker thread of ``job_id`` to end."""
    for thread in threading.enumerate():
        if thread.name == f"cm_{job_id}":
            thread.join(timeout)
            assert not thread.is_alive(), "the worker did not end"


def run(client, **body):
    """Start a job, wait for its worker, and return the job as the API shows it."""
    resp = start(client, **body)
    assert resp.status_code == 200, resp.get_json()
    job_id = resp.get_json()["job_id"]
    wait_for(job_id)
    return client.get(f"/api/channel-monitor/jobs/{job_id}").get_json()
