"""
REL-5, REL-6, REL-8 in channel_monitor.py: the limits a run keeps to, the
logging callable, what a failure looks like to the user, and the terminal
sign-in. No Telegram and no Google: the client is a stand-in and the
translator is replaced.
"""

import builtins
import json
import logging
import os
import re
import stat
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from telethon import errors as tg_errors
from telethon.tl.types import (
    Channel,
    ChatPhotoEmpty,
    Document,
    MessageMediaDocument,
    MessageMediaPhoto,
    Photo,
    PhotoSize,
    PhotoSizeProgressive,
)

from darkweb_scanner import channel_monitor as cm

MB = 1024 * 1024
GB = 1024 * MB
ERROR_ID = r"[0-9a-f]{8}"
_real_assert_disk_space = cm.assert_disk_space
_real_translate_text = cm.translate_text
_Usage = namedtuple("_Usage", "total used free")


class _Client:
    """Stands in for TelegramClient. Hands out every message it has, whatever limit is asked."""

    def __init__(self, messages=(), entity=None):
        self.entity = entity or _channel()
        self.messages = list(messages)
        self.limit_asked = "never asked"
        self.read = 0
        self.downloads = []
        self.download_error = None

    async def get_entity(self, ref):
        if isinstance(self.entity, BaseException):
            raise self.entity
        return self.entity

    async def iter_messages(self, channel, limit=None):
        self.limit_asked = limit
        for message in self.messages:
            self.read += 1
            yield message

    async def download_media(self, message, file=None):
        self.downloads.append(os.path.basename(file))
        if self.download_error is not None:
            raise self.download_error
        with open(file, "wb") as fh:
            fh.truncate(message.bytes_on_disk)
        return file


def _channel(**kw):
    args = dict(id=1, title="Title", photo=ChatPhotoEmpty(), date=None, broadcast=True, username="durov")
    args.update(kw)
    return Channel(**args)


def _message(mid, text="", media=None, on_disk=None):
    """``on_disk``: the bytes a download really writes (default: what Telegram states)."""
    stated = 1
    if isinstance(media, MessageMediaDocument):
        stated = media.document.size
    return SimpleNamespace(
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
        bytes_on_disk=stated if on_disk is None else on_disk,
    )


def _document(mime, size):
    return MessageMediaDocument(
        document=Document(
            id=1, access_hash=1, file_reference=b"", date=None, mime_type=mime, size=size, dc_id=1, attributes=[]
        )
    )


def _photo(*sizes):
    return MessageMediaPhoto(
        photo=Photo(id=1, access_hash=1, file_reference=b"", date=None, sizes=list(sizes), dc_id=1)
    )


@pytest.fixture
def export(tmp_path, monkeypatch):
    """Run process_channel on a stand-in client: enough disk, no translator.

    Returns what the run left behind: its summary, the lines it logged, the
    messages it exported and the media files on disk.
    """
    monkeypatch.setattr(cm, "translate_text", lambda text, lang: "translated")
    monkeypatch.setattr(cm, "assert_disk_space", lambda *a, **k: True)

    async def run(client, limit=100, **kwargs):
        lines = []
        if not isinstance(client, _Client):
            client = _Client(client)
        summary = await cm.process_channel(client, "durov", limit, tmp_path, log=lines.append, **kwargs)
        folder = tmp_path / "durov"
        return SimpleNamespace(
            summary=summary,
            log=lines,
            client=client,
            messages=json.loads((folder / "messages.json").read_text(encoding="utf-8")),
            media=sorted(p.name for p in (folder / "media").iterdir()),
            html=(folder / "messages.html").is_file(),
        )

    return run


# ── REL-5: message limit ───────────────────────────────────────────────────────


async def test_run_stops_at_the_message_limit_even_when_telegram_sends_more(export):
    done = await export([_message(i, f"text {i}") for i in range(1, 11)], limit=3)

    assert [m["id"] for m in done.messages] == [1, 2, 3]
    assert done.summary["messages"] == 3 and done.client.limit_asked == 3
    assert done.client.read == 4, "one look past the limit, nothing more"


@pytest.mark.parametrize("limit", [0, -1, None])
async def test_no_limit_means_the_default_not_all_messages(export, limit):
    done = await export([_message(i) for i in range(1, cm.LIMIT + 51)], limit=limit)

    assert len(done.messages) == cm.LIMIT == 200
    assert done.client.limit_asked == 200, "Telegram is never asked for everything"


# ── REL-5: file and video size ─────────────────────────────────────────────────


async def test_file_limit_covers_photos_and_every_image_document(export):
    messages = [
        _message(1, media=_document("image/png", 2 * MB)),
        _message(2, media=_document("image/png", MB // 2)),
        _message(3, media=_document("image/x-anything", 3 * MB)),  # the uploader chooses the MIME type
        _message(4, media=_photo(PhotoSize(type="y", w=1, h=1, size=2 * MB))),
        _message(5, media=_photo(PhotoSizeProgressive(type="y", w=1, h=1, sizes=[100, 2 * MB]))),
        _message(6, media=_photo(PhotoSize(type="y", w=1, h=1, size=1000))),
        _message(7, media=_document("image/gif", MB)),  # exactly the limit
    ]

    done = await export(messages, max_file_mb=1)

    assert done.client.downloads == ["2.png", "6.jpg", "7.gif"], "the others were never requested"
    assert done.media == ["2.png", "6.jpg", "7.gif"]
    paths = {m["id"]: m["media_path"] for m in done.messages}
    assert paths == {1: None, 2: "media/2.png", 3: None, 4: None, 5: None, 6: "media/6.jpg", 7: "media/7.gif"}
    assert [m["media_type"] for m in done.messages[:4]] == ["image_doc", "image_doc", "image_doc", "photo"]
    skipped = [line for line in done.log if "skipped" in line]
    assert len(skipped) == 4 and all("over the limit of 1 MB" in line for line in skipped)
    assert done.summary["media_files"] == 3 and done.summary["stopped"] is None


async def test_file_that_turns_out_larger_than_stated_is_removed(export):
    messages = [
        _message(1, media=_document("image/png", 10), on_disk=2 * MB),
        _message(2, media=_photo(), on_disk=2 * MB),  # a photo that states no size
        _message(3, media=_document("image/png", 10)),
    ]

    done = await export(messages, max_file_mb=1)

    assert done.client.downloads == ["1.png", "2.jpg", "3.png"]
    assert done.media == ["3.png"]
    assert [m["media_path"] for m in done.messages] == [None, None, "media/3.png"]
    assert sum("removed: 2.0 MB is over the limit of 1 MB" in line for line in done.log) == 2
    assert done.summary["media_bytes"] == 10


async def test_video_limit(export):
    messages = [
        _message(1, media=_document("video/mp4", 3 * MB)),
        _message(2, media=_document("video/mp4", 2 * MB)),
    ]

    done = await export(messages, max_video_mb=2, max_file_mb=1)

    assert done.client.downloads == ["2.mp4"], "a video answers to the video limit, not the file limit"
    assert any("Video skipped: 3.0 MB is over the limit of 2 MB" in line for line in done.log)

    off = await export(messages, max_video_mb=0)
    assert off.client.downloads == []
    assert sum("videos are off" in line for line in off.log) == 2
    assert [m["media_type"] for m in off.messages] == ["video", "video"]


# ── REL-5: job size and free space ─────────────────────────────────────────────


async def test_media_stop_at_the_job_size_limit_and_the_text_export_goes_on(export):
    messages = [_message(i, f"text {i}", media=_document("image/png", MB)) for i in range(1, 6)]
    messages.append(_message(6, "text only"))

    done = await export(messages, max_job_gb=2.5 * MB / GB)

    assert done.client.downloads == ["1.png", "2.png"], "the third would pass 2.5 MB"
    assert done.summary == {"messages": 6, "media_files": 2, "media_bytes": 2 * MB, "stopped": None}
    assert [m["id"] for m in done.messages] == [1, 2, 3, 4, 5, 6] and done.html
    assert [m["original"] for m in done.messages][-1] == "text only"
    said = [line for line in done.log if "Job size limit reached" in line]
    assert len(said) == 1 and "the text export continues" in said[0]


async def test_job_size_limit_also_holds_when_telegram_states_no_size(export):
    messages = [_message(i, media=_photo(), on_disk=MB) for i in range(1, 6)]

    done = await export(messages, max_job_gb=2 * MB / GB)

    assert done.client.downloads == ["1.jpg", "2.jpg"]
    assert done.summary["media_bytes"] == 2 * MB and len(done.messages) == 5


async def test_run_stops_when_free_space_is_under_the_minimum(export, monkeypatch):
    free = [6 * GB, 6 * GB, 6 * GB, 4 * GB]
    monkeypatch.setattr(cm, "assert_disk_space", _real_assert_disk_space)
    monkeypatch.setattr(
        cm.shutil, "disk_usage", lambda path: _Usage(100 * GB, 0, free.pop(0) if len(free) > 1 else free[0])
    )
    messages = [_message(i, f"text {i}", media=_document("image/png", 10)) for i in range(1, 6)]

    done = await export(messages, min_space_gb=5)

    # Checked before each message and before each download: 1 and its file, 2, then no more.
    assert done.client.downloads == ["1.png"]
    assert [m["id"] for m in done.messages] == [1, 2] and done.html
    assert done.summary["stopped"] == "disk" and done.summary["messages"] == 2
    assert any("Disk space dropped below 5 GB (4.00 GB free)" in line for line in done.log)
    assert any("Partial results saved up to #2" in line for line in done.log)


async def test_nothing_is_read_when_there_is_no_space_at_the_start(export, monkeypatch):
    monkeypatch.setattr(cm, "assert_disk_space", _real_assert_disk_space)
    monkeypatch.setattr(cm.shutil, "disk_usage", lambda path: _Usage(100 * GB, 99 * GB, GB))

    done = await export([_message(1, "text")], min_space_gb=5)

    assert done.messages == [] and done.summary == {
        "messages": 0,
        "media_files": 0,
        "media_bytes": 0,
        "stopped": "disk",
    }


# ── REL-6: a logging callable, not a replaced print ────────────────────────────


async def test_every_line_goes_to_the_logging_callable(export, monkeypatch):
    def no_print(*args, **kwargs):
        raise AssertionError(f"print() was called: {args}")

    monkeypatch.setattr(builtins, "print", no_print)
    messages = [
        _message(1, "Это сообщение на русском языке", media=_document("image/png", 10)),
        _message(2, media=_document("video/mp4", 10**9)),
    ]

    done = await export(messages, days=3650, forced_lang="ru")

    assert builtins.print is no_print
    assert all(isinstance(line, str) and "\n" not in line for line in done.log)
    for expected in (
        "[i] Fetching since:",
        "[+] Processing: Title | lang: forced=ru",
        "  [+] Image saved: 1.png",
        "  [!] Video skipped:",
        "  [MSG 1]",
        "  [MSG 2]",
        "  [✓] 2 messages saved, 1 media file(s)",
        "  [i] Language breakdown:",
    ):
        assert any(line.startswith(expected) for line in done.log), expected
    assert not any("firefox" in line or str(Path.cwd()) in line for line in done.log)


async def test_without_a_callable_lines_are_printed_as_the_command_line_tool_does(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cm, "assert_disk_space", lambda *a, **k: True)

    await cm.process_channel(_Client([_message(1)]), "durov", 10, tmp_path)

    assert "[+] Processing: Title" in capsys.readouterr().out


def test_disk_check_reports_through_the_callable(monkeypatch, capsys):
    monkeypatch.setattr(cm.shutil, "disk_usage", lambda path: _Usage(100 * GB, 99 * GB, GB))
    lines = []

    assert cm.assert_disk_space(5, "/", log=lines.append) is False
    assert lines == ["[✗] CRITICAL: Disk space dropped below 5 GB (1.00 GB free). Stopping."]
    assert capsys.readouterr().out == ""


# ── REL-8: no exception text in what the user sees ─────────────────────────────


async def test_download_failure_is_a_plain_line_with_an_error_id(export, caplog):
    client = _Client(
        [_message(1, media=_photo()), _message(2, media=_document("video/mp4", 10)), _message(3, "next")]
    )
    client.download_error = RuntimeError("secret-detail from /app/data")

    with caplog.at_level(logging.ERROR):
        done = await export(client)

    failed = [line for line in done.log if "could not be downloaded" in line]
    assert len(failed) == 2
    ids = [re.fullmatch(rf"  \[!\] (?:Photo 1\.jpg|Video 2\.mp4) could not be downloaded\. Error id: ({ERROR_ID})", line) for line in failed]
    assert all(ids), failed
    shown = "\n".join(done.log) + json.dumps(done.messages)
    assert "secret-detail" not in shown and "RuntimeError" not in shown and "Traceback" not in shown
    assert [m["id"] for m in done.messages] == [1, 2, 3], "the run goes on"
    # The server log has each traceback under its id.
    for match in ids:
        record = next(r for r in caplog.records if match.group(1) in r.getMessage())
        assert record.exc_info and "secret-detail" in str(record.exc_info[1])


@pytest.mark.parametrize(
    "failure,expected",
    [
        (ValueError('No user has "durov" as username'), "Telegram has no public channel or group named @durov."),
        (tg_errors.UsernameNotOccupiedError(request=None), "Telegram has no public channel or group named @durov."),
        (tg_errors.UsernameInvalidError(request=None), "Telegram has no public channel or group named @durov."),
        (tg_errors.ChannelPrivateError(request=None), "@durov is private or closed to this account."),
        (
            tg_errors.FloodWaitError(request=None, capture=420),
            "Telegram asked this account to wait 420 seconds before more requests. Try again later.",
        ),
        (
            tg_errors.AuthKeyUnregisteredError(request=None),
            "Telegram no longer accepts the session. On the server, run: "
            "docker compose exec dashboard python -m darkweb_scanner.main channel-monitor-auth",
        ),
    ],
    ids=["ValueError", "not-occupied", "invalid", "private", "flood-wait", "session-revoked"],
)
async def test_known_telegram_errors_are_plain_sentences(tmp_path, failure, expected):
    with pytest.raises(cm.ChannelAccessError) as raised:
        await cm.process_channel(_Client(entity=failure), "durov", 10, tmp_path, log=lambda line: None)

    assert str(raised.value) == expected
    assert list(tmp_path.iterdir()) == []


async def test_unknown_error_while_opening_the_channel_is_an_error_id(tmp_path, caplog):
    failure = RuntimeError("secret-detail: connection to 149.154.167.51 reset")

    with caplog.at_level(logging.ERROR), pytest.raises(cm.ChannelAccessError) as raised:
        await cm.process_channel(_Client(entity=failure), "durov", 10, tmp_path, log=lambda line: None)

    match = re.fullmatch(rf"Could not open @durov\. Error id: ({ERROR_ID})", str(raised.value))
    assert match, str(raised.value)
    assert any(match.group(1) in r.getMessage() and r.exc_info for r in caplog.records)


def test_only_errors_with_something_to_do_get_a_sentence():
    assert cm.telegram_error_text(RuntimeError("x")) is None
    assert cm.telegram_error_text(ValueError("x")) is None
    flood = tg_errors.FloodWaitError(request=None, capture=5)
    flood.seconds = None
    assert "wait a while" in cm.telegram_error_text(flood)


def test_error_id_is_eight_hex_characters_and_the_traceback_is_logged(caplog):
    with caplog.at_level(logging.ERROR):
        try:
            raise RuntimeError("the reason")
        except RuntimeError:
            error_id = cm.log_exception("Channel Monitor: something failed")

    assert re.fullmatch(ERROR_ID, error_id)
    record = caplog.records[-1]
    assert error_id in record.getMessage() and record.exc_info[0] is RuntimeError


async def test_failed_translation_says_so_without_the_reason(export, monkeypatch, caplog):
    class Translator:
        def translate(self, text):
            raise RuntimeError("secret-detail: 429 from translate.google.com")

    monkeypatch.setattr(cm, "translate_text", _real_translate_text)
    monkeypatch.setattr(cm, "get_translator", lambda lang: Translator())
    assert cm.translate_text("Это сообщение", "ru") == "[Translation failed]" == cm.TRANSLATION_FAILED

    with caplog.at_level(logging.WARNING):
        done = await export([_message(1, "Это первое сообщение"), _message(2, "Это второе сообщение")], forced_lang="ru")

    assert [m["translated_en"] for m in done.messages] == ["[Translation failed]"] * 2
    assert "  [!] Translation failed for 2 message(s); the report marks them" in done.log
    assert "secret-detail" not in "\n".join(done.log) + json.dumps(done.messages)
    assert any("translation from ru failed: RuntimeError" in r.getMessage() for r in caplog.records)


# ── REL-6: the sign-in happens in a terminal, with a session file for its owner only ──


class _SignInClient:
    """Stands in for TelegramClient in interactive_auth; creates the session file as Telethon does."""

    made = []

    def __init__(self, session, api_id, api_hash):
        self.args = (session, api_id, api_hash)
        self.started_with = None
        self.disconnected = False
        Path(session + ".session").touch()
        type(self).made.append(self)

    async def start(self, **kwargs):
        self.started_with = kwargs
        return self

    async def get_me(self):
        return SimpleNamespace(first_name="Monitor", username="monitor_account")

    async def disconnect(self):
        self.disconnected = True


@pytest.fixture
def sign_in_client(monkeypatch):
    monkeypatch.setattr(_SignInClient, "made", [])
    monkeypatch.setattr(cm, "TelegramClient", _SignInClient)
    return _SignInClient


@pytest.mark.parametrize("phone,start_args", [("+10000000000", {"phone": "+10000000000"}), (None, {})])
async def test_sign_in_creates_the_session_file_for_its_owner_only(tmp_path, sign_in_client, capsys, phone, start_args):
    session = tmp_path / "data" / "channel_monitor" / "channel_monitor.session"
    umask_before = os.umask(0o022)

    try:
        await cm.interactive_auth(12345, "hash", phone=phone, session_path=session)
        assert os.umask(0o022) == 0o022, "the process umask is as it was"
    finally:
        os.umask(umask_before)

    (client,) = sign_in_client.made
    assert client.args == (str(session.with_suffix("")), 12345, "hash")
    assert client.started_with == start_args and client.disconnected
    assert stat.S_IMODE(session.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert "Signed in as: Monitor (@monitor_account)" in out and "hash" not in out


async def test_sign_in_tightens_a_session_file_that_was_readable_by_others(tmp_path, sign_in_client):
    session = tmp_path / "channel_monitor.session"
    session.touch()
    os.chmod(session, 0o644)

    await cm.interactive_auth(1, "h", session_path=session)

    assert stat.S_IMODE(session.stat().st_mode) == 0o600


def test_session_file_is_the_one_the_dashboard_uses(monkeypatch):
    monkeypatch.setenv("DATA_DIR", "/srv/data")
    assert cm.session_file() == Path("/srv/data/channel_monitor/channel_monitor.session")
    monkeypatch.delenv("DATA_DIR")
    assert cm.session_file() == Path("/app/data/channel_monitor/channel_monitor.session")
    assert cm.AUTH_COMMAND in cm.SESSION_NOT_SIGNED_IN and cm.AUTH_COMMAND.endswith("channel-monitor-auth")


def test_channel_monitor_auth_command(monkeypatch):
    from darkweb_scanner.main import cli

    calls = []

    async def interactive_auth(api_id, api_hash, phone=None, session_path=None):
        calls.append((api_id, api_hash, phone, session_path))

    monkeypatch.setattr(cm, "interactive_auth", interactive_auth)
    runner = CliRunner()

    for api_id, api_hash in (("", "hash"), ("12ab", "hash"), ("12345", "")):
        monkeypatch.setenv("TELEGRAM_API_ID", api_id)
        monkeypatch.setenv("TELEGRAM_API_HASH", api_hash)
        result = runner.invoke(cli, ["channel-monitor-auth"])
        assert result.exit_code == 1 and "TELEGRAM_API_ID" in result.output
    assert calls == []

    monkeypatch.setenv("TELEGRAM_API_ID", "12345")
    monkeypatch.setenv("TELEGRAM_API_HASH", "hash")
    monkeypatch.setenv("TELEGRAM_PHONE", "+10000000000")
    assert runner.invoke(cli, ["channel-monitor-auth"]).exit_code == 0
    monkeypatch.setenv("TELEGRAM_PHONE", "")
    assert runner.invoke(cli, ["channel-monitor-auth"]).exit_code == 0
    assert calls == [(12345, "hash", "+10000000000", None), (12345, "hash", None, None)]
    assert "channel-monitor-auth" in runner.invoke(cli, ["--help"]).output
