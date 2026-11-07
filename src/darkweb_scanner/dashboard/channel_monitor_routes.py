"""
Channel Monitor blueprint — Telegram channel scraping tab.
Integrates channel_monitor.py into the threat intelligence dashboard.

Every route is admin-only. Only public channels are accepted, each job belongs
to the user who started it, and archives are deleted after RETENTION_DAYS.

One job runs at a time. A job's state is kept in its folder (job.json and
job.log), so the job list survives a restart; a folder without job.json is an
export made before v1.3.0 and is listed as "archived". The limits a job runs
under come from the environment, never from the request.
"""

import asyncio
import json
import logging
import math
import os
import re
import secrets
import shutil
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

from ..auth import current_user, require_admin

logger = logging.getLogger(__name__)

channel_monitor_bp = Blueprint("channel_monitor", __name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
CHANNEL_MONITOR_DIR = DATA_DIR / "channel_monitor"

MB = 1024 ** 2
GB = 1024 ** 3


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, default)))
    except ValueError:
        return default


def _env_float(name: str, default: float, minimum: float) -> float:
    try:
        value = float(os.getenv(name, default))
    except ValueError:
        return default
    return max(minimum, value) if math.isfinite(value) else default


# Job folders and their download ZIPs are deleted once they are this old.
RETENTION_DAYS = _env_int("CHANNEL_MONITOR_RETENTION_DAYS", 90, minimum=1)
_PURGE_INTERVAL_SECONDS = 3600

# What one job may use. Set on the server: a request can ask for less, never for more.
MAX_MESSAGES = _env_int("CHANNEL_MONITOR_MAX_MESSAGES", 5000, minimum=1)
# Every downloaded file that is not a video: photos and image documents.
MAX_FILE_MB = _env_int("CHANNEL_MONITOR_MAX_FILE_MB", 50, minimum=1)
# 0: videos are never downloaded.
MAX_VIDEO_MB = _env_int("CHANNEL_MONITOR_MAX_VIDEO_MB", 200, minimum=0)
# Media of one job. Past it the job goes on without media.
MAX_JOB_GB = _env_float("CHANNEL_MONITOR_MAX_JOB_GB", 2.0, minimum=0.1)
# Free disk space below which no job starts and a running one stops.
MIN_FREE_GB = _env_float("CHANNEL_MONITOR_MIN_FREE_GB", 5.0, minimum=1.0)

# Used when the start request leaves the value out.
DEFAULT_LIMIT = 200
DEFAULT_VIDEO_MB = 50
MAX_DAYS = 3650

# Cap on total source bytes zipped for a single download. Building to a file
# (rather than streaming) is bounded by disk, not memory, but we still
# want a clear failure instead of silently filling the data volume.
MAX_DOWNLOAD_SOURCE_BYTES = _env_int("CHANNEL_MONITOR_MAX_DOWNLOAD_GB", 5, minimum=1) * GB

STATUSES = ("running", "completed", "error", "interrupted", "archived")
_STORED_STATUSES = STATUSES[:4]  # "archived" is never written: it means "no job.json"

# In every job folder. job.json is the job's state and stays on the server (it
# names the owner); job.log is the log the page shows and is part of the download.
JOB_FILE = "job.json"
LOG_FILE = "job.log"
_NOT_IN_ZIP = frozenset({JOB_FILE, JOB_FILE + ".tmp"})
_STORED_FIELDS = ("id", "status", "channel", "owner_id", "owner", "config", "started_at", "ended_at", "error")

# The log keeps the first MAX_LOG_LINES lines of a job, each cut to
# MAX_LOG_LINE_CHARS characters, then one notice and the job's closing lines.
MAX_LOG_LINES = 20_000
MAX_LOG_LINE_CHARS = 500
_LOG_CLOSING_LINES = 8
_LOG_FULL = f"[i] Log limit reached ({MAX_LOG_LINES} lines). Later progress lines are not kept."

_INTERRUPTED = "The server restarted while this job was running. What it had saved by then is in the archive."

# The one job this process is running, or None; everything else is read from
# the job folders. _jobs_lock guards it and every read and write of a job.json.
_active: dict | None = None
_jobs_lock = threading.Lock()
# Held while a download ZIP is built, opened for sending, or deleted.
_zip_lock = threading.Lock()

_JOB_ID_RE = re.compile(r"[0-9a-f]{12}")
_ZIP_NAME_RE = re.compile(r"cm_download_([0-9a-f]{12})(?:\.part)?\.zip")
_ARCHIVE_NAME_MAX = 128
_unusable_reported: set[str] = set()
_last_purge: float | None = None
_purge_lock = threading.Lock()


def _ensure_dirs():
    CHANNEL_MONITOR_DIR.mkdir(parents=True, exist_ok=True)


def _new_job_id() -> str:
    return uuid.uuid4().hex[:12]


def _monitor():
    """channel_monitor pulls in telethon and the translator; load it on first use."""
    from .. import channel_monitor
    return channel_monitor


def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None).isoformat()


def _log_error(what: str) -> str:
    """Log the exception being handled, with its traceback, under a new error id.

    Returns the id (8 hex characters). Job logs and API answers carry a plain
    sentence and this id, never the exception text.
    """
    error_id = secrets.token_hex(4)
    logger.exception("%s [error_id=%s]", what, error_id)
    return error_id


def _free_gb() -> float:
    return shutil.disk_usage(CHANNEL_MONITOR_DIR).free / GB


def _session_file() -> Path:
    return CHANNEL_MONITOR_DIR / "channel_monitor.session"


def _owner_only(path: Path) -> None:
    """The Telegram session file holds the account's key: mode 600."""
    try:
        if path.stat().st_mode & 0o077:
            os.chmod(path, 0o600)
    except OSError:
        logger.warning("Channel Monitor: could not set mode 600 on %s", path.name)


# ── Job state on disk ─────────────────────────────────────────────────────────

def _job_dir(job_id: str) -> Path | None:
    """The job's folder: a real directory named like a job id, or None."""
    if not _JOB_ID_RE.fullmatch(job_id or ""):
        return None
    folder = CHANNEL_MONITOR_DIR / job_id
    if folder.is_symlink() or not folder.is_dir():
        return None
    return folder


def _write_job(job: dict) -> None:
    """Store the job's state in its folder. Caller holds _jobs_lock.

    Written to a temp file and renamed, so job.json is always a whole file.
    """
    folder = Path(job["output_dir"])
    data = {key: job.get(key) for key in _STORED_FIELDS}
    data["log_lines"] = len(job["log"]) if "log" in job else job.get("log_lines")
    tmp = folder / (JOB_FILE + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, folder / JOB_FILE)


def _stored_job(job_id: str, folder: Path) -> dict | None:
    """The job as its job.json describes it; None when there is no usable job.json."""
    path = folder / JOB_FILE
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = None
    if not isinstance(data, dict) or data.get("status") not in _STORED_STATUSES:
        if job_id not in _unusable_reported:  # once, not at every listing
            _unusable_reported.add(job_id)
            logger.warning("Channel Monitor: %s in job folder %s is not usable; listed as archived", JOB_FILE, job_id)
        return None

    def text(key):
        value = data.get(key)
        return value if isinstance(value, str) else None

    owner_id, log_lines = data.get("owner_id"), data.get("log_lines")
    return {
        "id":         job_id,
        "status":     data["status"],
        "channel":    text("channel") or "",
        "config":     data["config"] if isinstance(data.get("config"), dict) else {},
        "owner_id":   owner_id if type(owner_id) is int else None,
        "owner":      text("owner"),
        "output_dir": str(folder),
        "started_at": text("started_at") or _iso(folder.stat().st_mtime),
        "ended_at":   text("ended_at"),
        "error":      text("error"),
        "log_lines":  log_lines if type(log_lines) is int else None,
    }


def _archived_job(job_id: str, folder: Path) -> dict:
    """A job folder without job.json: an export made before v1.3.0.

    Nothing inside its files is read. The channel is the name of its one
    sub-folder (the channel's user name; its title in older exports) when that
    is letters, digits and underscores only. The times are file times.
    """
    channel, times = "", [folder.stat().st_mtime]
    try:
        subdirs = [p for p in folder.iterdir() if p.is_dir() and not p.is_symlink()]
    except OSError:
        subdirs = []
    if len(subdirs) == 1:
        name = subdirs[0].name
        if len(name) <= _ARCHIVE_NAME_MAX and all(c.isalnum() or c == "_" for c in name):
            channel = name
        for report in ("messages.json", "messages.html"):
            try:
                times.append((subdirs[0] / report).stat().st_mtime)
            except OSError:
                pass
    return {
        "id":         job_id,
        "status":     "archived",
        "channel":    channel,
        "config":     {"channel": channel},
        "owner_id":   None,
        "owner":      None,
        "output_dir": str(folder),
        "started_at": _iso(min(times)),
        "ended_at":   _iso(max(times)),
        "error":      None,
        "log_lines":  None,
    }


def _read_log(folder: Path) -> list[str]:
    """The stored log of a job that is not running: never more than a job can write."""
    try:
        with open(folder / LOG_FILE, encoding="utf-8", errors="replace") as fh:
            return [
                line.rstrip("\n")[:MAX_LOG_LINE_CHARS]
                for line in islice(fh, MAX_LOG_LINES + _LOG_CLOSING_LINES)
            ]
    except OSError:
        return []


def _settle_interrupted(job: dict, folder: Path) -> None:
    """Close a job stored as running that this process is not running.

    Its worker went with an earlier process. The end time is when the job last
    wrote something. Caller holds _jobs_lock.
    """
    times = []
    for name in (LOG_FILE, JOB_FILE):
        try:
            times.append((folder / name).stat().st_mtime)
        except OSError:
            pass
    job.update(status="interrupted", error=_INTERRUPTED, ended_at=_iso(max(times) if times else time.time()))
    try:
        with open(folder / LOG_FILE, "a", encoding="utf-8", errors="replace") as fh:
            fh.write(f"[✗] {_INTERRUPTED}\n")
        job["log_lines"] = len(_read_log(folder))
        _write_job(job)
    except OSError:
        logger.warning("Channel Monitor: could not store the interrupted state of job %s", job["id"], exc_info=True)
    logger.warning("Channel Monitor: job %s was running when the server stopped; now interrupted", job["id"])


def _snapshot(job_id: str, with_log: bool = False) -> dict | None:
    """The job as it is now, or None when there is no such job. Caller holds _jobs_lock.

    The running job comes from memory, every other one from its folder. The
    answer is a copy; with ``with_log`` it carries the log lines.
    """
    if _active is not None and _active["id"] == job_id:
        job = dict(_active)
        log = job.pop("log")
        job["log_lines"] = len(log)
        if with_log:
            job["log"] = list(log)
        return job

    folder = _job_dir(job_id)
    if folder is None:
        return None
    job = _stored_job(job_id, folder)
    if job is None:
        job = _archived_job(job_id, folder)
    elif job["status"] == "running":
        _settle_interrupted(job, folder)
    if with_log:
        job["log"] = _read_log(folder)
        job["log_lines"] = len(job["log"])
    elif job["log_lines"] is None:
        job["log_lines"] = len(_read_log(folder))
    return job


def load_jobs() -> list[dict]:
    """Every job there is: the running one from memory, the others from their folders.

    Reading settles what an earlier process left behind: a job stored as
    running that this process is not running becomes "interrupted". Called at
    application start (through purge_expired_archives) and for every listing.
    """
    if not CHANNEL_MONITOR_DIR.is_dir():
        return []
    jobs = []
    with _jobs_lock:
        for entry in sorted(CHANNEL_MONITOR_DIR.iterdir()):
            try:
                job = _snapshot(entry.name)
            except OSError as exc:
                logger.warning("Channel Monitor: could not read job folder %s: %s", entry.name, type(exc).__name__)
                continue
            if job is not None:
                jobs.append(job)
    return jobs


# ── Job log ───────────────────────────────────────────────────────────────────

def _clean_line(msg) -> str:
    """One log line: no line breaks or control characters, at most MAX_LOG_LINE_CHARS."""
    line = "".join(c if c.isprintable() else " " for c in str(msg)).rstrip()
    if len(line) > MAX_LOG_LINE_CHARS:
        line = line[:MAX_LOG_LINE_CHARS - 1] + "…"
    return line


def _append_log(job: dict, line: str, final: bool = False) -> None:
    """Add a line to the running job's log, in memory and in job.log. Caller holds _jobs_lock.

    Past MAX_LOG_LINES only ``final`` lines (how the job ended) are still kept.
    """
    kept = len(job["log"])
    if not final and kept >= MAX_LOG_LINES:
        if kept > MAX_LOG_LINES:
            return
        line = _LOG_FULL
    job["log"].append(line)
    try:
        with open(Path(job["output_dir"]) / LOG_FILE, "a", encoding="utf-8", errors="replace") as fh:
            fh.write(line + "\n")
    except OSError:
        if not job.get("log_file_failed"):
            job["log_file_failed"] = True
            logger.warning("Channel Monitor: could not write %s of job %s", LOG_FILE, job["id"], exc_info=True)


def _log(job: dict, msg) -> None:
    line = _clean_line(msg)
    if line.strip():
        with _jobs_lock:
            _append_log(job, line)


# ── Ownership ─────────────────────────────────────────────────────────────────

def _can_access(job: dict, user) -> bool:
    """A job belongs to the user who started it; admins see every job."""
    return user is not None and (bool(user.is_admin) or job.get("owner_id") == user.id)


def _get_job(job_id: str, with_log: bool = False):
    """A copy of the job, if the id is well formed and the current user may see it; else None."""
    if not _JOB_ID_RE.fullmatch(job_id or ""):
        return None
    user = current_user()
    with _jobs_lock:
        j = _snapshot(job_id, with_log)
    if j is None or not _can_access(j, user):
        return None
    return j


# ── Retention ─────────────────────────────────────────────────────────────────

def _older_than(path: Path, cutoff: float) -> bool:
    """True when neither ``path`` nor anything under it changed since ``cutoff``."""
    if path.stat().st_mtime >= cutoff:
        return False
    return not any(p.lstat().st_mtime >= cutoff for p in path.rglob("*"))


def purge_expired_archives(now: float | None = None) -> list[str]:
    """Delete job folders and download ZIPs older than RETENTION_DAYS.

    Runs at application start and then at most once an hour. It first settles
    the job state on disk (load_jobs), so a job that was running when the
    server stopped is "interrupted" from the start. Only names this module
    creates are touched (12-hex job folders and cm_download_*.zip), so the
    Telegram session file next to them stays. A running job is never removed;
    the ZIP of a job goes with its folder. Returns the names that were deleted.
    """
    if not CHANNEL_MONITOR_DIR.is_dir():
        return []
    load_jobs()
    cutoff = (time.time() if now is None else now) - RETENTION_DAYS * 86400
    with _jobs_lock:
        active_id = _active["id"] if _active is not None else None

    def expired_folder(entry: Path) -> bool:
        if not (entry.is_dir() and _JOB_ID_RE.fullmatch(entry.name)):
            return False
        return entry.name != active_id and _older_than(entry, cutoff)

    def expired_zip(entry: Path) -> bool:
        if not (entry.is_file() and entry.name.startswith("cm_download_") and entry.suffix == ".zip"):
            return False
        match = _ZIP_NAME_RE.fullmatch(entry.name)
        if match and not (CHANNEL_MONITOR_DIR / match.group(1)).is_dir():
            return True  # its job folder is gone
        return entry.stat().st_mtime < cutoff

    removed = []
    entries = sorted(CHANNEL_MONITOR_DIR.iterdir())
    # Folders first, so that the ZIP of a folder removed here goes in the same sweep.
    for expired, remove in ((expired_folder, shutil.rmtree), (expired_zip, Path.unlink)):
        for entry in entries:
            try:
                if entry.is_symlink() or not expired(entry):
                    continue
                remove(entry)
            except OSError as exc:
                logger.warning("Channel Monitor retention: could not remove %s: %s", entry.name, exc)
                continue
            removed.append(entry.name)

    if removed:
        logger.info(
            "Channel Monitor retention: removed %d archive(s) older than %d days: %s",
            len(removed), RETENTION_DAYS, ", ".join(removed),
        )
    return removed


def _purge_if_due() -> None:
    """Run the retention sweep at most once per _PURGE_INTERVAL_SECONDS."""
    global _last_purge
    with _purge_lock:
        now = time.monotonic()
        if _last_purge is not None and now - _last_purge < _PURGE_INTERVAL_SECONDS:
            return
        _last_purge = now
    try:
        purge_expired_archives()
    except Exception:
        logger.exception("Channel Monitor retention sweep failed")


def _get_telegram_creds() -> dict:
    """Read Telegram API creds from env or DATA_DIR/.env style file."""
    return {
        "api_id":    os.getenv("TELEGRAM_API_ID", ""),
        "api_hash":  os.getenv("TELEGRAM_API_HASH", ""),
        "phone":     os.getenv("TELEGRAM_PHONE", ""),
    }


# ── Status / Credential check ─────────────────────────────────────────────────

@channel_monitor_bp.route("/api/channel-monitor/credentials", methods=["GET"])
@require_admin
def api_cm_credentials():
    """Return whether Telegram credentials are configured, and the policy the UI states."""
    creds = _get_telegram_creds()
    configured = bool(creds["api_id"] and creds["api_hash"] and creds["phone"])
    return jsonify({
        "configured": configured,
        "has_api_id":   bool(creds["api_id"]),
        "has_api_hash": bool(creds["api_hash"]),
        "has_phone":    bool(creds["phone"]),
        "public_channels_only": True,
        "translation":    "google",
        "retention_days": RETENTION_DAYS,
        "limits": {
            "max_messages": MAX_MESSAGES,
            "max_video_mb": MAX_VIDEO_MB,
            "max_file_mb":  MAX_FILE_MB,
            "max_job_gb":   MAX_JOB_GB,
        },
    })


# ── Job management ────────────────────────────────────────────────────────────

def _public(job: dict) -> dict:
    return {
        "id":         job["id"],
        "status":     job["status"],
        "channel":    job["channel"],
        "owner":      job.get("owner"),
        "started_at": job["started_at"],
        "ended_at":   job.get("ended_at"),
        "error":      job.get("error"),
    }


@channel_monitor_bp.route("/api/channel-monitor/jobs", methods=["GET"])
@require_admin
def api_cm_jobs_list():
    _purge_if_due()
    user = current_user()
    jobs = [
        dict(_public(j), log_lines=j["log_lines"])
        for j in load_jobs() if _can_access(j, user)
    ]
    jobs.sort(key=lambda x: x["started_at"], reverse=True)
    return jsonify(jobs)


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>", methods=["GET"])
@require_admin
def api_cm_job_get(job_id: str):
    j = _get_job(job_id, with_log=True)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(dict(_public(j), config=j["config"], log=j["log"]))


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/log", methods=["GET"])
@require_admin
def api_cm_job_log(job_id: str):
    """Return only the log lines (optionally since a given index)."""
    since = max(0, request.args.get("since", 0, type=int))
    j = _get_job(job_id, with_log=True)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "status": j["status"],
        "log":    j["log"][since:],
        "total":  len(j["log"]),
    })


class _ZipRefused(Exception):
    """The ZIP is not built; the message and ``status`` are the answer."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _build_zip(job_id: str, files: list[Path], output_dir: Path, zip_path: Path) -> None:
    """Write the ZIP under a temporary name and rename it once it is whole."""
    part = zip_path.with_name(f"cm_download_{job_id}.part.zip")
    try:
        with open(part, "wb") as fh:
            with zipfile.ZipFile(fh, "w", zipfile.ZIP_STORED) as zf:
                for fpath in files:
                    zf.write(fpath, str(fpath.relative_to(output_dir.parent)))
            fh.flush()
            os.fsync(fh.fileno())
            bytes_written = fh.tell()

        # Integrity guard: what's on disk must match what we actually wrote,
        # and must parse as a well-formed archive (catches a truncated write
        # even when the byte count happens to line up).
        on_disk_size = os.path.getsize(part)
        if on_disk_size == 0 or on_disk_size != bytes_written:
            raise IOError(
                f"ZIP write mismatch for job {job_id}: wrote {bytes_written} "
                f"bytes but {on_disk_size} are on disk"
            )
        if not zipfile.is_zipfile(part):
            raise IOError(f"ZIP integrity check failed for job {job_id}: no valid EOCD record")
        os.replace(part, zip_path)
    except BaseException:
        part.unlink(missing_ok=True)
        raise


def _job_zip(job_id: str, output_dir: Path) -> Path:
    """The job's ZIP. Caller holds _zip_lock.

    Built once, then reused for as long as it is newer than everything in the
    job folder. job.json stays out of it: it names the owner.
    """
    zip_path = CHANNEL_MONITOR_DIR / f"cm_download_{job_id}.zip"
    entries = [output_dir, *sorted(output_dir.rglob("*"))]
    newest = max(p.lstat().st_mtime_ns for p in entries)
    if (
        zip_path.is_file()
        and not zip_path.is_symlink()
        and zip_path.stat().st_mtime_ns > newest
        and zipfile.is_zipfile(zip_path)
    ):
        return zip_path

    files = [
        p for p in entries[1:]
        if p.is_file() and not p.is_symlink() and not (p.parent == output_dir and p.name in _NOT_IN_ZIP)
    ]
    total = sum(f.stat().st_size for f in files)
    if total > MAX_DOWNLOAD_SOURCE_BYTES:
        raise _ZipRefused(413, (
            f"Output directory is {total / GB:.2f} GB, "
            f"over the {MAX_DOWNLOAD_SOURCE_BYTES / GB:.0f} GB download "
            "cap. Retrieve the files directly from the server instead."
        ))
    free = _free_gb()
    if free - total / GB < MIN_FREE_GB:
        raise _ZipRefused(507, (
            f"Not enough free disk space on the server to build the ZIP: it takes {total / GB:.2f} GB "
            f"and {MIN_FREE_GB:g} GB must stay free ({free:.1f} GB are free). Delete jobs that are no longer needed."
        ))
    _build_zip(job_id, files, output_dir, zip_path)
    return zip_path


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/download", methods=["GET"])
@require_admin
def api_cm_job_download(job_id: str):
    """Serve the job's ZIP from a file on disk, with a real Content-Length.

    Streaming the ZIP live from a generator (the old approach) meant no
    Content-Length and no way to answer a Range resume with anything but a
    fresh full 200 body — a client splicing that onto bytes it already had
    is exactly what produces a truncated archive with orphaned tail data
    and no End Of Central Directory record. Serving a file that's already
    complete on disk lets Flask's normal conditional/Range handling work
    correctly instead. The file is kept (one per job) and reused by later
    downloads until the job folder changes.
    """
    j = _get_job(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    if j["status"] == "running":
        return jsonify({"error": "Job still running"}), 400

    output_dir = Path(j["output_dir"])
    channel = j["channel"] if re.fullmatch(r"[A-Za-z0-9_]{1,64}", j["channel"] or "") else job_id
    ts = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d_%H%M")
    zip_filename = f"channel_monitor_{channel}_{ts}.zip"

    with _zip_lock:
        if not output_dir.is_dir():
            return jsonify({"error": "Output directory not found"}), 404
        try:
            zip_path = _job_zip(job_id, output_dir)
        except _ZipRefused as refused:
            return jsonify({"error": str(refused)}), refused.status
        except Exception:
            error_id = _log_error(f"Channel Monitor: building the ZIP of job {job_id} failed")
            return jsonify({"error": "The ZIP could not be built.", "error_id": error_id}), 500
        # send_file opens the file here, under the lock: a rebuild or a delete
        # that comes later cannot change what this response sends.
        return send_file(
            zip_path,
            mimetype="application/zip",
            as_attachment=True,
            download_name=zip_filename,
        )


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>", methods=["DELETE"])
@require_admin
def api_cm_job_delete(job_id: str):
    if not _get_job(job_id):
        return jsonify({"error": "Job not found"}), 404
    with _zip_lock:
        with _jobs_lock:
            if _active is not None and _active["id"] == job_id:
                # Its worker is still writing into the folder.
                return jsonify({"error": "Job is still running"}), 409
            folder = _job_dir(job_id)
            if folder is None:
                return jsonify({"error": "Job not found"}), 404
            try:
                shutil.rmtree(folder)
            except OSError:
                error_id = _log_error(f"Channel Monitor: deleting job folder {job_id} failed")
                return jsonify({"error": "The job folder could not be deleted.", "error_id": error_id}), 500
        for name in (f"cm_download_{job_id}.zip", f"cm_download_{job_id}.part.zip"):
            try:
                (CHANNEL_MONITOR_DIR / name).unlink(missing_ok=True)
            except OSError:
                logger.warning("Channel Monitor: could not remove %s", name)
    return jsonify({"ok": True})


# ── Start a scan ──────────────────────────────────────────────────────────────

class _BadRequest(ValueError):
    """A value in the start request has the wrong type."""


def _int_field(body: dict, name: str, default, low: int, high: int):
    value = body.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _BadRequest(f"{name} must be a whole number")
    return max(low, min(high, value))


def _bool_field(body: dict, name: str, default: bool) -> bool:
    value = body.get(name)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise _BadRequest(f"{name} must be true or false")
    return value


def _job_config(body, monitor) -> dict:
    """Validate a start request. Raises _BadRequest or monitor.ChannelNotAllowed.

    Numbers are clamped to the server's limits. How much disk space must stay
    free is the server's setting alone; the request has no say in it.
    """
    if not isinstance(body, dict):
        raise _BadRequest("Send a JSON object")

    lang = body.get("lang")
    if lang is None or lang == "":
        lang = None
    elif not isinstance(lang, str) or lang.strip().lower() not in monitor.SUPPORTED_LANGUAGES:
        raise _BadRequest("lang must be one of: " + ", ".join(monitor.SUPPORTED_LANGUAGES))
    else:
        lang = lang.strip().lower()

    # 0 or less, like a missing value, means the default: there is no "all messages".
    limit = _int_field(body, "limit", 0, 0, MAX_MESSAGES) or min(DEFAULT_LIMIT, MAX_MESSAGES)

    return {
        "channel":      monitor.parse_public_channel(body.get("channel")),
        "limit":        limit,
        "days":         _int_field(body, "days", None, 0, MAX_DAYS) or None,
        "lang":         lang,
        "max_video_mb": _int_field(body, "max_video_mb", min(DEFAULT_VIDEO_MB, MAX_VIDEO_MB), 0, MAX_VIDEO_MB),
        "skip_english": _bool_field(body, "skip_english", False),
        "translate":    _bool_field(body, "translate", True),
    }


def _busy_text(job: dict) -> str:
    started = str(job["started_at"])[:16].replace("T", " ")
    return (
        f"A job is already running: @{job['channel']}, started {started} UTC by {job.get('owner') or 'unknown'}. "
        "Only one job runs at a time; start yours when it has finished."
    )


def _start_worker(job_id: str, creds: dict) -> threading.Thread:
    t = threading.Thread(target=_run_job, args=(job_id, creds), daemon=True, name=f"cm_{job_id}")
    t.start()
    return t


@channel_monitor_bp.route("/api/channel-monitor/start", methods=["POST"])
@require_admin
def api_cm_start():
    global _active
    try:
        monitor = _monitor()
    except ImportError:
        logger.exception("Channel Monitor dependencies are missing")
        return jsonify({"error": "Channel Monitor is not available: telethon, deep-translator and langdetect must be installed"}), 503

    try:
        config = _job_config(request.get_json(silent=True), monitor)
    except (_BadRequest, monitor.ChannelNotAllowed) as e:
        return jsonify({"error": str(e)}), 400

    creds = _get_telegram_creds()
    if not (creds["api_id"] and creds["api_hash"] and creds["phone"]):
        return jsonify({"error": "Telegram credentials not configured. Add TELEGRAM_API_ID, TELEGRAM_API_HASH and TELEGRAM_PHONE to your .env"}), 400
    if not creds["api_id"].strip().isdigit():
        return jsonify({"error": "TELEGRAM_API_ID in .env must be a number"}), 400

    _purge_if_due()
    user = current_user()
    _ensure_dirs()

    with _jobs_lock:
        if _active is not None:
            return jsonify({"error": _busy_text(_active)}), 409

        free = _free_gb()
        if free < MIN_FREE_GB:
            return jsonify({"error": (
                f"Not enough free disk space on the server: {free:.1f} GB are free, "
                f"a job needs {MIN_FREE_GB:g} GB. Delete jobs that are no longer needed."
            )}), 507

        job_id = _new_job_id()
        while (CHANNEL_MONITOR_DIR / job_id).exists():
            job_id = _new_job_id()
        output_dir = CHANNEL_MONITOR_DIR / job_id
        job = {
            "id":         job_id,
            "status":     "running",
            "channel":    config["channel"],
            "config":     config,
            "owner_id":   user.id,
            "owner":      user.username,
            "output_dir": str(output_dir),
            "started_at": _now(),
            "ended_at":   None,
            "log":        [],
            "error":      None,
        }
        try:
            output_dir.mkdir()
            _write_job(job)
        except OSError:
            error_id = _log_error(f"Channel Monitor: creating job folder {job_id} failed")
            shutil.rmtree(output_dir, ignore_errors=True)
            return jsonify({"error": "The job folder could not be created.", "error_id": error_id}), 500
        _active = job

    logger.info("Channel Monitor: job %s started by %s for @%s", job_id, user.username, config["channel"])
    try:
        _start_worker(job_id, creds)
    except Exception:
        error_id = _log_error(f"Channel Monitor: starting the worker of job {job_id} failed")
        _finish_job(job, "error", f"The job could not be started. Error id: {error_id}")
        return jsonify({"error": "The job could not be started.", "error_id": error_id}), 500

    return jsonify({"ok": True, "job_id": job_id})


# ── The worker that actually runs the monitor ─────────────────────────────────

def _finish_job(job: dict, status: str, error: str | None) -> None:
    """Give the job its final status and end time, store them, and free the slot."""
    global _active
    with _jobs_lock:
        try:
            if status == "completed":
                closing = "[✓] Scan completed successfully. Click Download to get results."
            else:
                closing = _clean_line(f"[✗] {error}")
            _append_log(job, closing, final=True)
            job.update(status=status, error=error, ended_at=_now())
            _write_job(job)
        except Exception:
            # job.json still says "running"; the next read turns that into "interrupted".
            logger.exception("Channel Monitor: could not store the final state of job %s", job["id"])
        finally:
            if _active is job:
                _active = None
    logger.info("Channel Monitor: job %s ended with status %s", job["id"], status)


def _run_job(job_id: str, creds: dict) -> None:
    """Thread body: run the export on an event loop of its own.

    Whatever happens in there, cancellation and BaseException included, the
    finally leaves the job with a final status and an end time and frees the
    slot for the next job.
    """
    with _jobs_lock:
        job = _active if _active is not None and _active["id"] == job_id else None
    if job is None:
        return
    # What the job ends as when nothing below gets to say otherwise.
    status, error = "interrupted", "The job stopped before it finished."
    loop = None
    try:
        loop = asyncio.new_event_loop()
        status, error = loop.run_until_complete(_run_channel_monitor(job, creds))
    except Exception:
        error_id = _log_error(f"Channel Monitor: job {job_id} failed")
        status, error = "error", f"The scan stopped on an unexpected error. Error id: {error_id}"
    except BaseException:
        # Cancellation, SystemExit and the like. Nothing above this thread
        # waits for them, so they end here; the job is over all the same.
        error_id = _log_error(f"Channel Monitor: job {job_id} was stopped")
        status, error = "interrupted", f"The job was stopped before it finished. Error id: {error_id}"
    finally:
        _finish_job(job, status, error)
        if loop is not None:
            loop.close()


async def _run_channel_monitor(job: dict, creds: dict) -> tuple[str, str | None]:
    """Run one export. Returns the final status and, unless it completed, the reason."""
    config = job["config"]

    def log(msg):
        _log(job, msg)

    log(f"[+] Starting channel monitor for: @{config['channel']}")
    log(
        f"[i] Settings: limit={config['limit']}, days={config['days']}, lang={config['lang']}, "
        f"max_video={config['max_video_mb']}MB, skip_english={config['skip_english']}, translate={config['translate']}"
    )
    log(
        f"[i] Server limits: files up to {MAX_FILE_MB} MB, videos up to {MAX_VIDEO_MB} MB, "
        f"media up to {MAX_JOB_GB:g} GB per job; a job stops when less than {MIN_FREE_GB:g} GB of disk space is free"
    )
    if config["translate"]:
        log("[i] Message text that is not English is sent to Google Translate (translate.google.com)")

    from telethon import TelegramClient
    monitor = _monitor()

    # A job never signs in: client.start() would make Telegram send a login
    # code. It uses the session as it is, or says how to sign it in.
    session_file = _session_file()
    if not session_file.is_file():
        return "error", monitor.SESSION_NOT_SIGNED_IN
    _owner_only(session_file)

    client = None
    try:
        try:
            client = TelegramClient(str(session_file.with_suffix("")), int(creds["api_id"]), creds["api_hash"])
            await client.connect()
            authorized = await client.is_user_authorized()
        except Exception as e:
            reason = monitor.telegram_error_text(e)
            if reason is None:
                error_id = _log_error(f"Channel Monitor: job {job['id']} could not connect to Telegram")
                reason = f"Could not connect to Telegram. Error id: {error_id}"
            return "error", reason
        if not authorized:
            return "error", monitor.SESSION_NOT_SIGNED_IN
        log("[+] Connected to Telegram")

        try:
            summary = await monitor.process_channel(
                client=client,
                channel_id=config["channel"],
                limit=config["limit"],
                output_dir=Path(job["output_dir"]),
                days=config["days"],
                min_space_gb=MIN_FREE_GB,
                max_video_mb=config["max_video_mb"],
                forced_lang=config["lang"],
                skip_english=config["skip_english"],
                translate=config["translate"],
                max_file_mb=MAX_FILE_MB,
                max_job_gb=MAX_JOB_GB,
                log=log,
            )
        except (monitor.ChannelNotAllowed, monitor.ChannelAccessError) as e:
            # Refused before any message was read: not a public channel, or not found.
            return "error", str(e)
        except Exception as e:
            reason = monitor.telegram_error_text(e)
            if reason is None:
                error_id = _log_error(f"Channel Monitor: job {job['id']} failed during the scan")
                reason = f"The scan stopped on an unexpected error. Error id: {error_id}"
            return "error", reason
    finally:
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                logger.warning("Channel Monitor: disconnect after job %s failed", job["id"], exc_info=True)

    if summary.get("stopped") == "disk":
        return "error", (
            f"Stopped: less than {MIN_FREE_GB:g} GB of disk space is free on the server. "
            "The messages read until then are in the archive."
        )
    return "completed", None
