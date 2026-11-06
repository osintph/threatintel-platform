"""
Channel Monitor blueprint — Telegram channel scraping tab.
Integrates channel_monitor.py into the threat intelligence dashboard.

Every route is admin-only. Only public channels are accepted, each job belongs
to the user who started it, and archives are deleted after RETENTION_DAYS.
"""

import asyncio
import logging
import os
import re
import shutil
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, after_this_request, jsonify, request, send_file

from ..auth import current_user, require_admin

logger = logging.getLogger(__name__)

channel_monitor_bp = Blueprint("channel_monitor", __name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
CHANNEL_MONITOR_DIR = DATA_DIR / "channel_monitor"


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, default)))
    except ValueError:
        return default


# Job folders and leftover download ZIPs are deleted once they are this old.
RETENTION_DAYS = _env_int("CHANNEL_MONITOR_RETENTION_DAYS", 90, minimum=1)
_PURGE_INTERVAL_SECONDS = 3600

# Limits for the values a job is started with; numbers outside are clamped.
MAX_LIMIT = 100_000
MAX_DAYS = 3650
MAX_VIDEO_MB = 2000
MIN_SPACE_GB = 1.0
MAX_SPACE_GB = 1000.0

# Cap on total source bytes zipped for a single download. Building to a temp
# file (rather than streaming) is bounded by disk, not memory, but we still
# want a clear failure instead of silently filling the data volume.
MAX_DOWNLOAD_SOURCE_BYTES = int(os.getenv("CHANNEL_MONITOR_MAX_DOWNLOAD_GB", "5")) * (1024 ** 3)

# In-memory job store  { job_id: { status, log, output_dir, started_at, config, owner_id, owner } }
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()

_JOB_ID_RE = re.compile(r"[0-9a-f]{12}")
_last_purge: float | None = None
_purge_lock = threading.Lock()


def _ensure_dirs():
    CHANNEL_MONITOR_DIR.mkdir(parents=True, exist_ok=True)


def _new_job_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


def _monitor():
    """channel_monitor pulls in telethon and the translator; load it on first use."""
    from .. import channel_monitor
    return channel_monitor


# ── Ownership ─────────────────────────────────────────────────────────────────

def _can_access(job: dict, user) -> bool:
    """A job belongs to the user who started it; admins see every job."""
    return user is not None and (bool(user.is_admin) or job.get("owner_id") == user.id)


def _get_job(job_id: str):
    """The job, if the id is well formed and the current user may see it; else None."""
    if not _JOB_ID_RE.fullmatch(job_id or ""):
        return None
    user = current_user()
    with _jobs_lock:
        j = _jobs.get(job_id)
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
    """Delete job folders and leftover download ZIPs older than RETENTION_DAYS.

    Only names this module creates are touched (12-hex job folders and
    cm_download_*.zip), so the Telegram session file next to them stays. A
    running job is never removed. Returns the names that were deleted.
    """
    if not CHANNEL_MONITOR_DIR.is_dir():
        return []
    cutoff = (time.time() if now is None else now) - RETENTION_DAYS * 86400
    with _jobs_lock:
        running = {jid for jid, j in _jobs.items() if j["status"] == "running"}

    removed = []
    for entry in sorted(CHANNEL_MONITOR_DIR.iterdir()):
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir() and _JOB_ID_RE.fullmatch(entry.name):
                if entry.name in running or not _older_than(entry, cutoff):
                    continue
                shutil.rmtree(entry)
            elif entry.is_file() and entry.name.startswith("cm_download_") and entry.suffix == ".zip":
                if entry.stat().st_mtime >= cutoff:
                    continue
                entry.unlink()
            else:
                continue
        except OSError as exc:
            logger.warning("Channel Monitor retention: could not remove %s: %s", entry.name, exc)
            continue
        removed.append(entry.name)

    if removed:
        with _jobs_lock:
            for name in removed:
                _jobs.pop(name, None)
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
    })


# ── Job management ────────────────────────────────────────────────────────────

@channel_monitor_bp.route("/api/channel-monitor/jobs", methods=["GET"])
@require_admin
def api_cm_jobs_list():
    _purge_if_due()
    user = current_user()
    with _jobs_lock:
        jobs = []
        for jid, j in _jobs.items():
            if not _can_access(j, user):
                continue
            jobs.append({
                "id":         jid,
                "status":     j["status"],
                "channel":    j["config"].get("channel", ""),
                "owner":      j.get("owner"),
                "started_at": j["started_at"],
                "ended_at":   j.get("ended_at"),
                "log_lines":  len(j["log"]),
                "error":      j.get("error"),
            })
        jobs.sort(key=lambda x: x["started_at"], reverse=True)
        return jsonify(jobs)


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>", methods=["GET"])
@require_admin
def api_cm_job_get(job_id: str):
    j = _get_job(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "id":         job_id,
        "status":     j["status"],
        "channel":    j["config"].get("channel", ""),
        "owner":      j.get("owner"),
        "config":     j["config"],
        "started_at": j["started_at"],
        "ended_at":   j.get("ended_at"),
        "log":        j["log"],
        "error":      j.get("error"),
    })


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/log", methods=["GET"])
@require_admin
def api_cm_job_log(job_id: str):
    """Return only the log lines (optionally since a given index)."""
    since = max(0, request.args.get("since", 0, type=int))
    j = _get_job(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "status": j["status"],
        "log":    j["log"][since:],
        "total":  len(j["log"]),
    })


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/download", methods=["GET"])
@require_admin
def api_cm_job_download(job_id: str):
    """Build a ZIP of the job output directory to a temp file, then serve
    that file with a real Content-Length.

    Streaming the ZIP live from a generator (the old approach) meant no
    Content-Length and no way to answer a Range resume with anything but a
    fresh full 200 body — a client splicing that onto bytes it already had
    is exactly what produces a truncated archive with orphaned tail data
    and no End Of Central Directory record. Serving a file that's already
    complete on disk lets Flask's normal conditional/Range handling work
    correctly instead.
    """
    j = _get_job(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    if j["status"] not in ("completed", "error"):
        return jsonify({"error": "Job still running"}), 400

    output_dir = Path(j["output_dir"])
    if not output_dir.exists():
        return jsonify({"error": "Output directory not found"}), 404

    channel = j["config"].get("channel", "channel").replace("/", "_").replace("@", "")
    ts = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d_%H%M")
    zip_filename = f"channel_monitor_{channel}_{ts}.zip"

    files = sorted([f for f in output_dir.rglob("*") if f.is_file()])

    total_source_bytes = sum(f.stat().st_size for f in files)
    if total_source_bytes > MAX_DOWNLOAD_SOURCE_BYTES:
        return jsonify({
            "error": (
                f"Output directory is {total_source_bytes / (1024 ** 3):.2f} GB, "
                f"over the {MAX_DOWNLOAD_SOURCE_BYTES / (1024 ** 3):.0f} GB download "
                "cap. Retrieve the files directly from the server instead."
            )
        }), 413

    _ensure_dirs()
    fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="cm_download_", dir=CHANNEL_MONITOR_DIR)
    try:
        with os.fdopen(fd, "wb") as fh:
            with zipfile.ZipFile(fh, "w", zipfile.ZIP_STORED) as zf:
                for fpath in files:
                    arcname = str(fpath.relative_to(output_dir.parent))
                    zf.write(fpath, arcname)
            fh.flush()
            os.fsync(fh.fileno())
            bytes_written = fh.tell()

        # Integrity guard: what's on disk must match what we actually wrote,
        # and must parse as a well-formed archive (catches a truncated write
        # even when the byte count happens to line up).
        on_disk_size = os.path.getsize(tmp_path)
        if on_disk_size == 0 or on_disk_size != bytes_written:
            raise IOError(
                f"ZIP write mismatch for job {job_id}: wrote {bytes_written} "
                f"bytes but {on_disk_size} are on disk"
            )
        if not zipfile.is_zipfile(tmp_path):
            raise IOError(f"ZIP integrity check failed for job {job_id}: no valid EOCD record")
    except Exception as exc:
        os.unlink(tmp_path)
        return jsonify({"error": f"Failed to build ZIP: {exc}"}), 500

    @after_this_request
    def _cleanup_tmp_zip(response):
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return response

    return send_file(
        tmp_path,
        mimetype="application/zip",
        as_attachment=True,
        download_name=zip_filename,
    )


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>", methods=["DELETE"])
@require_admin
def api_cm_job_delete(job_id: str):
    if not _get_job(job_id):
        return jsonify({"error": "Job not found"}), 404
    with _jobs_lock:
        j = _jobs.get(job_id)
        if j is not None and j["status"] == "running":
            # Its worker is still writing into the folder.
            return jsonify({"error": "Job is still running"}), 409
        j = _jobs.pop(job_id, None)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    # Clean up output directory
    try:
        if j.get("output_dir"):
            shutil.rmtree(j["output_dir"], ignore_errors=True)
    except Exception:
        pass
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


def _float_field(body: dict, name: str, default: float, low: float, high: float) -> float:
    value = body.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        raise _BadRequest(f"{name} must be a number")
    return max(low, min(high, float(value)))


def _bool_field(body: dict, name: str, default: bool) -> bool:
    value = body.get(name)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise _BadRequest(f"{name} must be true or false")
    return value


def _job_config(body, monitor) -> dict:
    """Validate a start request. Raises _BadRequest or monitor.ChannelNotAllowed."""
    if not isinstance(body, dict):
        raise _BadRequest("Send a JSON object")

    lang = body.get("lang")
    if lang is None or lang == "":
        lang = None
    elif not isinstance(lang, str) or lang.strip().lower() not in monitor.SUPPORTED_LANGUAGES:
        raise _BadRequest("lang must be one of: " + ", ".join(monitor.SUPPORTED_LANGUAGES))
    else:
        lang = lang.strip().lower()

    return {
        "channel":      monitor.parse_public_channel(body.get("channel")),
        "limit":        _int_field(body, "limit", 200, 0, MAX_LIMIT),
        "days":         _int_field(body, "days", None, 0, MAX_DAYS) or None,
        "lang":         lang,
        "max_video_mb": _int_field(body, "max_video_mb", 50, 0, MAX_VIDEO_MB),
        "min_space_gb": _float_field(body, "min_space_gb", MIN_SPACE_GB, MIN_SPACE_GB, MAX_SPACE_GB),
        "skip_english": _bool_field(body, "skip_english", False),
        "translate":    _bool_field(body, "translate", True),
    }


def _start_worker(job_id: str, config: dict, output_dir: Path, creds: dict) -> None:
    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                _run_channel_monitor(job_id, config, output_dir, creds)
            )
        except Exception as e:
            import traceback
            with _jobs_lock:
                _jobs[job_id]["status"] = "error"
                _jobs[job_id]["error"] = str(e)
                _jobs[job_id]["ended_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
                _jobs[job_id]["log"].append(f"[✗] Fatal error: {e}")
                _jobs[job_id]["log"].append(traceback.format_exc())
        finally:
            loop.close()

    t = threading.Thread(target=run, daemon=True, name=f"cm_{job_id}")
    t.start()


@channel_monitor_bp.route("/api/channel-monitor/start", methods=["POST"])
@require_admin
def api_cm_start():
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

    _purge_if_due()
    user = current_user()

    job_id = _new_job_id()
    _ensure_dirs()
    output_dir = CHANNEL_MONITOR_DIR / job_id
    output_dir.mkdir(parents=True, exist_ok=True)

    job = {
        "status":     "running",
        "config":     config,
        "owner_id":   user.id,
        "owner":      user.username,
        "output_dir": str(output_dir),
        "started_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "ended_at":   None,
        "log":        [],
        "error":      None,
    }

    with _jobs_lock:
        _jobs[job_id] = job

    _start_worker(job_id, config, output_dir, creds)

    return jsonify({"ok": True, "job_id": job_id})


# ── The async worker that actually runs the monitor ───────────────────────────

async def _run_channel_monitor(job_id: str, config: dict, output_dir: Path, creds: dict):
    """Run channel_monitor logic inline, logging to the job's log list."""

    def log(msg: str):
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id]["log"].append(msg)

    log(f"[+] Starting channel monitor for: @{config['channel']}")
    log(f"[i] Settings: limit={config['limit']}, days={config['days']}, lang={config['lang']}, max_video={config['max_video_mb']}MB, min_free={config['min_space_gb']}GB, skip_english={config['skip_english']}, translate={config['translate']}")
    if config["translate"]:
        log("[i] Message text that is not English is sent to Google Translate (translate.google.com)")

    try:
        from telethon import TelegramClient
        monitor = _monitor()
    except ImportError as e:
        log(f"[✗] Import error: {e}")
        log("[i] Make sure telethon, deep-translator and langdetect are installed")
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(e)
            _jobs[job_id]["ended_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        return

    session_file = CHANNEL_MONITOR_DIR / "channel_monitor"

    try:
        client = TelegramClient(
            str(session_file),
            int(creds["api_id"]),
            creds["api_hash"],
        )
        await client.start(phone=creds["phone"])
        me = await client.get_me()
        log(f"[+] Connected as @{me.username or me.first_name}")
    except Exception as e:
        log(f"[✗] Telegram connection failed: {e}")
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(e)
            _jobs[job_id]["ended_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        return

    try:
        # Monkey-patch print so we capture output into job log
        import builtins
        _orig_print = builtins.print

        def _log_print(*args, **kwargs):
            msg = " ".join(str(a) for a in args)
            log(msg)
            _orig_print(*args, **kwargs)

        builtins.print = _log_print

        await monitor.process_channel(
            client=client,
            channel_id=config["channel"],
            limit=config["limit"],
            output_dir=output_dir,
            days=config["days"],
            min_space_gb=config["min_space_gb"],
            max_video_mb=config["max_video_mb"],
            forced_lang=config["lang"],
            skip_english=config["skip_english"],
            translate=config["translate"],
        )
    except (monitor.ChannelNotAllowed, monitor.ChannelAccessError) as e:
        # Refused before any message was read: not a public channel, or not found.
        log(f"[✗] {e}")
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(e)
    except Exception as e:
        import traceback
        log(f"[✗] Error during scan: {e}")
        log(traceback.format_exc())
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(e)
    else:
        with _jobs_lock:
            _jobs[job_id]["status"] = "completed"
        log("[✓] Scan completed successfully. Click Download to get results.")
    finally:
        builtins.print = _orig_print
        with _jobs_lock:
            _jobs[job_id]["ended_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        try:
            await client.disconnect()
        except Exception:
            pass
