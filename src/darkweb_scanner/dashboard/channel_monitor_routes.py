"""
Channel Monitor blueprint — Telegram channel scraping tab.
Integrates channel_monitor.py into the threat intelligence dashboard.
"""

import asyncio
import io
import json
import os
import shutil
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, jsonify, request, session, stream_with_context

from ..auth import require_login
from .storage_helper import get_storage

channel_monitor_bp = Blueprint("channel_monitor", __name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
CHANNEL_MONITOR_DIR = DATA_DIR / "channel_monitor"

# In-memory job store  { job_id: { status, log, output_dir, started_at, config } }
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _ensure_dirs():
    CHANNEL_MONITOR_DIR.mkdir(parents=True, exist_ok=True)


def _new_job_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


def _get_telegram_creds() -> dict:
    """Read Telegram API creds from env or DATA_DIR/.env style file."""
    return {
        "api_id":    os.getenv("TELEGRAM_API_ID", ""),
        "api_hash":  os.getenv("TELEGRAM_API_HASH", ""),
        "phone":     os.getenv("TELEGRAM_PHONE", ""),
    }


# ── Status / Credential check ─────────────────────────────────────────────────

@channel_monitor_bp.route("/api/channel-monitor/credentials", methods=["GET"])
@require_login
def api_cm_credentials():
    """Return whether Telegram credentials are configured."""
    creds = _get_telegram_creds()
    configured = bool(creds["api_id"] and creds["api_hash"] and creds["phone"])
    return jsonify({
        "configured": configured,
        "has_api_id":   bool(creds["api_id"]),
        "has_api_hash": bool(creds["api_hash"]),
        "has_phone":    bool(creds["phone"]),
    })


# ── Job management ────────────────────────────────────────────────────────────

@channel_monitor_bp.route("/api/channel-monitor/jobs", methods=["GET"])
@require_login
def api_cm_jobs_list():
    with _jobs_lock:
        jobs = []
        for jid, j in _jobs.items():
            jobs.append({
                "id":         jid,
                "status":     j["status"],
                "channel":    j["config"].get("channel", ""),
                "started_at": j["started_at"],
                "ended_at":   j.get("ended_at"),
                "log_lines":  len(j["log"]),
                "error":      j.get("error"),
            })
        jobs.sort(key=lambda x: x["started_at"], reverse=True)
        return jsonify(jobs)


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>", methods=["GET"])
@require_login
def api_cm_job_get(job_id: str):
    with _jobs_lock:
        j = _jobs.get(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "id":         job_id,
        "status":     j["status"],
        "channel":    j["config"].get("channel", ""),
        "config":     j["config"],
        "started_at": j["started_at"],
        "ended_at":   j.get("ended_at"),
        "log":        j["log"],
        "error":      j.get("error"),
    })


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/log", methods=["GET"])
@require_login
def api_cm_job_log(job_id: str):
    """Return only the log lines (optionally since a given index)."""
    since = int(request.args.get("since", 0))
    with _jobs_lock:
        j = _jobs.get(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "status": j["status"],
        "log":    j["log"][since:],
        "total":  len(j["log"]),
    })


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/download", methods=["GET"])
@require_login
def api_cm_job_download(job_id: str):
    """Stream a ZIP of the job output directory without buffering in memory."""
    with _jobs_lock:
        j = _jobs.get(job_id)
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

    def generate():
        """Yield ZIP data using ZIP_STORED (no compression).
        Photos/videos are already compressed — deflating wastes CPU and
        delays the first byte sent to the browser."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            for fpath in files:
                arcname = str(fpath.relative_to(output_dir.parent))
                zf.write(fpath, arcname)
                buf.seek(0)
                chunk = buf.read()
                buf.seek(0)
                buf.truncate(0)
                if chunk:
                    yield chunk
        # Flush ZIP central directory / end record
        buf.seek(0)
        remaining = buf.read()
        if remaining:
            yield remaining

    return Response(
        stream_with_context(generate()),
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename={zip_filename}"},
    )


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>", methods=["DELETE"])
@require_login
def api_cm_job_delete(job_id: str):
    with _jobs_lock:
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

@channel_monitor_bp.route("/api/channel-monitor/start", methods=["POST"])
@require_login
def api_cm_start():
    body = request.get_json() or {}

    channel = (body.get("channel") or "").strip().lstrip("@")
    if not channel:
        return jsonify({"error": "channel is required"}), 400

    creds = _get_telegram_creds()
    if not (creds["api_id"] and creds["api_hash"] and creds["phone"]):
        return jsonify({"error": "Telegram credentials not configured. Add TELEGRAM_API_ID, TELEGRAM_API_HASH and TELEGRAM_PHONE to your .env"}), 400

    config = {
        "channel":      channel,
        "limit":        int(body.get("limit", 200)),
        "days":         int(body.get("days")) if body.get("days") else None,
        "lang":         (body.get("lang") or "").strip() or None,
        "max_video_mb": int(body.get("max_video_mb", 50)),
        "min_space_gb": float(body.get("min_space_gb", 1.0)),
        "skip_english": bool(body.get("skip_english", False)),
    }

    job_id = _new_job_id()
    _ensure_dirs()
    output_dir = CHANNEL_MONITOR_DIR / job_id
    output_dir.mkdir(parents=True, exist_ok=True)

    job = {
        "status":     "running",
        "config":     config,
        "output_dir": str(output_dir),
        "started_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "ended_at":   None,
        "log":        [],
        "error":      None,
    }

    with _jobs_lock:
        _jobs[job_id] = job

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

    return jsonify({"ok": True, "job_id": job_id})


# ── The async worker that actually runs the monitor ───────────────────────────

async def _run_channel_monitor(job_id: str, config: dict, output_dir: Path, creds: dict):
    """Run channel_monitor logic inline, logging to the job's log list."""

    def log(msg: str):
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id]["log"].append(msg)

    log(f"[+] Starting channel monitor for: @{config['channel']}")
    log(f"[i] Settings: limit={config['limit']}, days={config['days']}, lang={config['lang']}, max_video={config['max_video_mb']}MB, skip_english={config['skip_english']}")

    # Import here to avoid circular import issues at module load time
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

    try:
        from telethon import TelegramClient
        from ..channel_monitor import (
            process_channel,
        )
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

        await process_channel(
            client=client,
            channel_id=config["channel"],
            limit=config["limit"],
            output_dir=output_dir,
            days=config["days"],
            min_space_gb=config["min_space_gb"],
            max_video_mb=config["max_video_mb"],
            forced_lang=config["lang"],
            skip_english=config["skip_english"],
        )
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
