"""
Dashboard blueprint — all protected routes.
"""

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode

from flask import Blueprint, Response, jsonify, render_template, request, session

from .. import regex_safety
from ..auth import (
    check_password,
    clear_failures,
    current_user,
    hash_password,
    locked_for,
    note_totp_failure,
    record_auth_event,
    reissue_session,
    require_admin,
    require_login,
    totp_key,
    use_totp_code,
    validate_password_strength,
)
from ..pdf_text import pdf_plain, pdf_text
from . import file_store, jobs
from . import validation as v
from .errors import api_error, log_error
from .http_client import SafeFetchError, fetch_public, safe_fetch
from .storage_helper import get_storage
from .upstream_cache import TTLCache, default_ttl

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.errorhandler(v.Invalid)
def _invalid_input(err):
    return jsonify({"error": str(err)}), 400


@dashboard_bp.errorhandler(jobs.Busy)
def _busy(err):
    """Too many heavy operations at once: 429 with Retry-After (see jobs.py)."""
    return jobs.busy_answer(err)


# Answers of the third-party services the pages ask for again and again (the
# abuse.ch relays on every home page load, crt.sh, WhiteIntel, DNSDumpster).
_upstream = TTLCache("dashboard relays", ttl=default_ttl(), max_entries=128)
# The WhatsMyName site list changes rarely and is about 1 MB.
_wmn_cache = TTLCache("WhatsMyName list", ttl=6 * 3600, max_entries=2, copy_values=False)


class _UpstreamFailed(Exception):
    """An upstream answer that must not be cached; the cache serves the last good one instead."""


def _cached_fetch(key, url: str, *, good=(200,), **kwargs):
    """safe_fetch() through the cache. The answer dict, or None when there is none to serve.

    Only an answer with a status in ``good`` is kept. Raises SafeFetchError
    as safe_fetch does when the request is refused or fails and nothing is
    cached, so callers keep their own handling of it.
    """
    failure: dict = {}

    def fetch():
        try:
            result = safe_fetch(url, **kwargs)
        except SafeFetchError as exc:
            failure["blocked"] = exc
            raise
        if result["status"] not in good:
            failure["answer"] = result
            raise _UpstreamFailed(f"HTTP {result['status']} for {url}")
        return {"status": result["status"], "body": result["body"]}

    answer = _upstream.get(key, fetch)
    if answer is None and "blocked" in failure:
        raise failure["blocked"]
    return answer if answer is not None else failure.get("answer")


def _path_segment(value, field: str = "name", max_len: int = 100) -> str:
    """``value`` percent-encoded for use as ONE segment of an upstream URL's path.

    Nothing in it can add a segment, a query or a fragment. Empty values and
    "." / ".." (which would change the path) are refused with v.Invalid.
    """
    value = v.text(value, field, max_len)
    if value is None or value.strip(".") == "":
        raise v.Invalid(f"{field} is not valid")
    return quote(value, safe="")


def _close_stale_jobs(_state=None) -> None:
    """Background jobs live in this process. What the database still shows as
    running when the process starts was cut off by a restart and will never
    finish: say so, once, instead of leaving it "running" for ever."""
    try:
        storage = get_storage()
        closed = {
            "DNS recon": storage.fail_running_dns_investigations(
                "Interrupted by a restart of the dashboard. Run it again."
            ),
            "breach investigation": storage.fail_running_investigations(),
            "IP lookup": storage.close_running_ip_investigations(
                "Not fetched: the dashboard was restarted before the extra data arrived."
            ),
            "Quick Scan": storage.fail_running_quick_scans(
                "Interrupted by a restart of the dashboard. Run it again."
            ),
        }
        for kind, count in closed.items():
            if count:
                logger.warning("%d %s job(s) were running at the last stop; marked as interrupted", count, kind)
    except Exception:
        logger.exception("could not close jobs left running by the last stop")


# Runs when the blueprint is registered, that is once per process, in create_app().
dashboard_bp.record_once(_close_stale_jobs)

# Config is read-only at /app/config — write user edits to /app/data instead
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "/app/config"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))

# Read from config (bundled defaults), write to data (persistent, writable)
KEYWORDS_FILE = DATA_DIR / "keywords.yaml"
KEYWORDS_DEFAULT = CONFIG_DIR / "keywords.yaml"
SEEDS_FILE = DATA_DIR / "seeds.txt"
SEEDS_DEFAULT = CONFIG_DIR / "seeds.txt"
CRAWL_FLAG = DATA_DIR / "crawl.start"
STOP_FLAG  = DATA_DIR / "crawl.stop"


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_seeds() -> list[str]:
    """Load seeds from data dir (user edits), falling back to config default."""
    src = SEEDS_FILE if SEEDS_FILE.exists() else SEEDS_DEFAULT
    if not src.exists():
        return []
    return [
        line.strip()
        for line in src.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _load_keywords() -> dict:
    """Load keywords from data dir (user edits), falling back to config default."""
    import yaml

    src = KEYWORDS_FILE if KEYWORDS_FILE.exists() else KEYWORDS_DEFAULT
    if not src.exists():
        return {}
    data = yaml.safe_load(src.read_text()) or {}
    return data.get("keywords", {})


def _update_keywords(change):
    """Change the keyword categories on disk: one writer at a time, written in
    one step, and the rest of the file (``settings:``) kept. See file_store.py."""
    _ensure_data_dir()
    return file_store.update_keywords(KEYWORDS_FILE, KEYWORDS_DEFAULT, change)


def _add_keywords(pairs) -> int:
    """Add (keyword, category) pairs to the keyword file. Returns how many were new."""

    def add(cats: dict) -> int:
        added = 0
        for keyword, category in pairs:
            if not isinstance(cats.get(category), list):
                cats[category] = []
            if keyword not in cats[category]:
                cats[category].append(keyword)
                added += 1
        return added

    return _update_keywords(add)


def _update_seeds(add=(), remove=()) -> int:
    """Add and remove seed URLs on disk, the same way. Returns how many were added."""
    _ensure_data_dir()
    return file_store.update_seeds(SEEDS_FILE, SEEDS_DEFAULT, add=add, remove=remove)


# ── Pages ──────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/dashboard")
@require_login
def index():
    user = current_user()
    return render_template("index.html", username=user.username, is_admin=bool(user.is_admin))


@dashboard_bp.route("/help")
@require_login
def help_page():
    from .channel_monitor_routes import RETENTION_DAYS

    user = current_user()
    return render_template(
        "help.html", username=user.username, is_admin=bool(user.is_admin), retention_days=RETENTION_DAYS
    )


# ── Stats & Hits API ───────────────────────────────────────────────────────────


@dashboard_bp.route("/api/stats")
@require_login
def api_stats():
    return jsonify(get_storage().get_stats())


@dashboard_bp.route("/api/hits")
@require_login
def api_hits():
    limit = v.int_arg("limit", 100, 1, 1000)
    keyword = request.args.get("keyword")
    storage = get_storage()
    records = (
        storage.get_hits_by_keyword(keyword, limit=limit)
        if keyword
        else storage.get_recent_hits(limit=limit)
    )
    return jsonify(
        [
            {
                "id": r.id,
                "url": r.url,
                "keyword": r.keyword,
                "category": r.category,
                "context": r.context,
                "depth": r.depth,
                "found_at": r.found_at.isoformat() if r.found_at else None,
                "alerted": r.alerted,
            }
            for r in records
        ]
    )


# ── Keywords API ───────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/keywords", methods=["GET"])
@require_login
def api_keywords_get():
    try:
        return jsonify({"categories": _load_keywords()})
    except Exception:
        return api_error("The keyword file could not be read.")


@dashboard_bp.route("/api/keywords", methods=["POST"])
@require_admin
def api_keywords_add():
    body = v.json_body()
    keyword = v.keyword(body.get("keyword"))
    category = v.category(body.get("category"))
    try:
        _add_keywords([(keyword, category)])
        return jsonify({"ok": True})
    except Exception:
        return api_error("The keyword could not be saved.")


@dashboard_bp.route("/api/keywords", methods=["DELETE"])
@require_admin
def api_keywords_delete():
    # Deletes match what is stored, so entries saved before validation existed can still be removed.
    body = v.json_body()
    keyword = str(body.get("keyword") or "").strip()
    category = str(body.get("category") or "").strip()
    if not keyword or not category:
        return jsonify({"error": "keyword and category required"}), 400
    def remove(cats: dict) -> None:
        if keyword in (cats.get(category) or []):
            cats[category].remove(keyword)

    try:
        _update_keywords(remove)
        return jsonify({"ok": True})
    except Exception:
        return api_error("The keyword could not be removed.")


# ── Seeds API ──────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/seeds", methods=["GET"])
@require_login
def api_seeds_get():
    try:
        return jsonify({"seeds": _load_seeds()})
    except Exception:
        return api_error("The seed list could not be read.")


def _urls_from_body(body: dict) -> list[str]:
    """``url`` or ``urls`` from a request body, each checked as an http(s) URL."""
    urls = body.get("urls") or ([body.get("url")] if body.get("url") else [])
    if not isinstance(urls, list) or not urls:
        raise v.Invalid("url(s) required")
    if len(urls) > 2000:
        raise v.Invalid("at most 2000 URLs per request")
    return [v.http_url(u) for u in urls if not (isinstance(u, str) and not u.strip())]


@dashboard_bp.route("/api/seeds", methods=["POST"])
@require_admin
def api_seeds_add():
    # Support both single url and bulk urls array
    urls = _urls_from_body(v.json_body())
    try:
        added = _update_seeds(add=urls)
        return jsonify({"ok": True, "added": added})
    except Exception:
        return api_error("The seed list could not be saved.")


@dashboard_bp.route("/api/seeds", methods=["DELETE"])
@require_admin
def api_seeds_delete():
    url = str(v.json_body().get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        _update_seeds(remove=[url])
        return jsonify({"ok": True})
    except Exception:
        return api_error("The seed list could not be saved.")


# ── Keyword bulk import/export ─────────────────────────────────────────────────


@dashboard_bp.route("/api/keywords/bulk", methods=["POST"])
@require_admin
def api_keywords_bulk_add():
    """Add multiple keywords in a single atomic write."""
    body = v.json_body()
    items = body.get("keywords", [])  # [{keyword, category}, ...]
    if not isinstance(items, list) or not items:
        return jsonify({"error": "keywords array required"}), 400
    if len(items) > 2000:
        return jsonify({"error": "at most 2000 keywords per request"}), 400
    pairs = []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("keyword") or "").strip():
            continue
        pairs.append((v.keyword(item.get("keyword")), v.category(item.get("category"))))
    added = _add_keywords(pairs)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/keywords/export", methods=["GET"])
@require_login
def api_keywords_export():
    import csv
    import io
    cats = _load_keywords()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["keyword", "category"])
    for cat, kws in cats.items():
        for kw in (kws or []):
            writer.writerow([kw, cat])
    output = buf.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=keywords.csv"}
    )


@dashboard_bp.route("/api/keywords/import", methods=["POST"])
@require_admin
def api_keywords_import():
    import csv
    import io

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    content = f.read(1_000_001).decode("utf-8", errors="ignore")
    if len(content) > 1_000_000:
        return jsonify({"error": "File too large (max 1 MB)"}), 400
    reader = csv.DictReader(io.StringIO(content))
    pairs = []
    skipped = 0
    for i, row in enumerate(reader, 1):
        try:
            raw_kw = (row.get("keyword") or row.get("Keyword") or "").strip()
            if not raw_kw:
                continue
            kw = v.keyword(raw_kw)
            cat = v.category((row.get("category") or row.get("Category") or "").strip())
        except v.Invalid:
            skipped += 1
            continue
        pairs.append((kw, cat))
    added = _add_keywords(pairs)
    return jsonify({"ok": True, "added": added, "skipped": skipped})


# ── Keyword generator ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/keywords/generate", methods=["POST"])
@require_login
def api_keywords_generate():
    """Rule-based keyword generator — zero API cost."""
    body = request.get_json() or {}
    name = (body.get("name") or "").strip()
    domain = (body.get("domain") or "").strip().lower().lstrip("www.").lstrip("https://").lstrip("http://").split("/")[0]
    industry = (body.get("industry") or "").strip()
    context = (body.get("context") or "").strip()

    if not name and not domain:
        return jsonify({"error": "Provide at least a name or domain"}), 400

    results = {
        "brand_monitoring": set(),
        "credentials": set(),
        "infrastructure": set(),
        "threat_intel": set(),
        "custom": set(),
    }

    # ── Brand / name variants ──
    if name:
        name_lower = name.lower()
        name_nospace = name_lower.replace(" ", "")
        name_dash = name_lower.replace(" ", "-")
        name_underscore = name_lower.replace(" ", "_")
        # Base variants
        for v in [name_lower, name_nospace, name_dash, name_underscore]:
            results["brand_monitoring"].add(v)
        # Abbreviation (first letters of each word)
        words = name_lower.split()
        if len(words) > 1:
            abbrev = "".join(w[0] for w in words)
            results["brand_monitoring"].add(abbrev)
        # Common typos — swap adjacent chars in short names
        if len(name_nospace) <= 12:
            for i in range(len(name_nospace)-1):
                typo = name_nospace[:i] + name_nospace[i+1] + name_nospace[i] + name_nospace[i+2:]
                results["brand_monitoring"].add(typo)

    # ── Domain variants ──
    if domain:
        bare = domain.split(".")[0]  # e.g. "philhealth" from "philhealth.gov.ph"
        tld = ".".join(domain.split(".")[1:]) if "." in domain else ""

        results["brand_monitoring"].update([domain, bare])
        if tld:
            results["brand_monitoring"].add(f"@{domain}")
            results["brand_monitoring"].add(f"@{bare}")

        # Common subdomain variants
        for sub in ["mail", "vpn", "remote", "webmail", "portal", "admin", "intranet", "api", "dev", "staging"]:
            results["infrastructure"].add(f"{sub}.{domain}")

        # Credential patterns
        for suffix in ["password", "passwords", "pass", "credentials", "creds", "dump", "leak", "combo", "db", "database"]:
            results["credentials"].add(f"{bare} {suffix}")
            results["credentials"].add(f"{domain} {suffix}")
            results["credentials"].add(f"{bare}_{suffix}")

        # Email patterns
        results["credentials"].add(f"@{domain}")
        results["credentials"].add(f"@{bare}")

        # Threat intel patterns
        for suffix in ["breach", "hacked", "ransomware", "attacked", "compromised", "data", "exposed", "stolen"]:
            results["threat_intel"].add(f"{bare} {suffix}")
            results["threat_intel"].add(f"{domain} {suffix}")

        # Paste/leak site patterns
        for suffix in ["pastebin", "leaked", "dump", "fullz"]:
            results["threat_intel"].add(f"{bare} {suffix}")

    # ── Industry-specific terms ──
    industry_keywords = {
        "bank": ["swift", "iban", "routing number", "wire transfer", "core banking", "atm skimmer"],
        "healthcare": ["patient records", "ehr", "medical records", "hipaa", "phi"],
        "government": [".gov.ph", "gsis", "philsys", "umid", "tin number"],
        "telco": ["sim swap", "imsi", "subscriber data", "cdr"],
        "insurance": ["policy data", "claims data", "insured"],
        "ecommerce": ["customer database", "order dump", "payment cards", "cvv"],
        "bpo": ["bpo credentials", "agent credentials", "call center"],
        "education": ["student records", "enrollment data", "lrn"],
    }
    if industry:
        industry_lower = industry.lower()
        for key, terms in industry_keywords.items():
            if key in industry_lower:
                results["custom"].update(terms)

    # ── Context extraction — pull meaningful words/phrases ──
    if context:
        import re as _re
        # Extract quoted phrases
        quoted = _re.findall(r'"([^"]+)"', context)
        results["custom"].update(q.lower() for q in quoted if len(q) > 3)
        # Extract capitalised proper nouns (likely org/product names)
        proper = _re.findall(r'\b[A-Z][A-Za-z]{3,}\b', context)
        results["custom"].update(p.lower() for p in proper if p.lower() not in (name or "").lower())
        # Extract domain-like patterns
        domains_found = _re.findall(r'\b[\w-]+\.\w{2,6}\b', context)
        results["infrastructure"].update(d.lower() for d in domains_found)

    # Clean up — remove empty strings, sort each category
    final = {}
    for cat, kws in results.items():
        cleaned = sorted(kw.strip() for kw in kws if kw and len(kw.strip()) > 2)
        if cleaned:
            final[cat] = cleaned

    return jsonify({"ok": True, "keywords": final})


# ── Crawl control API ──────────────────────────────────────────────────────────
# Which crawl is running is in the database (crawl_sessions: owner and
# heartbeat, see Storage.begin_crawl_session), so a crawl started by
# "make scan" in another container counts too, and a crawl whose process died
# is ended as interrupted, not reported as completed.

TOR_DOWN_MESSAGE = "Tor is not reachable, so the crawl was not started. Check the tor container (make check-tor)."


def _end_stale_crawls() -> None:
    """End the running sessions whose process is gone. While this process runs
    no crawl, a session under its own name is from before a restart."""
    from ..crawler import STALE_SECONDS, crawl_owner, local_crawl_running

    get_storage().interrupt_stale_crawl_sessions(
        STALE_SECONDS, idle_owner=None if local_crawl_running() else crawl_owner()
    )


@dashboard_bp.route("/api/crawl/start", methods=["POST"])
@require_admin
def api_crawl_start():
    import asyncio
    import threading
    from pathlib import Path as _Path

    from ..alerting import Alerter
    from ..crawler import (
        STALE_SECONDS,
        CrawlConfig,
        claim_local_crawl,
        crawl_owner,
        local_crawl_running,
        release_local_crawl,
    )
    from ..main import run_scan
    from ..scanner import KeywordConfig
    from ..tor_client import tor_reachable

    _ensure_data_dir()
    storage = get_storage()

    # Prevent double-start, in this process or another one.
    _end_stale_crawls()
    if local_crawl_running() or storage.get_active_session() is not None:
        return jsonify({"error": "A crawl is already running"}), 409

    # Resolve seeds and keywords files
    seeds_path = DATA_DIR / "seeds.txt"
    if not seeds_path.exists():
        seeds_path = _Path("config/seeds.txt")
    keywords_path = DATA_DIR / "keywords.yaml"
    if not keywords_path.exists():
        keywords_path = _Path("config/keywords.yaml")

    if not seeds_path.exists():
        return jsonify({"error": "No seeds file found. Add seeds in the Seeds tab first."}), 400
    if not keywords_path.exists():
        return jsonify({"error": "No keywords file found. Add keywords in the Keywords tab first."}), 400

    seed_urls = [
        line.strip()
        for line in seeds_path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not seed_urls:
        return jsonify({"error": "Seeds file is empty. Add at least one .onion URL."}), 400

    if not tor_reachable():
        logger.error("Crawl not started: Tor is not reachable")
        return jsonify({"error": TOR_DOWN_MESSAGE}), 503

    claim_local_crawl()
    try:
        session_id = storage.begin_crawl_session(seed_urls, crawl_owner(), STALE_SECONDS)
    except Exception:
        release_local_crawl()
        return api_error("The crawl could not be started.")
    if session_id is None:
        release_local_crawl()
        return jsonify({"error": "A crawl is already running"}), 409

    # The session is ours: a stop flag left from an earlier crawl is stale.
    STOP_FLAG.unlink(missing_ok=True)

    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            keyword_config = KeywordConfig.from_yaml(str(keywords_path))
            crawl_config = CrawlConfig()
            alerter = Alerter()
            loop.run_until_complete(
                run_scan(
                    seeds=seed_urls,
                    keyword_config=keyword_config,
                    crawl_config=crawl_config,
                    storage=storage,
                    alerter=alerter,
                    check_tor=False,  # checked above
                    stop_flag=STOP_FLAG,
                    session_id=session_id,
                )
            )
        except Exception:
            # run_scan has logged it and written the end of the session.
            logger.warning("Crawl session %s ended with an error", session_id)
        finally:
            loop.close()
            release_local_crawl()
            STOP_FLAG.unlink(missing_ok=True)

    threading.Thread(target=run, daemon=True, name="crawl_thread").start()

    return jsonify({"ok": True, "message": "Crawl started.", "session_id": session_id})


@dashboard_bp.route("/api/crawl/stop", methods=["POST"])
@require_admin
def api_crawl_stop():
    try:
        _ensure_data_dir()
        STOP_FLAG.write_text(datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        return jsonify({"ok": True, "message": "Stop signal sent — crawl will halt after current page."})
    except Exception:
        return api_error("The stop signal could not be written.")

@dashboard_bp.route("/api/crawl/status", methods=["GET"])
@require_login
def api_crawl_status():
    try:
        storage = get_storage()
        _end_stale_crawls()
        stats = storage.get_stats()
        active = storage.get_active_session()

        # Auto-clear stale stop flag if no scan is actually running
        if not active and STOP_FLAG.exists():
            try:
                STOP_FLAG.unlink()
            except Exception:
                pass

        session_data = None
        if active:
            live_hits = storage.count_session_hits(active["id"])
            live_pages = storage.count_session_pages(active["id"])
            session_data = {
                "id": active["id"],
                "started_at": active["started_at"],
                "pages_crawled": live_pages,
                "hits_found": live_hits,
            }
        return jsonify({
            "active": active is not None,
            "session": session_data,
            "last_session": None if active else storage.get_last_finished_session(),
            "stats": stats,
        })
    except Exception:
        return api_error("Crawl status could not be read.")


# ── User management API (admin only) ──────────────────────────────────────────


@dashboard_bp.route("/api/users", methods=["GET"])
@require_admin
def api_users_list():
    storage = get_storage()
    users = storage.list_users()
    return jsonify(
        [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "is_admin": u.is_admin,
                "totp_enabled": u.totp_enabled,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            }
            for u in users
        ]
    )


@dashboard_bp.route("/api/users", methods=["POST"])
@require_admin
def api_users_create():
    body = v.json_body()
    username = v.username(body.get("username"))
    email = v.email(body.get("email"), required=False)
    password = body.get("password") if isinstance(body.get("password"), str) else ""
    is_admin = v.strict_bool(body.get("is_admin"), "is_admin")

    if not password:
        return jsonify({"error": "username and password required"}), 400

    err = validate_password_strength(password)
    if err:
        return jsonify({"error": err}), 400

    storage = get_storage()
    if storage.get_user_by_username(username):
        return jsonify({"error": "username already taken"}), 409
    if email and storage.get_user_by_email(email):
        return jsonify({"error": "email already in use"}), 409

    user_id = storage.create_user(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_admin=is_admin,
        must_change_password=True,  # force password change + MFA on first login
    )
    record_auth_event("user_created", username, user_id, f"by {current_user().username}, admin={is_admin}")
    return jsonify({"ok": True, "id": user_id})


@dashboard_bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_admin
def api_users_delete(user_id):
    me = current_user()
    if user_id == me.id:
        return jsonify({"error": "cannot delete yourself"}), 400
    storage = get_storage()
    target = storage.get_user_by_id(user_id)
    if target is None:
        return jsonify({"error": "not found"}), 404
    name = target.username
    # The user's sessions end with the row: every request loads the user again.
    storage.delete_user(user_id)
    record_auth_event("user_deleted", name, user_id, f"by {me.username}")
    return jsonify({"ok": True})


@dashboard_bp.route("/api/users/<int:user_id>/mfa/reset", methods=["POST"])
@require_admin
def api_users_mfa_reset(user_id):
    """For a user who lost their authenticator: remove the second factor, end
    their sessions and clear any lock. They enrol again at the next sign-in."""
    me = current_user()
    if user_id == me.id:
        return jsonify({"error": "use Settings to change your own second factor"}), 400
    storage = get_storage()
    target = storage.get_user_by_id(user_id)
    if target is None:
        return jsonify({"error": "not found"}), 404
    storage.disable_totp(user_id)
    storage.bump_session_version(user_id)
    clear_failures(totp_key(user_id))
    record_auth_event("mfa_reset", target.username, user_id, f"by {me.username}")
    return jsonify({"ok": True})


@dashboard_bp.route("/api/admin/auth-events", methods=["GET"])
@require_admin
def api_auth_events():
    """Sign-ins, failures, lockouts and account changes, newest first."""
    return jsonify(get_storage().list_auth_events(limit=v.int_arg("limit", 200, 1, 1000)))


# ── User settings API (own account) ───────────────────────────────────────────


@dashboard_bp.route("/api/settings/password", methods=["POST"])
@require_login
def api_change_password():
    body = v.json_body()
    current = body.get("current_password") if isinstance(body.get("current_password"), str) else ""
    new_pw = body.get("new_password") if isinstance(body.get("new_password"), str) else ""
    confirm = body.get("confirm_password") if isinstance(body.get("confirm_password"), str) else ""

    storage = get_storage()
    user = current_user()

    if not check_password(current, user.password_hash):
        record_auth_event("password_change_failed", user.username, user.id, "wrong current password")
        return jsonify({"error": "Current password is incorrect"}), 400
    if new_pw != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if new_pw == current:
        return jsonify({"error": "The new password must differ from the current one"}), 400
    err = validate_password_strength(new_pw)
    if err:
        return jsonify({"error": err}), 400

    storage.update_user_password(user.id, hash_password(new_pw))
    reissue_session(user)  # ends the user's other sessions, keeps this one
    record_auth_event("password_changed", user.username, user.id)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/settings/totp/disable", methods=["POST"])
@require_login
def api_disable_totp():
    """Remove the second factor. Needs the password AND a current code. Two-factor
    sign-in is mandatory, so the next page asks the user to enrol again."""
    body = v.json_body()
    storage = get_storage()
    user = current_user()

    code = body.get("totp_code") if isinstance(body.get("totp_code"), str) else ""
    password = body.get("password") if isinstance(body.get("password"), str) else ""

    if locked_for(totp_key(user.id)):
        return jsonify({"error": "Too many wrong codes. Try again later."}), 429
    if not check_password(password, user.password_hash):
        record_auth_event("mfa_disable_failed", user.username, user.id, "wrong password")
        return jsonify({"error": "Invalid code or password"}), 400
    if not use_totp_code(user, code):
        note_totp_failure(user.id)
        record_auth_event("mfa_disable_failed", user.username, user.id, "wrong code")
        return jsonify({"error": "Invalid code or password"}), 400

    storage.disable_totp(user.id)
    reissue_session(user)
    record_auth_event("mfa_disabled", user.username, user.id)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/settings/profile", methods=["GET"])
@require_login
def api_profile():
    user = current_user()
    return jsonify(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "totp_enabled": user.totp_enabled,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }
    )



# ── Sessions API ───────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/sessions", methods=["GET"])
@require_login
def api_sessions():
    storage = get_storage()
    sessions = storage.get_sessions(limit=20)
    for s in sessions:
        try:
            s["seed_urls"] = json.loads(s["seed_urls"])
        except Exception:
            s["seed_urls"] = []
    return jsonify(sessions)


@dashboard_bp.route("/api/sessions/<int:session_id>/hits", methods=["GET"])
@require_login
def api_session_hits(session_id):
    storage = get_storage()
    hits = storage.get_hits_by_session(session_id, limit=200)
    return jsonify(
        [
            {
                "id": r.id,
                "url": r.url,
                "keyword": r.keyword,
                "category": r.category,
                "context": r.context,
                "depth": r.depth,
                "found_at": r.found_at.isoformat() if r.found_at else None,
            }
            for r in hits
        ]
    )


# ── PDF Report API ─────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/report/pdf", methods=["GET"])
@require_login
def api_report_pdf():
    try:
        from datetime import datetime as dt
        from io import BytesIO
        session_id_filter = request.args.get("session_id", type=int)

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        storage = get_storage()
        stats = storage.get_stats()
        if session_id_filter:
            sessions = [s for s in storage.get_sessions(limit=50) if s["id"] == session_id_filter]
            hits = storage.get_hits_by_session(session_id_filter, limit=500)
            report_title = f"Session #{session_id_filter} — Threat Intelligence Report"
        else:
            sessions = storage.get_sessions(limit=50)
            hits = storage.get_hits_for_report(limit=200)
            report_title = "Threat Intelligence Executive Report"

        buf = BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        styles = getSampleStyleSheet()
        W = A4[0] - 40 * mm

        # Custom styles
        s_title = ParagraphStyle(
            "ReportTitle",
            parent=styles["Normal"],
            fontSize=22,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0d1117"),
            spaceAfter=4,
        )
        s_subtitle = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#8b949e"),
            spaceAfter=2,
        )
        s_h2 = ParagraphStyle(
            "H2",
            parent=styles["Normal"],
            fontSize=13,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0d1117"),
            spaceBefore=14,
            spaceAfter=6,
        )

        s_small = ParagraphStyle(
            "Small",
            parent=styles["Normal"],
            fontSize=7.5,
            textColor=colors.HexColor("#57606a"),
            leading=11,
            wordWrap="CJK",
        )
        s_mono = ParagraphStyle(
            "Mono",
            parent=styles["Normal"],
            fontSize=7,
            fontName="Courier",
            textColor=colors.HexColor("#0550ae"),
            leading=10,
            wordWrap="CJK",
        )

        generated_at = dt.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M UTC")
        story = []

        # ── Cover header ──
        story.append(Paragraph("Dark Web Scanner", s_title))
        story.append(Paragraph(report_title, s_subtitle))
        story.append(Paragraph(f"Generated: {generated_at}", s_subtitle))
        story.append(HRFlowable(width=W, thickness=2, color=colors.HexColor("#f85149"), spaceAfter=14))

        # ── Executive summary stats ──
        story.append(Paragraph("Executive Summary", s_h2))

        stat_data = [
            ["Metric", "Value"],
            ["Total Crawl Sessions", str(stats["total_sessions"])],
            ["Total Pages Crawled", str(stats["total_pages"])],
            ["Total Keyword Hits", str(stats["total_hits"])],
            ["Unique Keywords Triggered", str(len(stats["top_keywords"]))],
        ]
        stat_table = Table(stat_data, colWidths=[W * 0.6, W * 0.4])
        stat_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("PADDING", (0, 0), (-1, -1), 7),
                    ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ]
            )
        )
        story.append(stat_table)

        # ── Top keywords ──
        if stats["top_keywords"]:
            story.append(Paragraph("Top Keywords by Hit Count", s_h2))
            kw_data = [["Keyword", "Hits"]] + [
                [pdf_plain(k["keyword"], 200), str(k["count"])] for k in stats["top_keywords"]
            ]
            kw_table = Table(kw_data, colWidths=[W * 0.75, W * 0.25])
            kw_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                        ("PADDING", (0, 0), (-1, -1), 7),
                        ("ALIGN", (1, 0), (1, -1), "CENTER"),
                    ]
                )
            )
            story.append(kw_table)

        # ── Session history ──
        story.append(Paragraph("Scan Session History", s_h2))
        sess_data = [["Started", "Status", "Pages", "Hits"]]
        for s in sessions[:15]:
            started = s["started_at"][:16].replace("T", " ") if s.get("started_at") else "—"
            sess_data.append([started, pdf_plain(s.get("status") or "—", 40), str(s.get("pages_crawled") or 0), str(s.get("hits_found") or 0)])
        sess_table = Table(sess_data, colWidths=[W * 0.38, W * 0.22, W * 0.2, W * 0.2])
        sess_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                ]
            )
        )
        story.append(sess_table)

        # ── Keyword hits detail ──
        if hits:
            story.append(Paragraph(f"Keyword Hits Detail (latest {len(hits)})", s_h2))
            hits_data = [["Keyword", "Category", "URL", "Context", "Found At"]]
            for h in hits:
                found = h.found_at.strftime("%m-%d %H:%M") if h.found_at else "—"
                ctx = (h.context or "")[:120] + ("…" if len(h.context or "") > 120 else "")
                hits_data.append([
                    Paragraph(pdf_text(h.keyword, 200), s_small),
                    Paragraph(pdf_text(h.category, 100), s_small),
                    Paragraph(pdf_text(h.url, 500), s_mono),
                    Paragraph(pdf_text(ctx), s_small),
                    Paragraph(found, s_small),
                ])
            hits_table = Table(
                hits_data,
                colWidths=[W * 0.12, W * 0.1, W * 0.25, W * 0.4, W * 0.13],
                repeatRows=1,
            )
            hits_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161b22")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 8),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f6f8fa"), colors.white]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                        ("PADDING", (0, 0), (-1, -1), 5),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(hits_table)

        # ── Footer ──
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width=W, thickness=0.5, color=colors.HexColor("#d0d7de")))
        story.append(Paragraph(
            "CONFIDENTIAL — This report contains sensitive threat intelligence data. "
            "Do not distribute without authorization.",
            ParagraphStyle("Footer", parent=s_small, textColor=colors.HexColor("#8b949e"), fontSize=7),
        ))

        def dark_page(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(colors.HexColor("#0d1117"))
            canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
            canvas.restoreState()

        doc.build(story, onFirstPage=dark_page, onLaterPages=dark_page)
        buf.seek(0)

        filename = f"threat-intel-report-{dt.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d-%H%M')}.pdf"
        return Response(
            buf.read(),
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except Exception:
        return api_error("PDF generation failed. Please try again later.")


# ── Investigations API ─────────────────────────────────────────────────────────


@dashboard_bp.route("/api/investigations", methods=["GET"])
@require_login
def api_investigations_list():
    storage = get_storage()
    return jsonify(storage.get_investigations(limit=50))


@dashboard_bp.route("/api/investigations", methods=["POST"])
@require_login
def api_investigations_create():
    from ..investigations import needs_hibp, run_investigation_targets

    body = v.json_body()
    name = v.text(body.get("name"), "Investigation name", 200)
    targets = body.get("targets") or []

    if not isinstance(targets, list) or not targets:
        return jsonify({"error": "At least one target required"}), 400
    if len(targets) > 50:
        return jsonify({"error": "At most 50 targets per investigation"}), 400

    # Validate targets
    valid = []
    for t in targets:
        if not isinstance(t, dict):
            continue
        ttype = str(t.get("type") or "keyword").strip()
        if ttype not in ("email", "name", "keyword") or not str(t.get("value") or "").strip():
            continue
        val = v.email(t.get("value"), "target") if ttype == "email" else v.text(t.get("value"), "target", 200)
        valid.append({"value": val, "type": ttype})

    if not valid:
        return jsonify({"error": "No valid targets provided"}), 400

    storage = get_storage()
    api_key = os.getenv("HIBP_API_KEY", "")

    slot = jobs.acquire_slot()  # Busy (429) when too many long requests are running
    try:
        inv_id = storage.create_investigation(name=name, targets=valid)
    except Exception:
        slot.release()
        return api_error("The investigation could not be created.")

    def mark_failed():
        try:
            storage.fail_investigation(inv_id)
        except Exception:
            logger.exception("investigation %s could not be marked as failed", inv_id)

    def run_in_background():
        try:
            run_investigation_targets(inv_id, valid, storage, api_key)
        except Exception:
            log_error(f"investigation {inv_id} failed")
            mark_failed()

    if needs_hibp(valid, api_key):
        # HIBP wants 1.5 s between two requests, so email targets take time. They
        # are checked outside the request; the row stays "running" until then.
        jobs.start_background(run_in_background, slot, name="breach_investigation")
        return jsonify({"ok": True, "id": inv_id, "status": "running"})

    with slot:
        try:
            run_investigation_targets(inv_id, valid, storage, api_key)
        except Exception:
            answer = api_error("The investigation failed.", what=f"investigation {inv_id} failed")
            mark_failed()
            return answer
    return jsonify({"ok": True, "id": inv_id, "status": "completed"})


@dashboard_bp.route("/api/investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_investigations_get(inv_id):
    storage = get_storage()
    targets = storage.get_investigation_targets(inv_id)
    investigations = storage.get_investigations(limit=50)
    inv = next((i for i in investigations if i["id"] == inv_id), None)
    if not inv:
        return jsonify({"error": "Not found"}), 404
    return jsonify({**inv, "targets": targets})


@dashboard_bp.route("/api/investigations/<int:inv_id>", methods=["DELETE"])
@require_admin
def api_investigations_delete(inv_id):
    storage = get_storage()
    storage.delete_investigation(inv_id)
    return jsonify({"ok": True})


# ── IP Investigation API ───────────────────────────────────────────────────────


@dashboard_bp.route("/api/ip-investigations", methods=["GET"])
@require_login
def api_ip_investigations_list():
    storage = get_storage()
    return jsonify(storage.get_ip_investigations(limit=50))


@dashboard_bp.route("/api/ip-investigations", methods=["POST"])
@require_login
@jobs.heavy
def api_ip_investigations_create():
    from ..ip_lookup import investigate_ip, queue_virustotal_extras

    ip = v.ip_address(v.json_body().get("ip"))

    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    if not abuse_key and not vt_key:
        return jsonify({"error": "No API keys configured. Add ABUSEIPDB_API_KEY and/or VIRUSTOTAL_API_KEY to .env"}), 400

    storage = get_storage()
    try:
        result = investigate_ip(ip, abuse_key, vt_key)
        virustotal = result.get("virustotal") or {}
        inv_id = storage.save_ip_investigation(
            ip=ip,
            abuseipdb_data=result.get("abuseipdb") or {},
            virustotal_data=virustotal,
        )
        extras = virustotal.get("extras_status")
        if extras == "pending":
            # VirusTotal's resolutions and communicating files are two more
            # rate-limited calls. They run on a queue outside this request and
            # are merged into the saved record; until then it is "running".
            storage.update_ip_investigation(inv_id, status="running")

            def save(fields: dict) -> None:
                storage.update_ip_investigation(inv_id, fields, status="completed")

            extras = queue_virustotal_extras(ip, vt_key, save)
            if extras == "skipped":
                save({
                    "extras_status": extras,
                    "extras_note": "Not fetched: too many lookups are waiting for VirusTotal. Run the lookup again later.",
                })
        return jsonify({"ok": True, "id": inv_id, "extras_status": extras})
    except Exception:
        return api_error("The IP lookup failed.")


@dashboard_bp.route("/api/ip-investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_ip_investigations_get(inv_id):
    storage = get_storage()
    data = storage.get_ip_investigation(inv_id)
    if not data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(data)


@dashboard_bp.route("/api/ip-investigations/<int:inv_id>", methods=["DELETE"])
@require_admin
def api_ip_investigations_delete(inv_id):
    storage = get_storage()
    storage.delete_ip_investigation(inv_id)
    return jsonify({"ok": True})

# ── Ransomware Tracker API ─────────────────────────────────────────────────────


@dashboard_bp.route("/api/ransomware/groups", methods=["GET"])
@require_login
def api_ransomware_groups():
    from ..ransomware_data import RANSOMWARE_GROUPS
    storage = get_storage()
    # Merge static + custom entries
    custom = storage.get_custom_intel("ransomware")
    static_slugs = {g["slug"] for g in RANSOMWARE_GROUPS}
    all_groups = list(RANSOMWARE_GROUPS) + [g for g in custom if g["slug"] not in static_slugs]

    # Bulk-fetch hits and last-seen dates for every keyword in one query each
    # instead of issuing one query per keyword per group.
    all_keywords = list({kw for g in all_groups for kw in g.get("keywords", [])})
    hits_by_kw = storage.get_hits_by_keywords(all_keywords, limit_per_keyword=5)
    last_date_by_kw = storage.get_last_hit_dates_bulk(all_keywords)

    enriched = []
    for group in all_groups:
        keywords = group.get("keywords", [])
        recent_hits = []
        for kw in keywords:
            for h in hits_by_kw.get(kw, []):
                recent_hits.append({
                    "keyword": h.keyword,
                    "url": h.url,
                    "found_at": h.found_at.isoformat() if h.found_at else None,
                    "context": (h.context or "")[:200],
                })
        dates = [last_date_by_kw[kw] for kw in keywords if kw in last_date_by_kw]
        enriched.append({
            **group,
            "hit_count": sum(len(hits_by_kw.get(kw, [])) for kw in keywords),
            "recent_hits": recent_hits[:10],
            "last_seen": max(dates) if dates else None,
            "is_custom": group.get("slug") not in static_slugs,
        })
    enriched.sort(key=lambda g: (
        g["status"] != "active",
        not g["targeting_sea"],
        -g["hit_count"],
    ))
    return jsonify(enriched)


@dashboard_bp.route("/api/ransomware/groups", methods=["POST"])
@require_admin
def api_ransomware_groups_add():
    from ..ransomware_data import RANSOMWARE_GROUPS
    storage = get_storage()
    body = request.get_json() or {}
    required = ["name", "slug", "origin", "status", "risk_level", "description"]
    for field in required:
        if not body.get(field):
            return jsonify({"error": f"'{field}' is required"}), 400
    # Prevent slug collision with static data
    static_slugs = {g["slug"] for g in RANSOMWARE_GROUPS}
    if body["slug"] in static_slugs:
        return jsonify({"error": "Slug already exists in static data"}), 409
    entry = {
        "name": body["name"],
        "slug": body["slug"],
        "status": body["status"],
        "origin": body["origin"],
        "first_seen": body.get("first_seen", ""),
        "targeting_sea": bool(body.get("targeting_sea", False)),
        "risk_level": body["risk_level"],
        "description": body["description"],
        "ttps": [t.strip() for t in body.get("ttps", "").split(",") if t.strip()],
        "keywords": [k.strip() for k in body.get("keywords", "").split(",") if k.strip()],
        "onion_seeds": [u.strip() for u in body.get("onion_seeds", "").split("\n") if u.strip()],
        "sea_victims": [v.strip() for v in body.get("sea_victims", "").split(",") if v.strip()],
    }
    username = session.get("username", "admin")
    ok = storage.add_custom_intel("ransomware", entry["slug"], entry, created_by=username)
    if not ok:
        return jsonify({"error": "Slug already exists"}), 409
    return jsonify({"ok": True})


@dashboard_bp.route("/api/ransomware/groups/<slug>", methods=["DELETE"])
@require_admin
def api_ransomware_groups_delete(slug):
    from ..ransomware_data import RANSOMWARE_GROUPS
    static_slugs = {g["slug"] for g in RANSOMWARE_GROUPS}
    if slug in static_slugs:
        return jsonify({"error": "Cannot delete built-in entries"}), 403
    storage = get_storage()
    ok = storage.delete_custom_intel(slug)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@dashboard_bp.route("/api/ransomware/add-seeds", methods=["POST"])
@require_admin
def api_ransomware_add_seeds():
    """Add all known ransomware .onion URLs to the seed list."""
    from ..ransomware_data import RANSOMWARE_ONION_SEEDS
    added = _update_seeds(add=RANSOMWARE_ONION_SEEDS)
    return jsonify({"ok": True, "added": added, "total": len(RANSOMWARE_ONION_SEEDS)})


@dashboard_bp.route("/api/ransomware/add-keywords", methods=["POST"])
@require_admin
def api_ransomware_add_keywords():
    """Add all ransomware group names as keywords."""
    from ..ransomware_data import RANSOMWARE_GROUPS
    added = _add_keywords(
        [(kw, "ransomware") for group in RANSOMWARE_GROUPS for kw in group.get("keywords", [])]
    )
    return jsonify({"ok": True, "added": added})


# ── Threat Actors API ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/threat-actors", methods=["GET"])
@require_login
def api_threat_actors():
    from ..threat_actors import THREAT_ACTORS
    storage = get_storage()
    custom = storage.get_custom_intel("threat-actor")
    static_slugs = {a["slug"] for a in THREAT_ACTORS}
    all_actors = list(THREAT_ACTORS) + [a for a in custom if a["slug"] not in static_slugs]

    # Bulk-fetch hits and last-seen dates for every keyword in one query each
    # instead of issuing one query per keyword per actor.
    all_keywords = list({kw for a in all_actors for kw in a.get("keywords", [])})
    hits_by_kw = storage.get_hits_by_keywords(all_keywords, limit_per_keyword=5)
    last_date_by_kw = storage.get_last_hit_dates_bulk(all_keywords)

    enriched = []
    for actor in all_actors:
        keywords = actor.get("keywords", [])
        recent_hits = []
        for kw in keywords:
            for h in hits_by_kw.get(kw, []):
                recent_hits.append({
                    "keyword": h.keyword,
                    "url": h.url,
                    "found_at": h.found_at.isoformat() if h.found_at else None,
                    "context": (h.context or "")[:200],
                })
        dates = [last_date_by_kw[kw] for kw in keywords if kw in last_date_by_kw]
        enriched.append({
            **actor,
            "hit_count": sum(len(hits_by_kw.get(kw, [])) for kw in keywords),
            "recent_hits": recent_hits[:10],
            "last_seen": max(dates) if dates else None,
            "is_custom": actor.get("slug") not in static_slugs,
        })
    enriched.sort(key=lambda a: (
        a["risk_level"] not in ("critical", "high"),
        not a["targeting_sea"],
        -a["hit_count"],
    ))
    return jsonify(enriched)


@dashboard_bp.route("/api/threat-actors", methods=["POST"])
@require_admin
def api_threat_actors_add():
    from ..threat_actors import THREAT_ACTORS
    storage = get_storage()
    body = request.get_json() or {}
    required = ["name", "slug", "origin", "type", "status", "risk_level", "description"]
    for field in required:
        if not body.get(field):
            return jsonify({"error": f"'{field}' is required"}), 400
    static_slugs = {a["slug"] for a in THREAT_ACTORS}
    if body["slug"] in static_slugs:
        return jsonify({"error": "Slug already exists in static data"}), 409
    entry = {
        "name": body["name"],
        "slug": body["slug"],
        "type": body["type"],
        "status": body["status"],
        "origin": body["origin"],
        "first_seen": body.get("first_seen", ""),
        "targeting_sea": bool(body.get("targeting_sea", False)),
        "risk_level": body["risk_level"],
        "description": body["description"],
        "aliases": [a.strip() for a in body.get("aliases", "").split(",") if a.strip()],
        "sectors": [s.strip() for s in body.get("sectors", "").split(",") if s.strip()],
        "countries_targeted": [c.strip() for c in body.get("countries_targeted", "").split(",") if c.strip()],
        "ttps": [t.strip() for t in body.get("ttps", "").split(",") if t.strip()],
        "known_malware": [m.strip() for m in body.get("known_malware", "").split(",") if m.strip()],
        "keywords": [k.strip() for k in body.get("keywords", "").split(",") if k.strip()],
    }
    username = session.get("username", "admin")
    ok = storage.add_custom_intel("threat-actor", entry["slug"], entry, created_by=username)
    if not ok:
        return jsonify({"error": "Slug already exists"}), 409
    return jsonify({"ok": True})


@dashboard_bp.route("/api/threat-actors/<slug>", methods=["DELETE"])
@require_admin
def api_threat_actors_delete(slug):
    from ..threat_actors import THREAT_ACTORS
    static_slugs = {a["slug"] for a in THREAT_ACTORS}
    if slug in static_slugs:
        return jsonify({"error": "Cannot delete built-in entries"}), 403
    storage = get_storage()
    ok = storage.delete_custom_intel(slug)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@dashboard_bp.route("/api/threat-actors/add-keywords", methods=["POST"])
@require_admin
def api_threat_actors_add_keywords():
    """Add all threat actor names as keywords."""
    from ..threat_actors import THREAT_ACTORS
    added = _add_keywords(
        [(kw, "threat-actors") for actor in THREAT_ACTORS for kw in actor.get("keywords", [])]
    )
    return jsonify({"ok": True, "added": added})


# ── Digest / Mailing List API ──────────────────────────────────────────────────


@dashboard_bp.route("/api/digest/subscribers", methods=["GET"])
@require_admin
def api_digest_subscribers_get():
    from ..digest import load_subscribers
    return jsonify({"subscribers": load_subscribers()})


@dashboard_bp.route("/api/digest/subscribers", methods=["POST"])
@require_admin
def api_digest_subscribers_add():
    from ..digest import add_subscriber
    email = v.email(v.json_body().get("email"))
    added = add_subscriber(email)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/digest/subscribers", methods=["DELETE"])
@require_admin
def api_digest_subscribers_remove():
    from ..digest import remove_subscriber
    # Matches what is stored, so an address saved before validation existed can still be removed.
    email = str(v.json_body().get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    remove_subscriber(email)
    return jsonify({"ok": True})


# One digest send at a time, and how long its request waits for the result.
_digest_sending = threading.Lock()
DIGEST_SEND_WAIT = 60
_DIGEST_HTTP_ERROR = re.compile(r"^\S+@\S+: HTTP \d{3}$")


def _plain_digest_result(result: dict) -> dict:
    """send_digest()'s result without exception text.

    digest.py puts the text of an exception after "PDF build failed: " and
    after "<recipient>: ". The answer keeps what happened and to whom.
    """
    plain = dict(result)
    if str(plain.get("error") or "").startswith("PDF build failed"):
        plain["error"] = "PDF build failed"
    if "errors" in plain:
        plain["errors"] = [
            entry if _DIGEST_HTTP_ERROR.match(entry) else f"{entry.split(': ', 1)[0]}: could not be sent"
            for entry in map(str, plain["errors"] or [])
        ]
    return plain


@dashboard_bp.route("/api/digest/send", methods=["POST"])
@require_admin
def api_digest_send():
    from ..digest import send_digest
    body = v.json_body()
    # Optional: send to specific emails instead of subscriber list
    recipients = body.get("recipients") or None
    if recipients is not None:
        if not isinstance(recipients, list) or len(recipients) > 50:
            return jsonify({"error": "recipients must be a list of at most 50 addresses"}), 400
        recipients = [v.email(r, "recipient") for r in recipients]
    storage = get_storage()

    # Sending is one request to the mail service per recipient, one after the
    # other. It runs outside the request; the request waits a bounded time for
    # the result so that the usual, short send still answers with its counts.
    if not _digest_sending.acquire(blocking=False):
        return jsonify({"ok": False, "error": "A digest is being sent right now. Wait for it to finish."}), 409
    try:
        slot = jobs.acquire_slot()
    except BaseException:
        _digest_sending.release()
        raise
    done = threading.Event()
    outcome: dict = {}

    def run():
        try:
            outcome["result"] = send_digest(storage, recipients=recipients)
        except Exception:
            outcome["error_id"] = log_error("digest send failed")
        finally:
            _digest_sending.release()
            done.set()

    try:
        jobs.start_background(run, slot, name="digest_send")
    except BaseException:
        if not done.is_set():
            _digest_sending.release()
        raise
    if not done.wait(DIGEST_SEND_WAIT):
        return jsonify({
            "ok": False,
            "pending": True,
            "error": "The digest is still being sent. It goes on in the background; do not send it again.",
        }), 202
    if "result" not in outcome:
        return api_error("The digest could not be sent.", error_id=outcome.get("error_id"), ok=False)
    result = _plain_digest_result(outcome["result"])
    return jsonify(result), (200 if result.get("ok") else 500)


@dashboard_bp.route("/api/digest/preview", methods=["GET"])
@require_login
@jobs.heavy
def api_digest_preview():
    """Download a preview of the digest PDF without sending."""
    from ..digest import build_digest_pdf
    from ..feeds import fetch_all_feeds
    storage = get_storage()
    try:
        feed_data = fetch_all_feeds()
        stats = storage.get_stats()
        top_kw = stats.get("top_keywords", [{}])
        scanner_summary = {
            "total_hits": stats.get("total_hits", 0),
            "total_pages": stats.get("total_pages", 0),
            "total_sessions": stats.get("total_sessions", 0),
            "top_keyword": top_kw[0].get("keyword", "—") if top_kw else "—",
        }
        pdf = build_digest_pdf(feed_data, scanner_summary=scanner_summary)
        from datetime import datetime as dt
        filename = f"digest-preview-{dt.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}.pdf"
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception:
        return api_error("The digest preview could not be built.")


@dashboard_bp.route("/api/digest/feeds", methods=["GET"])
@require_login
@jobs.heavy
def api_digest_feeds():
    """Preview feed data without building PDF."""
    from ..feeds import fetch_all_feeds
    try:
        data = fetch_all_feeds()
        return jsonify(data)
    except Exception:
        return api_error("The feeds could not be fetched.")


# ── DNS Crawler API ────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/dns/investigations", methods=["GET"])
@require_login
def api_dns_list():
    storage = get_storage()
    return jsonify(storage.get_dns_investigations(limit=100))


@dashboard_bp.route("/api/dns/investigate", methods=["POST"])
@require_login
def api_dns_start():
    """Start a DNS investigation — runs in background thread."""
    from ..dns_crawler import NotPublicName, check_public_domain, run_dns_recon

    # Recon is for public names. v.domain() wants two labels; check_public_domain()
    # also refuses names that only exist inside private networks (.internal,
    # .local ...). A name that resolves to an internal address is refused when
    # the job starts, see run_dns_recon().
    try:
        domain = check_public_domain(v.domain(v.json_body().get("domain")))
    except NotPublicName as err:
        return jsonify({"error": err.message}), 400

    storage = get_storage()
    slot = jobs.acquire_slot()  # Busy (429) when too many long requests are running
    try:
        inv_id = storage.create_dns_investigation(domain)
    except Exception:
        slot.release()
        return api_error("The DNS investigation could not be created.")

    def run():
        try:
            result = run_dns_recon(domain)
            storage.complete_dns_investigation(inv_id, result)
        except NotPublicName as err:
            storage.fail_dns_investigation(inv_id, err.message)
        except Exception:
            error_id = log_error(f"DNS investigation {inv_id} failed")
            storage.fail_dns_investigation(inv_id, f"The recon failed. Error id: {error_id}")

    # The recon keeps its slot until it ends: there are never more than
    # HEAVY_JOBS_MAX of these threads.
    jobs.start_background(run, slot, name="dns_recon")

    return jsonify({"ok": True, "id": inv_id, "domain": domain})


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_dns_get(inv_id: int):
    storage = get_storage()
    result = storage.get_dns_investigation(inv_id)
    if not result:
        return jsonify({"error": "not found"}), 404
    return jsonify(result)


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>", methods=["DELETE"])
@require_admin
def api_dns_delete(inv_id: int):
    storage = get_storage()
    storage.delete_dns_investigation(inv_id)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>/enrich", methods=["POST"])
@require_login
def api_dns_enrich(inv_id: int):
    """
    Fetch DNSDumpster data for this investigation and merge it into the stored result.
    Deduplicates subdomains and adds dnsdumpster_data to the result JSON.
    Requires DNSDUMPSTER_API_KEY env var.
    """
    import json as _json

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        return jsonify({"error": "not found"}), 404

    api_key = os.getenv("DNSDUMPSTER_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "DNSDUMPSTER_API_KEY not configured"}), 500

    domain = inv["domain"]

    # ── Call DNSDumpster API ──────────────────────────────────────────────────
    try:
        _dn = _cached_fetch(
            ("dnsdumpster", domain),
            f"https://api.dnsdumpster.com/domain/{quote(domain, safe='')}",
            headers={
                "X-API-Key": api_key,
                "Accept": "application/json",
                "User-Agent": "OSINTPH-DNSCrawler/1.0",
            },
            timeout=20,
        )
    except SafeFetchError as e:
        logger.warning("DNSDumpster safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    if _dn is None:
        return jsonify({"error": "DNSDumpster did not answer. Try again in a minute."}), 502
    status, body = _dn["status"], _dn["body"]

    if status != 200:
        return jsonify({"error": f"DNSDumpster API returned {status}"}), 502

    try:
        dd_data = _json.loads(body)
        if not isinstance(dd_data, dict):
            raise ValueError("not a JSON object")
    except Exception:
        return api_error("DNSDumpster sent an answer that could not be read.", 502)

    # ── Merge into existing result ────────────────────────────────────────────
    result = inv.get("result", {})

    # Store raw DNSDumpster data
    result["dnsdumpster"] = dd_data

    # Extract subdomains from DNS Dumpster response
    # Their API returns: {dns_records: {host: [{host, ips, ttl, ...}]}, ...}
    dd_new_subs = set()
    dd_host_map = {}  # fqdn -> {ips, asn, country, ...}

    for rtype in ("a", "aaaa", "mx", "ns", "txt"):
        for rec in dd_data.get("dns_records", {}).get(rtype, []):
            host = rec.get("host", "").strip().lower().rstrip(".")
            if not host:
                continue
            if host.endswith(f".{domain}") or host == domain:
                dd_new_subs.add(host)
                dd_host_map[host] = {
                    "ips": [ip.get("address", ip) if isinstance(ip, dict) else ip
                            for ip in rec.get("ips", [])],
                    "asn": rec.get("asn", ""),
                    "country": rec.get("country", ""),
                    "reverse_dns": rec.get("reverse_dns", ""),
                }

    # Also pull from "hosts" key if present
    for rec in dd_data.get("hosts", []):
        host = rec.get("domain", "").strip().lower().rstrip(".")
        if host and (host.endswith(f".{domain}") or host == domain):
            dd_new_subs.add(host)
            dd_host_map.setdefault(host, {
                "ips": [ip.get("address", ip) if isinstance(ip, dict) else ip
                        for ip in rec.get("ips", [])],
                "asn": rec.get("asn", ""),
                "country": rec.get("country", ""),
            })

    # Merge into subdomains_resolved — deduplicate by subdomain name
    existing_subs = {s["subdomain"]: s for s in result.get("subdomains_resolved", [])}
    dd_count_new = 0
    for fqdn, info in dd_host_map.items():
        if fqdn not in existing_subs:
            existing_subs[fqdn] = {
                "subdomain": fqdn,
                "ips": info["ips"],
                "geo": [],
                "source": "dnsdumpster",
            }
            dd_count_new += 1
        else:
            # Tag existing entry as also seen by DNSDumpster
            existing_subs[fqdn]["source"] = existing_subs[fqdn].get("source", "passive") + "+dnsdumpster"
            # Merge any new IPs
            existing_ips = set(existing_subs[fqdn].get("ips", []))
            for ip in info["ips"]:
                if ip and ip not in existing_ips:
                    existing_subs[fqdn]["ips"].append(ip)

    result["subdomains_resolved"] = list(existing_subs.values())
    result["subdomain_count"] = len(existing_subs)
    result["resolved_count"] = len(result["subdomains_resolved"])
    result["dnsdumpster_enriched"] = True
    result["dnsdumpster_new_subs"] = dd_count_new

    # Persist updated result
    with storage.get_session() as db_session:
        from ..storage import DNSInvestigation
        row = db_session.get(DNSInvestigation, inv_id)
        if row:
            row.result_json = _json.dumps(result)
            row.subdomain_count = result["subdomain_count"]
            row.resolved_count = result["resolved_count"]
            db_session.commit()

    return jsonify({
        "ok": True,
        "new_subdomains": dd_count_new,
        "total_subdomains": result["subdomain_count"],
        "dnsdumpster_data": dd_data,
    })


@dashboard_bp.route("/api/dns/certs/<path:domain>", methods=["GET"], strict_slashes=False)
@require_login
def api_dns_certs(domain: str):
    """
    Fetch full certificate transparency history from crt.sh for a domain.
    Returns rich cert data: issuer, validity, SANs, grouped by cert.
    """
    import json as _json

    domain = v.domain(domain.strip().split("/")[0])

    if os.getenv("DEMO_MODE") == "1" and domain.endswith(".example"):
        # The demo instance's invented domains are not in crt.sh.
        from ..demo_seed import crtsh_entries

        raw = crtsh_entries(get_storage(), domain)
    else:
        # Query crt.sh — use the deduplicated JSON endpoint
        try:
            _result = _cached_fetch(
                ("crt.sh", domain),
                "https://crt.sh/?" + urlencode({"q": f"%.{domain}", "output": "json"}),
                headers={"User-Agent": "OSINTPH-DNSCrawler/1.0", "Accept": "application/json"},
                timeout=30,
            )
        except SafeFetchError as e:
            logger.warning("crt.sh safe_fetch blocked: %s", e)
            return jsonify({"error": "Certificate transparency lookup failed."}), 502
        if _result is None:
            return jsonify({"error": "crt.sh did not answer. Try again in a minute."}), 502

        if _result["status"] != 200:
            return jsonify({"error": f"crt.sh returned HTTP {_result['status']}"}), 502

        try:
            raw = _json.loads(_result["body"])
            if not isinstance(raw, list):
                raise ValueError("not a JSON list")
        except Exception:
            return jsonify({"error": "crt.sh sent an answer that could not be read."}), 502

    from datetime import datetime as dt
    now = dt.now(timezone.utc).replace(tzinfo=None)

    certs = []
    seen_ids = set()

    for entry in raw:
        cid = entry.get("id")
        if cid in seen_ids:
            continue
        seen_ids.add(cid)

        # Parse dates — crt.sh uses both "2024-01-01T00:00:00" and "2024-01-01" formats
        not_before_str = entry.get("not_before", "")
        not_after_str = entry.get("not_after", "")
        not_before = None
        not_after = None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                not_before = dt.strptime(not_before_str[:19], fmt[:len(not_before_str[:19])])
                break
            except Exception:
                pass
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                not_after = dt.strptime(not_after_str[:19], fmt[:len(not_after_str[:19])])
                break
            except Exception:
                pass

        is_expired = (not_after < now) if not_after else False
        days_remaining = (not_after - now).days if (not_after and not is_expired) else None
        expiring_soon = days_remaining is not None and days_remaining <= 30

        # SANs from name_value
        sans = sorted(set(
            n.strip().lower()
            for n in entry.get("name_value", "").split("\n")
            if n.strip()
        ))

        # Issuer parsing
        issuer_raw = entry.get("issuer_name", "")
        issuer_cn = ""
        issuer_org = ""
        for part in issuer_raw.split(","):
            part = part.strip()
            if part.startswith("CN="):
                issuer_cn = part[3:].strip()
            elif part.startswith("O="):
                issuer_org = part[2:].strip()

        certs.append({
            "id": cid,
            "serial": entry.get("serial_number", ""),
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
            "issuer_raw": issuer_raw,
            "not_before": not_before_str,
            "not_after": not_after_str,
            "not_before_ts": int(not_before.timestamp()) if not_before else 0,
            "not_after_ts": int(not_after.timestamp()) if not_after else 0,
            "is_expired": is_expired,
            "expiring_soon": expiring_soon,
            "days_remaining": days_remaining,
            "sans": sans,
            "san_count": len(sans),
        })

    # Sort newest first
    certs.sort(key=lambda c: c.get("not_before_ts", 0), reverse=True)

    # Build summary stats
    total = len(certs)
    expired = sum(1 for c in certs if c["is_expired"])
    expiring_soon_count = sum(1 for c in certs if c.get("expiring_soon"))
    all_sans = sorted(set(s for c in certs for s in c["sans"]))

    # Issuer breakdown
    from collections import Counter
    issuer_counts = Counter(c["issuer_org"] or c["issuer_cn"] for c in certs)

    return jsonify({
        "domain": domain,
        "total": total,
        "expired": expired,
        "expiring_soon": expiring_soon_count,
        "active": total - expired,
        "unique_sans": len(all_sans),
        "all_sans": all_sans,
        "issuers": dict(issuer_counts.most_common(10)),
        "certs": certs,
    })


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>/pdf", methods=["GET"])
@require_login
def api_dns_pdf(inv_id: int):
    """Export DNS investigation as a rich PDF report — DNSDumpster-inspired layout."""
    from collections import Counter
    from datetime import datetime as dt
    from io import BytesIO

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.style.use('dark_background')
    import math

    import matplotlib.patches as mpatches
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Image,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        return jsonify({"error": "not found"}), 404
    if inv["status"] != "complete":
        return jsonify({"error": "investigation not complete yet"}), 400

    r = inv.get("result", {})
    domain = inv["domain"]
    created = inv.get("created_at", "")[:16].replace("T", " ")
    dns = r.get("dns_records", {})
    zt = r.get("zone_transfer", {})
    email_sec = r.get("email_security", {})
    resolved = r.get("subdomains_resolved", [])
    passive = r.get("subdomains_passive", [])
    bruteforce = r.get("subdomains_bruteforce", [])
    ip_geo = r.get("ip_geo", {})
    ptr = r.get("ptr_records", {})
    port_scan = r.get("port_scan", {})
    dir_enum = r.get("dir_enum", {})
    zt_success = any(v.get("success") for v in zt.values() if isinstance(v, dict))
    main_ips = dns.get("A", []) + dns.get("AAAA", [])

    # ── Colour palette ──
    C_BG      = colors.HexColor("#0d1117")
    C_SURFACE = colors.HexColor("#161b22")
    C_BORDER  = colors.HexColor("#30363d")
    C_TEXT    = colors.HexColor("#e6edf3")
    C_MUTED   = colors.HexColor("#8b949e")
    C_ACCENT  = colors.HexColor("#58a6ff")
    C_RED     = colors.HexColor("#f85149")
    C_GREEN   = colors.HexColor("#3fb950")
    C_YELLOW  = colors.HexColor("#d29922")

    buf = BytesIO()
    W, H = A4
    M = 15 * mm
    def dark_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#0d1117"))
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=M, rightMargin=M,
                            topMargin=M, bottomMargin=M)
    PW = W - 2 * M
    styles = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    s_h1    = S("h1",    fontSize=22, fontName="Helvetica-Bold",   textColor=C_TEXT,   leading=26, spaceAfter=2)
    s_body  = S("body",  fontSize=8,  textColor=C_TEXT,   leading=12)
    s_small = S("small", fontSize=7,  textColor=C_MUTED,  leading=10)
    s_mono  = S("mono",  fontSize=7,  fontName="Courier", textColor=C_ACCENT, leading=10, wordWrap="CJK")
    s_warn  = S("warn",  fontSize=8,  fontName="Helvetica-Bold", textColor=C_RED, leading=12)
    s_foot  = S("foot",  fontSize=6.5, textColor=C_MUTED, leading=10)

    story = []

    # ── helpers ──────────────────────────────────────────────────────────────

    def dark_table(headers, rows, col_widths, row_colors=None):
        """Build a dark-themed table. headers = list of cells, rows = list of row lists."""
        data = [headers] + rows
        tbl = Table(data, colWidths=col_widths, repeatRows=1)
        row_bg = row_colors or [C_SURFACE, C_BG]
        cmds = [
            ("BACKGROUND",  (0, 0), (-1, 0),  C_BG),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  C_TEXT),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), row_bg),
            ("GRID",        (0, 0), (-1, -1), 0.3, C_BORDER),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0,0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",(0, 0), (-1, -1), 6),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ]
        tbl.setStyle(TableStyle(cmds))
        return tbl

    def section_header(title, color=None):
        story.append(Spacer(1, 6))
        story.append(HRFlowable(width=PW, thickness=1, color=color or C_BORDER, spaceAfter=4))
        story.append(Paragraph(title, S(f"sh_{title[:6]}", fontSize=10, fontName="Helvetica-Bold",
                     textColor=color or C_ACCENT, leading=14, spaceBefore=4, spaceAfter=3)))

    def badge(text, bg="#161b22", fg="#e6edf3"):
        return Paragraph(f'<font color="{fg}"><b>{pdf_text(text, 200)}</b></font>',
                         S("bd_badge", fontSize=7, backColor=colors.HexColor(bg),
                           borderPadding=(2,5,2,5), leading=10))

    def geo_str(geo_list):
        if not geo_list:
            return ""
        parts = [f"{g.get('city','')} {g.get('countryCode','')}" for g in (geo_list if isinstance(geo_list, list) else [geo_list]) if g and g.get("country")]
        return " / ".join(p.strip() for p in parts if p.strip())

    # ── ASN / hosting breakdown ───────────────────────────────────────────────
    asn_counter = Counter()
    org_counter = Counter()
    country_counter = Counter()
    cc_counter = Counter()   # ISO 2-letter codes for map
    cc_names   = {}          # cc -> full country name
    for sub in resolved:
        for g in (sub.get("geo") or []):
            if g and g.get("as"):
                asn_counter[g["as"]] += 1
            if g and g.get("org"):
                org_counter[g["org"]] += 1
            if g and g.get("country"):
                country_counter[g["country"]] += 1
            if g and g.get("countryCode"):
                cc = g["countryCode"].upper()
                cc_counter[cc] += 1
                cc_names[cc] = g.get("country", cc)

    # ── matplotlib helpers ────────────────────────────────────────────────────

    def fig_to_image(fig, width_mm=None):
        """Convert a matplotlib figure to a ReportLab Image."""
        img_buf = BytesIO()
        fig.savefig(img_buf, format="png", dpi=150, bbox_inches="tight",
                    facecolor="#161b22")
        img_buf.seek(0)
        plt.close(fig)
        from reportlab.lib.utils import ImageReader
        ir = ImageReader(img_buf)
        iw, ih = ir.getSize()
        ratio = ih / iw
        w = (width_mm or 170) * mm
        return Image(img_buf, width=w, height=w * ratio)

    # ── GRAPH: subdomain node diagram ─────────────────────────────────────────
    def build_graph_image():
        all_subs = {s["subdomain"]: s for s in resolved}
        for b in bruteforce:
            if b["subdomain"] not in all_subs:
                all_subs[b["subdomain"]] = b

        nodes = {}   # id -> (x, y, label, color, size)
        edges = []

        # Root
        nodes["root"] = (0, 0, domain, "#f85149", 400)

        sub_list = list(all_subs.values())[:60]
        n = len(sub_list)
        for i, s in enumerate(sub_list):
            angle = 2 * math.pi * i / max(n, 1)
            radius = 2.2
            sx = radius * math.cos(angle)
            sy = radius * math.sin(angle)
            is_brute = s["subdomain"] in {b["subdomain"] for b in bruteforce}
            col = "#bc8cff" if is_brute else "#58a6ff"
            label = s["subdomain"].replace("." + domain, "")
            sid = f"s{i}"
            nodes[sid] = (sx, sy, label, col, 120)
            edges.append(("root", sid))

            for j, ip in enumerate((s.get("ips") or [])[:2]):
                ip_id = f"ip_{ip.replace('.','_').replace(':','_')}"
                if ip_id not in nodes:
                    ia = angle + (j - 0.5) * 0.35
                    ir = radius + 1.1
                    nodes[ip_id] = (ir * math.cos(ia), ir * math.sin(ia), ip, "#3fb950", 60)
                edges.append((sid, ip_id))

        fig, ax = plt.subplots(figsize=(10, 7))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#0d1117")
        ax.axis("off")

        # Draw edges
        for (a, b_) in edges:
            if a in nodes and b_ in nodes:
                x1, y1 = nodes[a][:2]
                x2, y2 = nodes[b_][:2]
                col = "#3fb95033" if nodes[b_][3] == "#3fb950" else nodes[b_][3] + "44"
                ax.plot([x1, x2], [y1, y2], color=col, lw=0.6, zorder=1)

        # Draw nodes
        for nid, (nx, ny, lbl, col, sz) in nodes.items():
            ax.scatter(nx, ny, c=col, s=sz, zorder=3, edgecolors=col, linewidths=0.5, alpha=0.9)
            fs = 5.5 if nid == "root" else 4
            fw = "bold" if nid == "root" else "normal"
            ax.annotate(lbl, (nx, ny), xytext=(0, -10), textcoords="offset points",
                        ha="center", va="top", fontsize=fs, color="#e6edf3",
                        fontweight=fw, fontfamily="monospace")

        # Legend
        legend_els = [
            mpatches.Patch(color="#f85149", label="Root domain"),
            mpatches.Patch(color="#58a6ff", label="Passive subdomain"),
            mpatches.Patch(color="#bc8cff", label="Brute-forced"),
            mpatches.Patch(color="#3fb950", label="IP address"),
        ]
        ax.legend(handles=legend_els, loc="lower right", fontsize=6,
                  facecolor="#161b22", edgecolor="#30363d", labelcolor="#e6edf3",
                  framealpha=0.9)

        ax.set_aspect("equal")
        ax.margins(0.15)
        return fig_to_image(fig, width_mm=175)

    # ── GRAPH: world map via Playwright + jsvectormap ────────────────────────
    def build_world_map():
        """Screenshot the real jsvectormap using Playwright — same map as the dashboard."""
        import json as _json
        from io import BytesIO as _BytesIO

        from reportlab.lib.utils import ImageReader as _IR

        if not cc_counter:
            return None

        centroids_pw = {
            'US':[38,-97],'CA':[56,-96],'MX':[23,-102],'BR':[-10,-55],'AR':[-34,-64],
            'CO':[4,-74],'CL':[-30,-71],'PE':[-10,-76],'VE':[8,-66],
            'GB':[54,-3],'IE':[53,-8],'FR':[46,2],'DE':[51,10],'NL':[52,5],
            'BE':[50,4],'ES':[40,-4],'PT':[39,-8],'IT':[42,12],'CH':[47,8],
            'AT':[47,14],'PL':[52,20],'CZ':[50,15],'HU':[47,19],'RO':[46,25],
            'BG':[43,25],'GR':[39,22],'HR':[45,16],'UA':[49,32],'SE':[62,15],
            'NO':[62,10],'FI':[64,26],'DK':[56,10],'BY':[53,28],'RS':[44,21],
            'RU':[62,105],'TR':[39,35],'IL':[31,35],'SA':[24,45],'AE':[24,54],
            'IR':[32,53],'IQ':[33,44],'EG':[27,30],'LY':[27,17],'DZ':[28,3],
            'MA':[32,-6],'NG':[10,8],'KE':[-1,38],'ZA':[-29,25],'ET':[9,40],
            'GH':[8,-1],'TZ':[-6,35],'AO':[-12,18],'CM':[4,12],'CD':[-4,24],
            'IN':[21,78],'PK':[30,70],'BD':[24,90],'LK':[7,81],'NP':[28,84],
            'CN':[35,105],'JP':[36,138],'KR':[36,128],'TW':[23,121],'HK':[22,114],
            'SG':[1,104],'MY':[4,110],'TH':[15,101],'VN':[16,108],'PH':[12,122],
            'ID':[-5,120],'MM':[17,96],'KH':[13,105],'KZ':[48,68],
            'AU':[-25,134],'NZ':[-41,174],
        }

        regions = list(cc_counter.keys())
        markers = [
            {'coords': centroids_pw[cc], 'name': f"{cc_names.get(cc,cc)} ({cnt} IPs)"}
            for cc, cnt in cc_counter.items() if cc in centroids_pw
        ]

        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css"/>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117}}
#map{{width:1200px;height:500px;background:#0d1117}}
.jvm-tooltip{{background:#1c2d3a!important;color:#e6edf3!important;border:1px solid #30363d!important;font-size:11px!important;border-radius:4px!important;padding:4px 8px!important}}
</style></head><body>
<div id="map"></div>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/js/jsvectormap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/maps/world.js"></script>
<script>
window._ready = false;
try {{
  new jsVectorMap({{
    map:'world', selector:'#map',
    zoomButtons:false, zoomOnScroll:false, draggable:false,
    focusOn:{{ x:0.5, y:0.5, scale:1 }},
    selectedRegions:{_json.dumps(regions)},
    markers:{_json.dumps(markers)},
    regionStyle:{{
      initial:{{fill:'#1c2d3a',stroke:'#2d4a5e',strokeWidth:0.5}},
      selected:{{fill:'#1d3a5e'}},
    }},
    markerStyle:{{
      initial:{{fill:'#58a6ff',stroke:'#79c0ff',strokeWidth:1.5,r:5}},
      selected:{{fill:'#58a6ff'}},
    }},
    backgroundColor:'#0d1117',
  }});
}} catch(e){{console.error(e)}}
window._ready = true;
</script></body></html>"""

        try:
            import os as _os
            import tempfile as _tmp

            from playwright.sync_api import sync_playwright as _swp
            with _swp() as _p:
                _browser = _p.chromium.launch(headless=True)
                _page = _browser.new_page(viewport={'width': 1200, 'height': 500})
                _tf = _tmp.NamedTemporaryFile(suffix='.html', delete=False, mode='w')
                _tf.write(html)
                _tf.close()
                _page.goto(f"file://{_tf.name}", wait_until='networkidle', timeout=20000)
                _page.wait_for_timeout(800)
                _png = _page.locator('#map').screenshot()
                _browser.close()
                _os.unlink(_tf.name)

            if len(_png) < 5000:
                return None

            _buf = _BytesIO(_png)
            _ir = _IR(_buf)
            _iw, _ih = _ir.getSize()
            _w = 175 * mm
            _h = _w * (_ih / _iw)
            # Cap height at 90mm for full-width map
            _max_h = 90 * mm
            if _h > _max_h:
                _w = _max_h * (_iw / _ih)
                _h = _max_h
            return Image(_buf, width=_w, height=_h)
        except Exception as _e:
            return None

    # ── CERT: issuer bar chart ─────────────────────────────────────────────────
    def build_cert_issuer_chart(cert_data):
        issuers = cert_data.get("issuers", {})
        if not issuers:
            return None
        top = sorted(issuers.items(), key=lambda x: x[1], reverse=True)[:8]
        labels = [lbl[:28] for lbl, _ in top]
        vals = [v for _, v in top]
        palette = ["#58a6ff","#3fb950","#bc8cff","#f85149","#d29922","#8b949e","#79c0ff","#56d364"]
        fig, ax = plt.subplots(figsize=(5.5, 2.6))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#0d1117")
        bars = ax.barh(labels[::-1], vals[::-1],
                       color=[palette[i % len(palette)] for i in range(len(labels)-1,-1,-1)],
                       height=0.55)
        for bar, val in zip(bars, vals[::-1]):
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                    str(val), va="center", ha="left", color="#e6edf3", fontsize=7)
        ax.set_xlabel("Certs issued", color="#8b949e", fontsize=7)
        ax.tick_params(colors="#8b949e", labelsize=6.5)
        ax.spines[:].set_color("#30363d")
        ax.set_title("Certificate Issuers", color="#e6edf3", fontsize=8,
                     fontweight="bold", pad=6)
        fig.tight_layout()
        return fig_to_image(fig, width_mm=88)

    # ── CERT: issuance timeline chart ─────────────────────────────────────────
    def build_cert_timeline_chart(cert_data):
        certs = cert_data.get("certs", [])
        if not certs:
            return None
        by_year = {}
        for c in certs:
            yr = (c.get("not_before") or "")[:4]
            if yr and yr.isdigit():
                by_year[yr] = by_year.get(yr, 0) + 1
        if len(by_year) < 2:
            return None
        years = sorted(by_year.keys())
        vals = [by_year[y] for y in years]
        palette = ["#3fb950" if y == max(years) else "#58a6ff" for y in years]
        fig, ax = plt.subplots(figsize=(5, 2.6))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#0d1117")
        bars = ax.bar(years, vals, color=palette, width=0.6)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    str(val), ha="center", va="bottom", color="#e6edf3", fontsize=6.5)
        ax.tick_params(colors="#8b949e", labelsize=6.5, axis="x", rotation=30)
        ax.tick_params(colors="#8b949e", labelsize=6.5, axis="y")
        ax.spines[:].set_color("#30363d")
        ax.set_title("Cert Issuance by Year", color="#e6edf3", fontsize=8,
                     fontweight="bold", pad=6)
        fig.tight_layout()
        return fig_to_image(fig, width_mm=78)

    # ── GRAPH: ASN bar chart ──────────────────────────────────────────────────
    def build_asn_chart():
        if not org_counter:
            return None
        top = org_counter.most_common(6)
        labels = [o[:22] for o, _ in top]
        vals = [v for _, v in top]
        fig, ax = plt.subplots(figsize=(5.5, 2.8))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#0d1117")
        bars = ax.barh(labels[::-1], vals[::-1], color="#58a6ff", height=0.55)
        for bar, val in zip(bars, vals[::-1]):
            ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", ha="left", color="#e6edf3", fontsize=7)
        ax.set_xlabel("IP count", color="#8b949e", fontsize=7)
        ax.tick_params(colors="#8b949e", labelsize=7)
        ax.spines[:].set_color("#30363d")
        ax.set_title("Hosting / Networks", color="#e6edf3", fontsize=8, fontweight="bold", pad=6)
        fig.tight_layout()
        return fig_to_image(fig, width_mm=82)

    # ── GRAPH: country pie ────────────────────────────────────────────────────
    def build_country_chart():
        if not country_counter:
            return None
        top = country_counter.most_common(5)
        labels = [c for c, _ in top]
        vals = [v for _, v in top]
        palette = ["#58a6ff", "#3fb950", "#bc8cff", "#f85149", "#d29922"]
        fig, ax = plt.subplots(figsize=(3, 2.8))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#161b22")
        wedges, texts, autotexts = ax.pie(
            vals, labels=labels, autopct="%1.0f%%",
            colors=palette[:len(vals)], startangle=140,
            textprops={"color": "#e6edf3", "fontsize": 7},
            pctdistance=0.75,
        )
        for at in autotexts:
            at.set_color("#0d1117")
            at.set_fontsize(6)
        ax.set_title("Locations", color="#e6edf3", fontsize=8, fontweight="bold", pad=6)
        fig.tight_layout()
        return fig_to_image(fig, width_mm=58)

    # ── GRAPH: port heatmap ───────────────────────────────────────────────────
    def build_port_heatmap():
        if not port_scan:
            return None
        all_ports = {}
        for ip, ports in port_scan.items():
            for p in ports:
                key = f"{p['port']}/{p['service']}"
                if key not in all_ports:
                    all_ports[key] = {}
                all_ports[key][ip] = p["status"]

        open_ports = {k: v for k, v in all_ports.items() if any(s == "open" for s in v.values())}
        if not open_ports:
            return None

        ips = list(port_scan.keys())
        port_keys = sorted(open_ports.keys(), key=lambda x: int(x.split("/")[0]))
        matrix = []
        for pk in port_keys:
            row = []
            for ip in ips:
                status = all_ports.get(pk, {}).get(ip, "closed")
                row.append(1 if status == "open" else 0.3 if status == "filtered" else 0)
            matrix.append(row)

        fig, ax = plt.subplots(figsize=(max(4, len(ips) * 1.2), max(3, len(port_keys) * 0.35)))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#161b22")
        import numpy as np
        from matplotlib.colors import LinearSegmentedColormap
        cmap = LinearSegmentedColormap.from_list("ports", ["#0d1117", "#d29922", "#3fb950"])
        ax.imshow(np.array(matrix), aspect="auto", cmap=cmap, vmin=0, vmax=1)
        ax.set_xticks(range(len(ips)))
        ax.set_xticklabels(ips, fontsize=6, color="#8b949e", rotation=20, ha="right")
        ax.set_yticks(range(len(port_keys)))
        ax.set_yticklabels(port_keys, fontsize=6, color="#e6edf3", fontfamily="monospace")
        ax.set_title("Open Port Heatmap", color="#e6edf3", fontsize=8, fontweight="bold", pad=6)
        ax.tick_params(colors="#30363d")
        for spine in ax.spines.values():
            spine.set_color("#30363d")
        fig.tight_layout()
        return fig_to_image(fig, width_mm=175)

    # ════════════════════════════════════════════════════════════════════════
    # STORY BUILD
    # ════════════════════════════════════════════════════════════════════════

    # ── Page 1: Cover / header ───────────────────────────────────────────────
    story.append(HRFlowable(width=PW, thickness=4, color=C_RED, spaceAfter=0))

    # Dark header band
    hdr_inner = Table([
        [
            Paragraph('<font color="#f85149"><b>⬡</b></font>', S("logo", fontSize=28, leading=32, textColor=C_RED)),
            Table([
                [Paragraph("Infrastructure Recon Report", s_h1)],
                [Paragraph('<font color="#f85149">OSINT PH  ·  osintph.info</font>',
                            S("tl", fontSize=9, fontName="Helvetica-Bold", textColor=C_RED, leading=13))],
                [Paragraph(f'Target: <font color="#58a6ff"><b>{pdf_text(domain, 253)}</b></font>  ·  '
                           f'Investigated: {pdf_text(created, 40)}  ·  Generated: {dt.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M UTC")}',
                           S("meta", fontSize=7.5, textColor=C_MUTED, leading=11))],
            ], colWidths=[PW - 20 * mm]),
        ]
    ], colWidths=[16 * mm, PW - 16 * mm])
    hdr_inner.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND", (0,0), (-1,-1), C_BG),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
    ]))
    story.append(hdr_inner)
    story.append(HRFlowable(width=PW, thickness=1, color=C_BORDER, spaceAfter=8))

    # ── Stat strip ───────────────────────────────────────────────────────────
    bf_count = len(bruteforce)
    cert_count = len(passive)
    stat_items = [
        (str(inv.get("subdomain_count") or 0), "SUBDOMAINS"),
        (str(inv.get("resolved_count") or 0), "RESOLVED"),
        (str(bf_count), "BRUTE-FORCED"),
        (str(cert_count), "CERT SANs"),
        (str(len(main_ips)), "IPs"),
        ("⚠ YES" if zt_success else "✓ NO", "ZONE XFR"),
        ("✓" if email_sec.get("spf_valid") else "✗", "SPF"),
        ("✓" if email_sec.get("dmarc_valid") else "✗", "DMARC"),
    ]
    stat_colors = {
        "⚠ YES": C_RED, "✓ NO": C_GREEN,
        "✓": C_GREEN, "✗": C_RED,
    }
    stat_cells = []
    for val, lbl in stat_items:
        vc = stat_colors.get(val, C_ACCENT)
        cell = Table([
            [Paragraph(f'<b>{pdf_text(val, 40)}</b>', S(f"sv_{lbl}", fontSize=14, fontName="Helvetica-Bold", textColor=vc, leading=17))],
            [Paragraph(lbl, S(f"sl_{lbl}", fontSize=6, textColor=C_MUTED, leading=8, fontName="Helvetica-Bold"))],
        ], colWidths=[PW / len(stat_items) - 2])
        cell.setStyle(TableStyle([
            ("ALIGN", (0,0), (-1,-1), "CENTER"),
            ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 2),
            ("RIGHTPADDING", (0,0), (-1,-1), 2),
            ("BOX", (0,0), (-1,-1), 0.4, C_BORDER),
        ]))
        stat_cells.append(cell)

    stat_tbl = Table([stat_cells], colWidths=[PW / len(stat_items)] * len(stat_items))
    stat_tbl.setStyle(TableStyle([
        ("LEFTPADDING", (0,0), (-1,-1), 2),
        ("RIGHTPADDING", (0,0), (-1,-1), 2),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(stat_tbl)
    story.append(Spacer(1, 8))

    # ── Zone transfer alert ──────────────────────────────────────────────────
    if zt_success:
        ns_vuln = [ns for ns, info in zt.items() if isinstance(info, dict) and info.get("success")]
        alert_tbl = Table([[
            Paragraph("🚨", S("alertico", fontSize=16, leading=20)),
            Paragraph(f"<b>CRITICAL: Zone Transfer Succeeded</b><br/>"
                      f"Nameserver(s) {pdf_text(', '.join(ns_vuln), 500)} are leaking full DNS zone data. "
                      f"Restrict AXFR to authorised secondaries immediately.",
                      S("alerttxt", fontSize=8, textColor=C_RED, leading=12)),
        ]], colWidths=[10*mm, PW-10*mm])
        alert_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#3d0000")),
            ("BOX", (0,0), (-1,-1), 1, C_RED),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(alert_tbl)
        story.append(Spacer(1, 6))

    # ── Email security issues ─────────────────────────────────────────────────
    issues = email_sec.get("issues", [])
    if issues:
        for issue in issues:
            story.append(Paragraph(f"⚠ {pdf_text(issue, 500)}", s_warn))
        story.append(Spacer(1, 4))

    # ── Page 1: Infrastructure overview (charts side by side) ────────────────
    section_header("Infrastructure Overview")

    asn_img = build_asn_chart()
    cty_img = build_country_chart()
    if asn_img and cty_img:
        overview_tbl = Table([[asn_img, cty_img]], colWidths=[PW * 0.58, PW * 0.42])
        overview_tbl.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING", (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(overview_tbl)
    elif asn_img:
        story.append(asn_img)

    # ── World map ─────────────────────────────────────────────────────────────
    wmap = None
    if cc_counter:
        try:
            wmap = build_world_map()
        except Exception:
            wmap = None

    asn_tbl = None
    if org_counter:
        asn_rows = []
        all_geo_by_org = {}
        for sub in resolved:
            for g in (sub.get("geo") or []):
                if g and g.get("org"):
                    org = g["org"]
                    if org not in all_geo_by_org:
                        all_geo_by_org[org] = {"ips": set(), "asn": g.get("as",""), "country": g.get("country","")}
                    all_geo_by_org[org]["ips"].add(g.get("query",""))
        for org, cnt in org_counter.most_common(10):
            info = all_geo_by_org.get(org, {})
            asn_rows.append([
                Paragraph(pdf_text(org, 45), s_body),
                Paragraph(pdf_text(info.get("asn",""), 80), s_small),
                Paragraph(pdf_text(info.get("country",""), 60), s_small),
                Paragraph(str(cnt), S("cnt", fontSize=8, fontName="Helvetica-Bold", textColor=C_ACCENT, leading=12)),
            ])
        asn_tbl = dark_table(
            [Paragraph(h, S(f"ah_{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
             for h in ["Organisation / ASN Name", "ASN", "Country", "IPs"]],
            asn_rows, [PW*0.46, PW*0.26, PW*0.17, PW*0.11]
        )

    if wmap and asn_tbl:
        story.append(Spacer(1, 6))
        story.append(wmap)
        story.append(Spacer(1, 6))
        story.append(asn_tbl)
    elif wmap:
        story.append(Spacer(1, 6))
        story.append(wmap)
    elif asn_tbl:
        story.append(Spacer(1, 6))
        story.append(asn_tbl)

    # ── Subdomain graph ───────────────────────────────────────────────────────
    story.append(PageBreak())
    section_header("Subdomain Infrastructure Graph")
    story.append(Paragraph(
        f"{len(resolved)} passive subdomains · {len(bruteforce)} brute-forced · "
        f"{sum(len(s.get('ips',[])) for s in resolved)} IP nodes",
        s_small))
    story.append(Spacer(1, 4))
    try:
        graph_img = build_graph_image()
        story.append(graph_img)
    except Exception:
        graph_error_id = log_error(f"DNS PDF {inv_id}: graph generation failed")
        story.append(Paragraph(f"Graph generation failed. Error id: {graph_error_id}", s_warn))

    # ── DNS Records ───────────────────────────────────────────────────────────
    section_header("DNS Records")
    rec_rows = []
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]:
        for val in dns.get(rtype, []):
            geo = ip_geo.get(val, {})
            geo_s = f"{geo.get('city','')} {geo.get('country','')} · {geo.get('org','')}".strip(" ·")
            ptr_s = ptr.get(val, "")
            rec_rows.append([
                Paragraph(rtype, S(f"rt{rtype}", fontSize=7, fontName="Helvetica-Bold",
                    textColor=C_ACCENT, leading=10)),
                Paragraph(pdf_text(val, 1000), s_mono),
                Paragraph(pdf_text(ptr_s, 255), s_small),
                Paragraph(pdf_text(geo_s, 200), s_small),
            ])
    if rec_rows:
        story.append(dark_table(
            [Paragraph(h, S(f"rh{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
             for h in ["Type", "Value", "PTR", "Geolocation / Org"]],
            rec_rows, [PW*0.07, PW*0.27, PW*0.26, PW*0.40]
        ))

    # ── Email security ────────────────────────────────────────────────────────
    section_header("Email Security Analysis")
    spf_v = email_sec.get("spf_valid")
    dmarc_v = email_sec.get("dmarc_valid")
    dkim_sel = email_sec.get("dkim_selectors_found", [])
    score = 100 - (0 if spf_v else 35) - (0 if dmarc_v else 35) - (0 if dkim_sel else 20)
    score_col = C_GREEN if score >= 80 else C_YELLOW if score >= 50 else C_RED

    esec_data = [
        [Paragraph("Record", S("esh", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold")),
         Paragraph("Status", S("esh2", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold")),
         Paragraph("Value", S("esh3", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))],
        [Paragraph("SPF", s_body),
         Paragraph("✓ Valid" if spf_v else "✗ Missing", S("sv2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREEN if spf_v else C_RED, leading=12)),
         Paragraph(pdf_text(email_sec.get("spf") or "—", 1000), s_mono)],
        [Paragraph("DMARC", s_body),
         Paragraph("✓ Valid" if dmarc_v else "✗ Missing", S("dv2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREEN if dmarc_v else C_RED, leading=12)),
         Paragraph(pdf_text(email_sec.get("dmarc") or "—", 1000), s_mono)],
        [Paragraph("DKIM", s_body),
         Paragraph(f"✓ {len(dkim_sel)} selector(s)" if dkim_sel else "✗ Not detected",
                   S("kv2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREEN if dkim_sel else C_MUTED, leading=12)),
         Paragraph(pdf_text(", ".join(dkim_sel) or "No selectors found", 500), s_small)],
    ]
    esec_tbl = Table(esec_data, colWidths=[PW*0.12, PW*0.2, PW*0.68])
    esec_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), C_BG),
        ("TEXTCOLOR", (0,0), (-1,0), C_TEXT),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_BG]),
        ("GRID", (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))

    score_cell = Table([
        [Paragraph(f'<b>{score}</b>', S("sc", fontSize=28, fontName="Helvetica-Bold", textColor=score_col, leading=32))],
        [Paragraph("EMAIL SCORE", S("scl", fontSize=6, textColor=C_MUTED, leading=8, fontName="Helvetica-Bold"))],
        [Paragraph("GOOD" if score>=80 else "MODERATE RISK" if score>=50 else "HIGH RISK",
                   S("scr", fontSize=7, fontName="Helvetica-Bold", textColor=score_col, leading=9))],
    ], colWidths=[25*mm])
    score_cell.setStyle(TableStyle([
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("BOX", (0,0), (-1,-1), 0.4, score_col),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))

    email_layout = Table([[score_cell, esec_tbl]], colWidths=[27*mm, PW-27*mm])
    email_layout.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING", (0,0), (0,0), 6),
    ]))
    story.append(email_layout)

    # ── Subdomains table ──────────────────────────────────────────────────────
    section_header(f"Resolved Subdomains ({len(resolved)} passive · {len(bruteforce)} brute-forced)")
    all_sub_map = {s["subdomain"]: {**s, "src": "passive"} for s in resolved}
    for b in bruteforce:
        if b["subdomain"] not in all_sub_map:
            all_sub_map[b["subdomain"]] = {**b, "src": "brute"}

    sub_rows = []
    for sub in sorted(all_sub_map.values(), key=lambda x: x["subdomain"]):
        ips = ", ".join(sub.get("ips") or [])
        geo = geo_str(sub.get("geo") or [])
        src = sub.get("src", "passive")
        src_col = "#bc8cff" if src == "brute" else "#58a6ff"
        src_lbl = "brute-force" if src == "brute" else "passive"
        sub_rows.append([
            Paragraph(pdf_text(sub["subdomain"], 255), s_mono),
            Paragraph(pdf_text(ips, 500), s_mono),
            Paragraph(pdf_text(geo, 300), s_small),
            Paragraph(f'<font color="{src_col}"><b>{src_lbl}</b></font>',
                      S(f"src_{src}", fontSize=6.5, leading=10)),
        ])
    if sub_rows:
        story.append(dark_table(
            [Paragraph(h, S(f"sbh{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
             for h in ["Subdomain", "IP Address(es)", "Location", "Source"]],
            sub_rows, [PW*0.38, PW*0.23, PW*0.27, PW*0.12]
        ))

    # ── Certificate Transparency (rich version if available) ──────────────────
    if passive:
        # Try to fetch rich cert data from crt.sh for the PDF
        rich_cert_data = None
        try:
            _cr_result = _cached_fetch(
                ("crt.sh", domain),
                "https://crt.sh/?" + urlencode({"q": f"%.{domain}", "output": "json"}),
                headers={"User-Agent": "OSINTPH-PDFGen/1.0", "Accept": "application/json"},
                timeout=20,
            )
            if _cr_result is not None and _cr_result["status"] == 200:
                from datetime import datetime as _dt
                _now = _dt.now(timezone.utc).replace(tzinfo=None)
                _raw = json.loads(_cr_result["body"])
                _certs = []
                _seen = set()
                _issuer_cnt = Counter()
                _san_set = set()
                _expired = _expiring = _active = 0
                for _e in _raw:
                    _cid = _e.get("id")
                    if _cid in _seen:
                        continue
                    _seen.add(_cid)
                    _nb = _e.get("not_before","")
                    _na = _e.get("not_after","")
                    _nb_dt = _na_dt = None
                    for _fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                        try:
                            _nb_dt = _dt.strptime(_nb[:19], _fmt[:len(_nb[:19])])
                            break
                        except Exception:
                            pass
                    for _fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                        try:
                            _na_dt = _dt.strptime(_na[:19], _fmt[:len(_na[:19])])
                            break
                        except Exception:
                            pass
                    _is_exp = (_na_dt < _now) if _na_dt else False
                    _days = (_na_dt - _now).days if (_na_dt and not _is_exp) else None
                    _exp_soon = _days is not None and _days <= 30
                    _sans = sorted(set(s.strip().lower() for s in _e.get("name_value","").split("\n") if s.strip()))
                    _san_set.update(_sans)
                    _issuer_raw = _e.get("issuer_name","")
                    _icn = ""
                    for _p in _issuer_raw.split(","):
                        _p = _p.strip()
                        if _p.startswith("O="):
                            _icn = _p[2:].strip()
                            break
                    if not _icn:
                        for _p in _issuer_raw.split(","):
                            _p = _p.strip()
                            if _p.startswith("CN="):
                                _icn = _p[3:].strip()
                                break
                    if _icn:
                        _issuer_cnt[_icn] += 1
                    if _is_exp:
                        _expired += 1
                    elif _exp_soon:
                        _expiring += 1
                    else:
                        _active += 1
                    _certs.append({
                        "id": _cid, "issuer_org": _icn, "not_before": _nb,
                        "not_after": _na, "not_before_ts": int(_nb_dt.timestamp()) if _nb_dt else 0,
                        "is_expired": _is_exp, "expiring_soon": _exp_soon,
                        "days_remaining": _days, "sans": _sans,
                    })
                _certs.sort(key=lambda c: c.get("not_before_ts", 0), reverse=True)
                rich_cert_data = {
                    "total": len(_certs), "expired": _expired,
                    "expiring_soon": _expiring, "active": _active,
                    "unique_sans": len(_san_set), "issuers": dict(_issuer_cnt),
                    "certs": _certs,
                }
        except Exception:
            rich_cert_data = None

        if rich_cert_data and rich_cert_data.get("total", 0) > 0:
            cd = rich_cert_data
            section_header(f"Certificate Transparency — {cd['total']} certificates")

            # Stat strip
            cert_stat_items = [
                (str(cd["total"]), "TOTAL CERTS"),
                (str(cd["active"]), "ACTIVE"),
                (str(cd["expired"]), "EXPIRED"),
                (str(cd["expiring_soon"]), "EXPIRING SOON"),
                (str(cd["unique_sans"]), "UNIQUE SANs"),
            ]
            cert_stat_cells = []
            for val, lbl in cert_stat_items:
                col = C_RED if lbl == "EXPIRED" and int(val) > 0 else \
                      C_YELLOW if lbl == "EXPIRING SOON" and int(val) > 0 else \
                      C_GREEN if lbl == "ACTIVE" else C_ACCENT
                cell = Table([
                    [Paragraph(f'<b>{pdf_text(val, 40)}</b>', S(f"csv_{lbl[:4]}", fontSize=13,
                               fontName="Helvetica-Bold", textColor=col, leading=16))],
                    [Paragraph(lbl, S(f"csl_{lbl[:4]}", fontSize=5.5, textColor=C_MUTED,
                               leading=8, fontName="Helvetica-Bold"))],
                ], colWidths=[PW / len(cert_stat_items) - 2])
                cell.setStyle(TableStyle([
                    ("ALIGN", (0,0), (-1,-1), "CENTER"),
                    ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
                    ("TOPPADDING", (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                    ("BOX", (0,0), (-1,-1), 0.4, C_BORDER),
                ]))
                cert_stat_cells.append(cell)
            cert_stat_tbl = Table([cert_stat_cells],
                                  colWidths=[PW / len(cert_stat_items)] * len(cert_stat_items))
            cert_stat_tbl.setStyle(TableStyle([
                ("LEFTPADDING", (0,0), (-1,-1), 2),
                ("RIGHTPADDING", (0,0), (-1,-1), 2),
                ("TOPPADDING", (0,0), (-1,-1), 0),
                ("BOTTOMPADDING", (0,0), (-1,-1), 0),
            ]))
            story.append(cert_stat_tbl)
            story.append(Spacer(1, 6))

            # Issuer chart + timeline side by side
            try:
                ci_img = build_cert_issuer_chart(cd)
                ct_img = build_cert_timeline_chart(cd)
                if ci_img and ct_img:
                    charts_tbl = Table([[ci_img, ct_img]], colWidths=[PW*0.55, PW*0.45])
                    charts_tbl.setStyle(TableStyle([
                        ("VALIGN", (0,0), (-1,-1), "TOP"),
                        ("LEFTPADDING", (0,0), (-1,-1), 0),
                        ("RIGHTPADDING", (0,0), (-1,-1), 4),
                    ]))
                    story.append(charts_tbl)
                    story.append(Spacer(1, 6))
                elif ci_img:
                    story.append(ci_img)
                    story.append(Spacer(1, 6))
            except Exception:
                pass

            # Cert table — show all, colour-code expired/expiring
            cert_rows = []
            for c in cd["certs"][:150]:
                is_exp = c.get("is_expired")
                exp_soon = c.get("expiring_soon")
                days = c.get("days_remaining")
                status_txt = "EXPIRED" if is_exp else (f"⚠ {days}d" if exp_soon else "✓ Active")
                status_col = C_RED if is_exp else (C_YELLOW if exp_soon else C_GREEN)
                san_preview = (c["sans"][0] if c.get("sans") else "—")
                issuer_s = (c.get("issuer_org") or "—")[:32]
                cert_rows.append([
                    Paragraph(pdf_text(san_preview, 255), s_mono),
                    Paragraph(pdf_text(issuer_s, 80), s_small),
                    Paragraph(pdf_text((c.get("not_after") or ""), 10), s_small),
                    Paragraph(f'<b>{status_txt}</b>',
                              S(f"cst_{c['id']}", fontSize=6.5, fontName="Helvetica-Bold",
                                textColor=status_col, leading=9)),
                ])
            story.append(dark_table(
                [Paragraph(h, S(f"cth{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
                 for h in ["Subdomain / SAN", "Issuer", "Expires", "Status"]],
                cert_rows, [PW*0.42, PW*0.28, PW*0.14, PW*0.16]
            ))

        else:
            # Fallback: basic cert table from passive subdomains
            section_header(f"Certificate Transparency — {len(passive)} crt.sh certificates")
            cert_rows = []
            for c in passive[:100]:
                issuer = (c.get("issuer") or "").split("O=")[-1].split(",")[0][:35]
                cert_rows.append([
                    Paragraph(pdf_text(c.get("subdomain",""), 255), s_mono),
                    Paragraph(pdf_text(issuer, 80), s_small),
                    Paragraph(pdf_text((c.get("not_after") or ""), 10), s_small),
                ])
            story.append(dark_table(
                [Paragraph(h, S(f"ch{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
                 for h in ["Subdomain / SAN", "Issuer", "Expires"]],
                cert_rows, [PW*0.5, PW*0.3, PW*0.2]
            ))

    # ── Port scan ─────────────────────────────────────────────────────────────
    if port_scan:
        story.append(PageBreak())
        section_header("Port Scan Results")

        # Heatmap chart
        try:
            hm = build_port_heatmap()
            if hm:
                story.append(hm)
                story.append(Spacer(1, 6))
        except Exception:
            pass

        # Open ports detail table per IP
        for ip, ports in port_scan.items():
            open_p = [p for p in ports if p["status"] == "open"]
            filt_p = [p for p in ports if p["status"] == "filtered"]
            if not open_p and not filt_p:
                continue
            story.append(Paragraph(
                f'<font color="#58a6ff"><b>{pdf_text(ip, 60)}</b></font> — '
                f'<font color="#3fb950"><b>{len(open_p)} open</b></font>'
                + (f', <font color="#d29922">{len(filt_p)} filtered</font>' if filt_p else ""),
                S("ip_head", fontSize=8, textColor=C_TEXT, leading=12, spaceBefore=6, spaceAfter=3)
            ))
            if open_p:
                port_rows = [[
                    Paragraph(str(p["port"]), S("pn", fontSize=7, fontName="Helvetica-Bold", textColor=C_GREEN, leading=10)),
                    Paragraph(pdf_text(p["service"], 80), s_body),
                    Paragraph("OPEN", S("po", fontSize=7, fontName="Helvetica-Bold", textColor=C_GREEN, leading=10)),
                ] for p in open_p]
                story.append(dark_table(
                    [Paragraph(h, S(f"ph{h}", fontSize=7, textColor=C_TEXT, fontName="Helvetica-Bold"))
                     for h in ["Port", "Service", "Status"]],
                    port_rows, [PW*0.12, PW*0.38, PW*0.50]
                ))

    # ── Directory enumeration ─────────────────────────────────────────────────
    if dir_enum:
        interesting_total = sum(len([p for p in paths if p.get("status_code") not in (404,410)])
                                for paths in dir_enum.values())
        if interesting_total:
            section_header(f"Directory Enumeration — {interesting_total} paths found")
            for target, paths in dir_enum.items():
                interesting = [p for p in paths if p.get("status_code") not in (404, 410)]
                if not interesting:
                    continue
                story.append(Paragraph(
                    f'<font color="#58a6ff"><b>{pdf_text(target, 255)}</b></font> — {len(interesting)} paths',
                    S("dt_head", fontSize=8, textColor=C_TEXT, leading=12, spaceBefore=6, spaceAfter=3)
                ))
                dir_rows = []
                for p in interesting:
                    sc = p["status_code"]
                    sc_col = "#3fb950" if sc==200 else "#58a6ff" if 300<=sc<400 else "#d29922" if sc in (401,403) else "#f85149"
                    dir_rows.append([
                        Paragraph(f'<font color="{sc_col}"><b>{pdf_text(sc, 6)}</b></font>',
                                  S(f"dsc{sc}", fontSize=8, fontName="Helvetica-Bold", leading=12)),
                        Paragraph(pdf_text(p.get("path",""), 300), s_mono),
                        Paragraph(pdf_text(p.get("content_length","") or "—", 20), s_small),
                        Paragraph(pdf_text(p.get("redirect_to","") or "—", 300), s_small),
                    ])
                story.append(dark_table(
                    [Paragraph(h, S(f"dh{h}", fontSize=7, textColor=C_TEXT, fontName="Helvetica-Bold"))
                     for h in ["Code", "Path", "Size", "Redirect"]],
                    dir_rows, [PW*0.08, PW*0.42, PW*0.12, PW*0.38]
                ))

    # ── Zone transfer detail ──────────────────────────────────────────────────
    if zt_success:
        section_header("Zone Transfer Records — CRITICAL", C_RED)
        for ns, info in zt.items():
            if not info.get("success"):
                continue
            story.append(Paragraph(f"Nameserver: {pdf_text(ns, 255)} — {pdf_text(info.get('record_count',0), 12)} records exposed", s_warn))
            zt_rows = [
                [Paragraph(pdf_text(rec["name"], 255), s_mono), Paragraph(pdf_text(rec["type"], 20), s_body), Paragraph(pdf_text(rec["value"], 1000), s_mono)]
                for rec in (info.get("records") or [])[:80]
            ]
            if zt_rows:
                story.append(dark_table(
                    [Paragraph(h, S(f"zh{h}", fontSize=7, textColor=C_TEXT, fontName="Helvetica-Bold"))
                     for h in ["Name", "Type", "Value"]],
                    zt_rows, [PW*0.3, PW*0.1, PW*0.6],
                    row_colors=[colors.HexColor("#2d0000"), colors.HexColor("#1a0000")]
                ))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width=PW, thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"CONFIDENTIAL — Infrastructure Recon Report  ·  OSINT PH / osintph.info  ·  "
        f"Target: {pdf_text(domain, 253)}  ·  Report ID: OSINTPH-DNS-{inv_id}-{dt.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}",
        s_foot))

    doc.build(story, onFirstPage=dark_page, onLaterPages=dark_page)
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=osintph-dns-{domain}-{dt.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}.pdf"},
    )




# ── Projects API ───────────────────────────────────────────────────────────────


def _check_project_access(project_id: int, require_owner: bool = False):
    """Returns (project_dict, error_response). Checks auth and ownership."""
    storage = get_storage()
    project = storage.get_project(project_id)
    if not project:
        return None, (jsonify({"error": "Project not found"}), 404)
    user = current_user()
    if not user.is_admin and project["owner_id"] != user.id:
        return None, (jsonify({"error": "Access denied"}), 403)
    return project, None


@dashboard_bp.route("/api/projects", methods=["GET"])
@require_login
def api_projects_list():
    storage = get_storage()
    user = current_user()
    if user.is_admin:
        projects = storage.list_projects()
    else:
        projects = storage.list_projects(owner_id=user.id)
    # attach owner username
    for p in projects:
        owner = storage.get_user_by_id(p["owner_id"])
        p["owner_username"] = owner.username if owner else "unknown"
    return jsonify(projects)


@dashboard_bp.route("/api/projects", methods=["POST"])
@require_login
def api_projects_create():
    body = v.json_body()
    name = v.text(body.get("name"), "Project name", 120)
    storage = get_storage()
    project_id = storage.create_project(
        name=name,
        owner_id=current_user().id,
        description=v.free_text(body.get("description"), "description", 2000),
        color=v.color(body.get("color")),
        tags=v.tags(body.get("tags")),
        alert_threshold=v.to_int(body.get("alert_threshold"), 1, 1, 1000),
    )
    return jsonify({"ok": True, "id": project_id})


@dashboard_bp.route("/api/projects/<int:project_id>", methods=["GET"])
@require_login
def api_projects_get(project_id):
    project, err = _check_project_access(project_id)
    if err:
        return err
    storage = get_storage()
    owner = storage.get_user_by_id(project["owner_id"])
    project["owner_username"] = owner.username if owner else "unknown"
    return jsonify(project)


@dashboard_bp.route("/api/projects/<int:project_id>", methods=["PUT"])
@require_login
def api_projects_update(project_id):
    project, err = _check_project_access(project_id)
    if err:
        return err
    body = v.json_body()
    updates = {}
    if "name" in body:
        updates["name"] = v.text(body.get("name"), "Project name", 120)
    if "description" in body:
        updates["description"] = v.free_text(body.get("description"), "description", 2000)
    if "status" in body:
        if body.get("status") not in ("active", "paused", "archived"):
            return jsonify({"error": "status must be active, paused, or archived"}), 400
        updates["status"] = body["status"]
    if "color" in body:
        updates["color"] = v.color(body.get("color"))
    if "tags" in body:
        updates["tags"] = v.tags(body.get("tags"))
    if "alert_threshold" in body:
        updates["alert_threshold"] = v.to_int(body.get("alert_threshold"), 1, 1, 1000)
    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400
    get_storage().update_project(project_id, **updates)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/projects/<int:project_id>", methods=["DELETE"])
@require_login
def api_projects_delete(project_id):
    project, err = _check_project_access(project_id)
    if err:
        return err
    get_storage().delete_project(project_id)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/projects/<int:project_id>/status", methods=["PATCH"])
@require_login
def api_projects_status(project_id):
    project, err = _check_project_access(project_id)
    if err:
        return err
    body = v.json_body()
    status = body.get("status")
    if status not in ("active", "paused", "archived"):
        return jsonify({"error": "status must be active, paused, or archived"}), 400
    get_storage().update_project(project_id, status=status)
    return jsonify({"ok": True})


# Keywords
@dashboard_bp.route("/api/projects/<int:project_id>/keywords", methods=["GET"])
@require_login
def api_project_keywords_get(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_keywords(project_id))


@dashboard_bp.route("/api/projects/<int:project_id>/keywords", methods=["POST"])
@require_login
def api_project_keywords_add(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    body = v.json_body()
    keyword = v.keyword(body.get("keyword"))
    is_regex = v.strict_bool(body.get("is_regex"), "is_regex")
    if is_regex:
        try:
            regex_safety.check_pattern(keyword)
        except regex_safety.UnsafePattern as exc:
            return jsonify({"error": f"The pattern is not accepted: {exc}."}), 400
    kid = get_storage().add_project_keyword(
        project_id, keyword,
        category=v.category(body.get("category")),
        is_regex=is_regex,
    )
    return jsonify({"ok": True, "id": kid})


@dashboard_bp.route("/api/projects/<int:project_id>/keywords/<int:keyword_id>", methods=["DELETE"])
@require_login
def api_project_keywords_delete(project_id, keyword_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    if not get_storage().delete_project_keyword(project_id, keyword_id):
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


# Domains
@dashboard_bp.route("/api/projects/<int:project_id>/domains", methods=["GET"])
@require_login
def api_project_domains_get(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_domains(project_id))


@dashboard_bp.route("/api/projects/<int:project_id>/domains", methods=["POST"])
@require_login
def api_project_domains_add(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    body = v.json_body()
    domain = v.domain(body.get("domain"))
    did = get_storage().add_project_domain(
        project_id, domain,
        priority=v.to_int(body.get("priority"), 3, 1, 5),
        notes=v.free_text(body.get("notes"), "notes", 1000),
    )
    return jsonify({"ok": True, "id": did})


@dashboard_bp.route("/api/projects/<int:project_id>/domains/<int:domain_id>", methods=["DELETE"])
@require_login
def api_project_domains_delete(project_id, domain_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    if not get_storage().delete_project_domain(project_id, domain_id):
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


# Entities
@dashboard_bp.route("/api/projects/<int:project_id>/entities", methods=["GET"])
@require_login
def api_project_entities_get(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_entities(project_id))


@dashboard_bp.route("/api/projects/<int:project_id>/entities", methods=["POST"])
@require_login
def api_project_entities_add(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    body = v.json_body()
    entity_type = str(body.get("entity_type") or "").strip()
    valid_types = ("person", "organization", "brand", "ip", "email", "bitcoin_address")
    if entity_type not in valid_types:
        return jsonify({"error": f"entity_type must be one of {valid_types}"}), 400
    value = v.text(body.get("value"), "value", 300)
    eid = get_storage().add_project_entity(
        project_id, entity_type, value, v.free_text(body.get("notes"), "notes", 1000)
    )
    return jsonify({"ok": True, "id": eid})


@dashboard_bp.route("/api/projects/<int:project_id>/entities/<int:entity_id>", methods=["DELETE"])
@require_login
def api_project_entities_delete(project_id, entity_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    if not get_storage().delete_project_entity(project_id, entity_id):
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


# Hits & Stats
@dashboard_bp.route("/api/projects/<int:project_id>/hits", methods=["GET"])
@require_login
def api_project_hits(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    limit = v.int_arg("limit", 100, 1, 1000)
    return jsonify(get_storage().get_project_hits(project_id, limit=limit))


@dashboard_bp.route("/api/projects/<int:project_id>/stats", methods=["GET"])
@require_login
def api_project_stats(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_stats(project_id))




# ── OSINT Toolkit Proxy Routes ────────────────────────────────────────────────
# Server-side proxy so browser CORS restrictions don't block external APIs
# All routes use safe_fetch() which enforces HTTPS, host allowlist, and IP
# blocklist. See dashboard/http_client.py for the full policy.


@dashboard_bp.route("/api/osint/github/<username>")
@require_login
def osint_github(username):
    """Proxy GitHub public API."""
    import json as _json
    user = _path_segment(username, "username")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "OsintTool/1.0"}

    def get(key, url):
        # A blocked request comes back as the exception: the two calls run on the pool.
        try:
            return _cached_fetch(key, url, headers=headers)
        except SafeFetchError as exc:
            return exc

    got = jobs.call_all({
        "profile": lambda: get(("github", user), f"https://api.github.com/users/{user}"),
        "events": lambda: get(
            ("github events", user), f"https://api.github.com/users/{user}/events/public?per_page=10"
        ),
    }, timeout=25)
    _r1, _r2 = got["profile"], got["events"]
    if isinstance(_r1, SafeFetchError) or isinstance(_r2, SafeFetchError):
        logger.warning("GitHub OSINT safe_fetch blocked: %s", _r1 if isinstance(_r1, SafeFetchError) else _r2)
        return jsonify({"error": "External request blocked by security policy."}), 502
    if _r1 is None:
        return jsonify({"error": "GitHub did not answer. Try again in a minute."}), 502
    status, body, ev_body = _r1["status"], _r1["body"], (_r2 or {}).get("body")
    try:
        profile = _json.loads(body)
        events = _json.loads(ev_body) if ev_body else []
        emails = list({
            ev.get("payload", {}).get("commits", [{}])[0].get("author", {}).get("email", "")
            for ev in (events if isinstance(events, list) else [])
            if ev.get("payload", {}).get("commits")
            and "noreply" not in ev.get("payload", {}).get("commits", [{}])[0].get("author", {}).get("email", "noreply")
        } - {""})
        profile["_extracted_emails"] = emails
        return jsonify(profile), status
    except Exception:
        return api_error("GitHub sent an answer that could not be read.")


@dashboard_bp.route("/api/osint/reddit/<username>")
@require_login
def osint_reddit(username):
    import json as _json
    user = _path_segment(username, "username")
    try:
        _r = _cached_fetch(
            ("reddit", user),
            f"https://www.reddit.com/user/{user}/about.json",
            headers={"User-Agent": "OsintTool/1.0 (research)", "Accept": "application/json"},
        )
    except SafeFetchError as e:
        logger.warning("Reddit OSINT safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    if _r is None:
        return jsonify({"error": "Reddit did not answer. Try again in a minute."}), 502
    try:
        return jsonify(_json.loads(_r["body"])), _r["status"]
    except Exception:
        return api_error("Reddit sent an answer that could not be read.")


@dashboard_bp.route("/api/osint/discord/<user_id>")
@require_login
def osint_discord(user_id):
    import json as _json
    user = _path_segment(user_id, "user id")
    try:
        _r = _cached_fetch(("discord", user), f"https://discordlookup.mesalytic.moe/v1/user/{user}")
    except SafeFetchError as e:
        logger.warning("Discord OSINT safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    if _r is None:
        return jsonify({"error": "The Discord lookup did not answer. Try again in a minute."}), 502
    try:
        return jsonify(_json.loads(_r["body"])), _r["status"]
    except Exception:
        return api_error("The Discord lookup sent an answer that could not be read.")


@dashboard_bp.route("/api/osint/domain/<path:domain>")
@require_login
def osint_domain(domain):
    import json as _json
    domain = v.domain(domain.strip().split("/")[0])
    results = {}

    def get(key, url, **kwargs):
        try:
            return _cached_fetch(key, url, **kwargs)
        except SafeFetchError:
            return None

    # The two lookups do not depend on each other: they run side by side.
    # RDAP — rdap.org is allowlisted; registry-specific redirect targets are not.
    # If rdap.org redirects to a non-allowlisted registry RDAP server, SafeFetchError
    # is raised and we return an empty rdap result gracefully.
    got = jobs.call_all({
        "rdap": lambda: get(
            ("rdap", domain), f"https://rdap.org/domain/{quote(domain, safe='')}", allow_redirects=True
        ),
        "crtsh": lambda: get(
            ("crt.sh names", domain),
            "https://crt.sh/?" + urlencode({"q": domain, "output": "json"}),
            headers={"User-Agent": "OsintTool/1.0", "Accept": "application/json"},
        ),
    }, timeout=25)
    _rdap, _crt = got["rdap"], got["crtsh"]
    rdap_status, rdap_body = (_rdap["status"], _rdap["body"]) if _rdap else (0, b"")
    try:
        results["rdap"] = _json.loads(rdap_body)
        results["rdap_status"] = rdap_status
    except Exception:
        results["rdap"] = None
        results["rdap_status"] = rdap_status
    # crt.sh
    crt_status, crt_body = (_crt["status"], _crt["body"]) if _crt else (0, b"[]")
    try:
        certs = _json.loads(crt_body) if crt_status == 200 else []
        names = sorted(set(
            n.strip()
            for c in certs
            for n in c.get("name_value", "").split("\n")
            if n.strip()
        ))
        results["crtsh"] = names
    except Exception:
        results["crtsh"] = []
    return jsonify(results)


@dashboard_bp.route("/api/osint/tiktok/<username>")
@require_login
def osint_tiktok(username):
    import json as _json
    user = v.text(username, "username", 100)
    try:
        _r = _cached_fetch(
            ("tiktok", user),
            "https://www.tiktok.com/api/user/detail/?" + urlencode({"uniqueId": user, "aid": "1988"}),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://www.tiktok.com/",
                "Accept": "application/json",
            },
        )
    except SafeFetchError as e:
        logger.warning("TikTok OSINT safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    if _r is None:
        return jsonify({"error": "TikTok did not answer. Try again in a minute."}), 502
    try:
        data = _json.loads(_r["body"])
        return jsonify(data), _r["status"]
    except Exception:
        return api_error("TikTok sent an answer that could not be read.")


def _wmn_sites() -> list:
    """The WhatsMyName site list, fetched at most once in six hours. Raises when there is none."""
    def fetch():
        result = safe_fetch(
            "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
            timeout=15,
        )
        if result["status"] != 200:
            raise _UpstreamFailed(f"HTTP {result['status']} for the WhatsMyName list")
        sites = json.loads(result["body"]).get("sites", [])
        return [s for s in sites if isinstance(s, dict) and s.get("uri_check") and s.get("e_code") == 200][:200]

    sites = _wmn_cache.get("sites", fetch)
    if sites is None:
        raise _UpstreamFailed("no WhatsMyName list")
    return sites


# One username check: how many sites are asked at a time, and for how long in all.
USERNAME_CHECK_PARALLEL = 12
USERNAME_CHECK_SECONDS = 45


@dashboard_bp.route("/api/osint/username/<username>")
@require_login
@jobs.heavy
def osint_username_check(username):
    """Check a username against WhatsMyName dataset."""
    account = _path_segment(username, "username")
    try:
        sites = _wmn_sites()
    except Exception:
        return api_error("Could not fetch WMN data")

    def check(site):
        url = site["uri_check"].replace("{account}", account)
        # WhatsMyName spans 200+ public sites — host allowlist not applied.
        # HTTPS enforced; private-IP blocklist applied to block SSRF.
        if not url.startswith("https://"):
            return False
        try:
            # Resolves once, refuses internal addresses, connects to the address it checked.
            r = fetch_public(url, timeout=5, max_bytes=512_000)
            st, body_b = r["status"], r["body"]
        except (SafeFetchError, Exception):
            return False
        text = body_b.decode("utf-8", errors="replace")
        e_string = site.get("e_string", "")
        m_string = site.get("m_string", "")
        if st == site["e_code"] and (not e_string or e_string in text) and (not m_string or m_string not in text):
            return {"name": site["name"], "url": url, "pretty": site.get("uri_pretty", "").replace("{account}", account)}
        return False

    # The sites are asked through the shared pool, a few at a time, and the
    # whole check has a time limit. A site not reached by then gives None.
    answers = jobs.fan_out(check, sites, parallel=USERNAME_CHECK_PARALLEL, timeout=USERNAME_CHECK_SECONDS)
    found = [a for a in answers if a]
    skipped = sum(1 for a in answers if a is None)

    return jsonify({"found": found, "checked": len(sites) - skipped, "skipped": skipped})


# ── ThreatFox proxy (avoids browser CORS) ─────────────────────────────────────

@dashboard_bp.route("/api/proxy/threatfox", methods=["POST"])
@require_login
def proxy_threatfox():
    """Proxy ThreatFox API — avoids CORS from browser.

    Only the recent-IOC query the page uses is relayed; the request is rebuilt
    here, so nothing else can be sent with the organisation's key.
    """
    asked = v.json_body()
    if asked.get("query") != "get_iocs":
        return jsonify({"error": "only the get_iocs query is relayed"}), 400
    days = v.to_int(asked.get("days"), 1, 1, 7)
    body = json.dumps({"query": "get_iocs", "days": days}).encode()
    api_key = os.getenv("THREATFOX_API_KEY", "")
    _hdrs = {"Content-Type": "application/json", "User-Agent": "OSINTPH/1.0"}
    if api_key:
        _hdrs["Auth-Key"] = api_key
    try:
        _r = _cached_fetch(
            ("threatfox", days),
            "https://threatfox-api.abuse.ch/api/v1/",
            method="POST",
            headers=_hdrs,
            data=body,
            timeout=15,
        )
    except SafeFetchError as e:
        logger.warning("ThreatFox proxy safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    if _r is None:
        return jsonify({"error": "ThreatFox did not answer. Try again in a minute."}), 502
    return Response(_r["body"], mimetype="application/json")


@dashboard_bp.route("/api/proxy/urlhaus", methods=["POST"])
@require_login
def proxy_urlhaus():
    """Proxy URLhaus recent URLs."""
    try:
        _r = _cached_fetch(
            "urlhaus recent",
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "OSINTPH/1.0"},
            data=b"limit=200",
            timeout=15,
        )
    except SafeFetchError as e:
        logger.warning("URLhaus proxy safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    if _r is None:
        return jsonify({"error": "URLhaus did not answer. Try again in a minute."}), 502
    return Response(_r["body"], mimetype="application/json")


@dashboard_bp.route("/api/proxy/feodo")
@require_login
def proxy_feodo():
    """Proxy Feodo Tracker C2 blocklist."""
    try:
        _r = _cached_fetch("feodo blocklist", "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    except SafeFetchError as e:
        logger.warning("Feodo proxy safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    if _r is None:
        return jsonify({"error": "Feodo Tracker did not answer. Try again in a minute."}), 502
    return Response(_r["body"], mimetype="application/json")


# ── WhiteIntel proxy ───────────────────────────────────────────────────────────

@dashboard_bp.route("/api/whiteintel/alerts")
@require_login
def whiteintel_alerts():
    """
    Fetch credential exposure alerts from WhiteIntel.
    Requires WHITEINTEL_API_KEY in .env
    GET /api/whiteintel/alerts?page=1&limit=50&severity=critical
    """
    import json as _json
    api_key = os.getenv("WHITEINTEL_API_KEY", "")
    if not api_key:
        return jsonify({"ok": False, "error": "WHITEINTEL_API_KEY not set", "data": []}), 200

    query = {
        "page": v.int_arg("page", 1, 1, 100000),
        "limit": v.int_arg("limit", 50, 1, 500),
    }
    severity = request.args.get("severity", "").strip()[:40]
    if severity:
        query["severity"] = severity

    try:
        _r = _cached_fetch(
            ("whiteintel alerts", tuple(query.items())),
            "https://whiteintel.io/api/v1/alerts?" + urlencode(query),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "OSINTPH/1.0",
            },
        )
    except SafeFetchError as e:
        logger.warning("WhiteIntel alerts safe_fetch blocked: %s", e)
        return jsonify({"ok": False, "error": "External request blocked by security policy.", "data": []}), 200
    if _r is None:
        return jsonify({"ok": False, "error": "WhiteIntel did not answer. Try again in a minute.", "data": []}), 200
    status, body = _r["status"], _r["body"]
    try:
        data = _json.loads(body)
        return jsonify({"ok": True, "data": data})
    except Exception:
        return jsonify({"ok": False, "error": f"HTTP {status}"}), 200


@dashboard_bp.route("/api/whiteintel/search")
@require_login
def whiteintel_search():
    """Search WhiteIntel for a specific domain. ?domain=example.com"""
    import json as _json
    api_key = os.getenv("WHITEINTEL_API_KEY", "")
    domain  = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"ok": False, "error": "domain parameter required"}), 400
    if not api_key:
        return jsonify({"ok": False, "error": "WHITEINTEL_API_KEY not set", "data": []}), 200

    try:
        _r = _cached_fetch(
            ("whiteintel search", domain.lower()),
            "https://whiteintel.io/api/v1/search?" + urlencode({"domain": domain}),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "OSINTPH/1.0",
            },
        )
    except SafeFetchError as e:
        logger.warning("WhiteIntel search safe_fetch blocked: %s", e)
        return jsonify({"ok": False, "error": "External request blocked by security policy."}), 200
    if _r is None:
        return jsonify({"ok": False, "error": "WhiteIntel did not answer. Try again in a minute."}), 200
    status, body = _r["status"], _r["body"]
    try:
        data = _json.loads(body)
        return jsonify({"ok": True, "data": data})
    except Exception:
        return jsonify({"ok": False, "error": f"HTTP {status}"}), 200


# ── Quick Scan ─────────────────────────────────────────────────────────────────


def _iso(dt):
    return dt.isoformat() if dt else None


def _quick_scan_session_dict(sess) -> dict:
    return {
        "id": sess.id,
        "target_value": sess.target_value,
        "target_type": sess.target_type,
        "normalized_variants": json.loads(sess.normalized_variants or "[]"),
        "sources_used": json.loads(sess.sources_used or "[]"),
        "status": sess.status,
        "started_at": _iso(sess.started_at),
        "completed_at": _iso(sess.completed_at),
        "urls_visited": sess.urls_visited,
        "findings_count": sess.findings_count,
        "error_message": sess.error_message,
    }


@dashboard_bp.route("/quick-scan")
@require_login
def quick_scan_page():
    from ..quick_scan_sources import ALL_SOURCES

    sources = [
        {"name": s.name, "label": s.label, "kind": s.kind,
         "transport": s.transport, "enabled": s.enabled}
        for s in ALL_SOURCES
    ]
    return render_template(
        "quick_scan.html",
        username=session.get("username"),
        sources=sources,
    )


@dashboard_bp.route("/api/quick-scan/start", methods=["POST"])
@require_login
def api_quick_scan_start():
    import asyncio

    from ..quick_scan import (
        VALID_TARGET_TYPES,
        detect_target_type,
        normalize_variants,
        run_quick_scan,
    )
    from ..quick_scan_sources import resolve_sources
    from ..tor_client import create_tor_client

    storage = get_storage()
    user_id = session["user_id"]

    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400

    target_type = body.get("target_type")
    if target_type in (None, "", "auto"):
        target_type = detect_target_type(target)
    elif target_type not in VALID_TARGET_TYPES:
        return jsonify({"error": f"invalid target_type {target_type!r}"}), 400

    variants = normalize_variants(target, target_type)

    requested_sources = body.get("sources")
    sources = resolve_sources(requested_sources)
    if not sources:
        return jsonify({"error": "no enabled sources selected"}), 400
    source_names = [s.name for s in sources]

    # Single active quick scan per user (DB-backed so it holds across workers).
    if storage.has_active_quick_scan(user_id):
        return jsonify({"error": "A quick scan is already running"}), 409

    # A scan counts as one heavy operation until its thread ends.
    slot = jobs.acquire_slot()  # Busy (429) when too many long requests are running
    try:
        session_id = storage.create_quick_scan_session(
            user_id=user_id,
            target_value=target,
            target_type=target_type,
            normalized_variants=variants,
            sources_used=source_names,
        )
    except BaseException:
        slot.release()
        raise

    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        tor_client = create_tor_client()
        try:
            loop.run_until_complete(run_quick_scan(session_id, storage, tor_client))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Quick scan thread crashed for session %s", session_id)
            try:
                storage.update_quick_scan_session(
                    session_id,
                    status="failed",
                    error_message=f"Scan crashed: {type(exc).__name__}",
                )
            except Exception:
                pass
        finally:
            try:
                loop.run_until_complete(tor_client.close())
            except Exception:
                pass
            loop.close()

    jobs.start_background(run, slot, name="quick_scan_thread")

    return jsonify({"session_id": session_id}), 201


@dashboard_bp.route("/api/quick-scan/status/<int:session_id>")
@require_login
def api_quick_scan_status(session_id):
    storage = get_storage()
    sess = storage.get_quick_scan_session(session_id)
    if sess is None:
        return jsonify({"error": "not found"}), 404
    if sess.user_id != session["user_id"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({
        "status": sess.status,
        "started_at": _iso(sess.started_at),
        "completed_at": _iso(sess.completed_at),
        "urls_visited": sess.urls_visited,
        "findings_count": sess.findings_count,
        "error_message": sess.error_message,
    })


@dashboard_bp.route("/api/quick-scan/cancel/<int:session_id>", methods=["POST"])
@require_login
def api_quick_scan_cancel(session_id):
    storage = get_storage()
    sess = storage.get_quick_scan_session(session_id)
    if sess is None:
        return jsonify({"error": "not found"}), 404
    if sess.user_id != session["user_id"]:
        return jsonify({"error": "forbidden"}), 403
    if sess.status not in ("pending", "running"):
        return jsonify({"error": f"cannot cancel a scan in status {sess.status!r}"}), 400
    storage.update_quick_scan_session(
        session_id,
        status="cancelled",
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    logger.info("Quick scan %s cancelled by user %s", session_id, session["user_id"])
    return jsonify(_quick_scan_session_dict(storage.get_quick_scan_session(session_id)))


@dashboard_bp.route("/api/quick-scan/sessions")
@require_login
def api_quick_scan_sessions():
    storage = get_storage()
    sessions = storage.list_quick_scan_sessions(session["user_id"], limit=50)
    return jsonify([_quick_scan_session_dict(s) for s in sessions])


@dashboard_bp.route("/api/quick-scan/findings/<int:session_id>")
@require_login
def api_quick_scan_findings(session_id):
    storage = get_storage()
    sess = storage.get_quick_scan_session(session_id)
    if sess is None:
        return jsonify({"error": "not found"}), 404
    if sess.user_id != session["user_id"]:
        return jsonify({"error": "forbidden"}), 403
    high_signal_only = request.args.get("high_signal_only") == "1"
    findings = storage.list_quick_scan_findings(session_id, high_signal_only=high_signal_only)
    return jsonify([
        {
            "id": f.id,
            "source_name": f.source_name,
            "url": f.url,
            "matched_variant": f.matched_variant,
            "context": f.context,
            "high_signal": f.high_signal,
            "found_at": _iso(f.found_at),
        }
        for f in findings
    ])


# ── Health ─────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()})
