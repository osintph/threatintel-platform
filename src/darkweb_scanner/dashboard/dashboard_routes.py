"""
Dashboard blueprint — all protected routes.
"""

import json
import os
import ssl
import urllib.error
import urllib.request
import urllib3
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, jsonify, render_template, request, session

from ..auth import hash_password, require_login, validate_password_strength
from .storage_helper import get_storage

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dashboard_bp = Blueprint("dashboard", __name__)

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
CLEARNET_SEEDS_FILE = DATA_DIR / "clearnet_seeds.txt"
PASTE_SOURCES_FILE  = DATA_DIR / "paste_sources.txt"


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


# ── Pages ──────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/dashboard")
@require_login
def index():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    return render_template("index.html", username=session.get("username"), is_admin=user.is_admin)


# ── Stats & Hits API ───────────────────────────────────────────────────────────


@dashboard_bp.route("/api/stats")
@require_login
def api_stats():
    return jsonify(get_storage().get_stats())


@dashboard_bp.route("/api/hits")
@require_login
def api_hits():
    limit = int(request.args.get("limit", 100))
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/keywords", methods=["POST"])
@require_login
def api_keywords_add():
    try:
        import yaml

        body = request.get_json()
        keyword = (body.get("keyword") or "").strip()
        category = (body.get("category") or "custom").strip()
        if not keyword:
            return jsonify({"error": "keyword required"}), 400

        _ensure_data_dir()
        cats = _load_keywords()
        cats.setdefault(category, [])
        if keyword not in cats[category]:
            cats[category].append(keyword)
            KEYWORDS_FILE.write_text(
                yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
            )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/keywords", methods=["DELETE"])
@require_login
def api_keywords_delete():
    try:
        import yaml

        body = request.get_json()
        keyword = (body.get("keyword") or "").strip()
        category = (body.get("category") or "").strip()
        if not keyword or not category:
            return jsonify({"error": "keyword and category required"}), 400

        _ensure_data_dir()
        cats = _load_keywords()
        if keyword in cats.get(category, []):
            cats[category].remove(keyword)
            KEYWORDS_FILE.write_text(
                yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
            )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Seeds API ──────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/seeds", methods=["GET"])
@require_login
def api_seeds_get():
    try:
        return jsonify({"seeds": _load_seeds()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/seeds", methods=["POST"])
@require_login
def api_seeds_add():
    try:
        body = request.get_json()
        # Support both single url and bulk urls array
        urls = body.get("urls") or ([body.get("url")] if body.get("url") else [])
        urls = [u.strip() for u in urls if u and u.strip()]
        if not urls:
            return jsonify({"error": "url(s) required"}), 400
        invalid = [u for u in urls if not u.startswith("http")]
        if invalid and len(invalid) == len(urls):
            return jsonify({"error": "URLs must start with http"}), 400

        _ensure_data_dir()
        existing = _load_seeds()
        added = 0
        for url in urls:
            if url.startswith("http") and url not in existing:
                existing.append(url)
                added += 1
        SEEDS_FILE.write_text("\n".join(existing) + "\n")
        return jsonify({"ok": True, "added": added})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/seeds", methods=["DELETE"])
@require_login
def api_seeds_delete():
    try:
        body = request.get_json()
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400

        _ensure_data_dir()
        seeds = [s for s in _load_seeds() if s != url]
        SEEDS_FILE.write_text("\n".join(seeds) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Clearnet Seeds API ─────────────────────────────────────────────────────────

def _load_clearnet_seeds() -> list[str]:
    if not CLEARNET_SEEDS_FILE.exists():
        return []
    return [line.strip() for line in CLEARNET_SEEDS_FILE.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]

def _save_clearnet_seeds(seeds: list[str]):
    _ensure_data_dir()
    CLEARNET_SEEDS_FILE.write_text("\n".join(seeds) + "\n")

def _load_paste_sources() -> list[str]:
    if not PASTE_SOURCES_FILE.exists():
        return []
    return [line.strip() for line in PASTE_SOURCES_FILE.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]

def _save_paste_sources(sources: list[str]):
    _ensure_data_dir()
    PASTE_SOURCES_FILE.write_text("\n".join(sources) + "\n")


@dashboard_bp.route("/api/seeds/clearnet", methods=["GET"])
@require_login
def api_clearnet_seeds_get():
    return jsonify({"seeds": _load_clearnet_seeds()})


@dashboard_bp.route("/api/seeds/clearnet", methods=["POST"])
@require_login
def api_clearnet_seeds_add():
    body = request.get_json() or {}
    urls = body.get("urls") or ([body.get("url")] if body.get("url") else [])
    urls = [u.strip() for u in urls if u and u.strip()]
    if not urls:
        return jsonify({"error": "url(s) required"}), 400
    existing = _load_clearnet_seeds()
    added = 0
    for url in urls:
        if url not in existing:
            existing.append(url)
            added += 1
    _save_clearnet_seeds(existing)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/seeds/clearnet", methods=["DELETE"])
@require_login
def api_clearnet_seeds_delete():
    body = request.get_json() or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    seeds = [s for s in _load_clearnet_seeds() if s != url]
    _save_clearnet_seeds(seeds)
    return jsonify({"ok": True})


# ── Paste Sources API ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/seeds/paste", methods=["GET"])
@require_login
def api_paste_sources_get():
    return jsonify({"sources": _load_paste_sources()})


@dashboard_bp.route("/api/seeds/paste", methods=["POST"])
@require_login
def api_paste_sources_add():
    body = request.get_json() or {}
    urls = body.get("urls") or ([body.get("url")] if body.get("url") else [])
    urls = [u.strip() for u in urls if u and u.strip()]
    if not urls:
        return jsonify({"error": "url(s) required"}), 400
    existing = _load_paste_sources()
    added = 0
    for url in urls:
        if url not in existing:
            existing.append(url)
            added += 1
    _save_paste_sources(existing)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/seeds/paste", methods=["DELETE"])
@require_login
def api_paste_sources_delete():
    body = request.get_json() or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    sources = [s for s in _load_paste_sources() if s != url]
    _save_paste_sources(sources)
    return jsonify({"ok": True})


# ── Keyword bulk import/export ─────────────────────────────────────────────────


@dashboard_bp.route("/api/keywords/bulk", methods=["POST"])
@require_login
def api_keywords_bulk_add():
    """Add multiple keywords in a single atomic write."""
    import yaml
    body = request.get_json() or {}
    items = body.get("keywords", [])  # [{keyword, category}, ...]
    if not items:
        return jsonify({"error": "keywords array required"}), 400
    _ensure_data_dir()
    cats = _load_keywords()
    added = 0
    for item in items:
        kw = (item.get("keyword") or "").strip()
        cat = (item.get("category") or "custom").strip()
        if not kw:
            continue
        cats.setdefault(cat, [])
        if kw not in cats[cat]:
            cats[cat].append(kw)
            added += 1
    KEYWORDS_FILE.write_text(
        yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
    )
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/keywords/export", methods=["GET"])
@require_login
def api_keywords_export():
    import csv, io
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
@require_login
def api_keywords_import():
    import csv, io, yaml
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    content = f.read().decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    _ensure_data_dir()
    cats = _load_keywords()
    added = 0
    for i, row in enumerate(reader, 1):
        kw = (row.get("keyword") or row.get("Keyword") or "").strip()
        cat = (row.get("category") or row.get("Category") or "custom").strip()
        if not kw:
            continue
        cats.setdefault(cat, [])
        if kw not in cats[cat]:
            cats[cat].append(kw)
            added += 1
    KEYWORDS_FILE.write_text(
        yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
    )
    return jsonify({"ok": True, "added": added})


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

_active_scan_thread = None  # track running scan thread


@dashboard_bp.route("/api/crawl/start", methods=["POST"])
@require_login
def api_crawl_start():
    # Clear any stale stop flag before starting
    STOP_FLAG.unlink(missing_ok=True)
    import asyncio
    import threading
    from pathlib import Path as _Path
    from ..main import run_scan
    from ..crawler import CrawlConfig
    from ..scanner import KeywordConfig
    from ..alerting import Alerter

    global _active_scan_thread

    _ensure_data_dir()

    # Prevent double-start
    if _active_scan_thread and _active_scan_thread.is_alive():
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

    # Clear any stale stop flag
    if STOP_FLAG.exists():
        STOP_FLAG.unlink()

    storage = get_storage()

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
                    check_tor=True,
                    stop_flag=STOP_FLAG,
                )
            )
        except Exception as e:
            print(f"Scan thread error: {e}", flush=True)
        finally:
            loop.close()
            if STOP_FLAG.exists():
                STOP_FLAG.unlink()

    _active_scan_thread = threading.Thread(target=run, daemon=True, name="crawl_thread")
    _active_scan_thread.start()

    return jsonify({"ok": True, "message": "Crawl started."})


@dashboard_bp.route("/api/crawl/stop", methods=["POST"])
@require_login
def api_crawl_stop():
    try:
        _ensure_data_dir()
        STOP_FLAG.write_text(datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        return jsonify({"ok": True, "message": "Stop signal sent — crawl will halt after current page."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route("/api/crawl/status", methods=["GET"])
@require_login
def api_crawl_status():
    try:
        storage = get_storage()
        # If DB shows running but no thread is alive, mark it completed
        active = storage.get_active_session()
        if active and active.get("status") == "running":
            thread_alive = any(t.name == "crawl_thread" and t.is_alive()
                               for t in __import__("threading").enumerate())
            if not thread_alive:
                from sqlalchemy import text as _text
                from datetime import datetime as _dt
                with storage.get_session() as sess:
                    sess.execute(
                        _text(
                            "UPDATE crawl_sessions"
                            " SET status='completed', ended_at=:now"
                            " WHERE status='running'"
                        ),
                        {"now": _dt.now(timezone.utc).replace(tzinfo=None)},
                    )
                    sess.commit()
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
            "stats": stats,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── User management API (admin only) ──────────────────────────────────────────


def require_admin(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "unauthorized"}), 401
        storage = get_storage()
        user = storage.get_user_by_id(session["user_id"])
        if not user or not user.is_admin:
            return jsonify({"error": "admin required"}), 403
        return f(*args, **kwargs)

    return decorated


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
                "oauth_provider": u.oauth_provider,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            }
            for u in users
        ]
    )


@dashboard_bp.route("/api/users", methods=["POST"])
@require_admin
def api_users_create():
    body = request.get_json()
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip() or None
    password = body.get("password") or ""
    is_admin = bool(body.get("is_admin", False))

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    err = validate_password_strength(password)
    if err:
        return jsonify({"error": err}), 400

    storage = get_storage()
    if storage.get_user_by_username(username):
        return jsonify({"error": "username already taken"}), 409

    user_id = storage.create_user(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_admin=is_admin,
        must_change_password=True,  # force password change + MFA on first login
    )
    return jsonify({"ok": True, "id": user_id})


@dashboard_bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_admin
def api_users_delete(user_id):
    if user_id == session["user_id"]:
        return jsonify({"error": "cannot delete yourself"}), 400
    storage = get_storage()
    storage.delete_user(user_id)
    return jsonify({"ok": True})


# ── User settings API (own account) ───────────────────────────────────────────


@dashboard_bp.route("/api/settings/password", methods=["POST"])
@require_login
def api_change_password():
    from ..auth import check_password

    body = request.get_json()
    current = body.get("current_password", "")
    new_pw = body.get("new_password", "")
    confirm = body.get("confirm_password", "")

    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])

    if user.password_hash and not check_password(current, user.password_hash):
        return jsonify({"error": "Current password is incorrect"}), 400
    if new_pw != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    err = validate_password_strength(new_pw)
    if err:
        return jsonify({"error": err}), 400

    storage.update_user_password(session["user_id"], hash_password(new_pw))
    return jsonify({"ok": True})


@dashboard_bp.route("/api/settings/totp/disable", methods=["POST"])
@require_login
def api_disable_totp():
    from ..auth import check_password, verify_totp

    body = request.get_json()
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])

    code = body.get("totp_code", "").strip()
    password = body.get("password", "")

    if user.totp_secret and code and verify_totp(user.totp_secret, code):
        storage.disable_totp(session["user_id"])
        return jsonify({"ok": True})
    if user.password_hash and password and check_password(password, user.password_hash):
        storage.disable_totp(session["user_id"])
        return jsonify({"ok": True})
    return jsonify({"error": "Invalid code or password"}), 400


@dashboard_bp.route("/api/settings/profile", methods=["GET"])
@require_login
def api_profile():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    return jsonify(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "totp_enabled": user.totp_enabled,
            "oauth_provider": user.oauth_provider,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }
    )



# ── Telegram Channels API ──────────────────────────────────────────────────────

TELEGRAM_CHANNELS_FILE = DATA_DIR / "telegram_channels.txt"


def _load_channels() -> list[str]:
    if not TELEGRAM_CHANNELS_FILE.exists():
        # Fall back to env var
        raw = os.getenv("TELEGRAM_CHANNELS", "")
        return [c.strip().lstrip("@") for c in raw.split(",") if c.strip()]
    return [
        line.strip().lstrip("@")
        for line in TELEGRAM_CHANNELS_FILE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@dashboard_bp.route("/api/telegram/channels", methods=["GET"])
@require_login
def api_telegram_channels_get():
    try:
        return jsonify({"channels": _load_channels()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/telegram/channels", methods=["POST"])
@require_login
def api_telegram_channels_add():
    try:
        body = request.get_json()
        channel = (body.get("channel") or "").strip().lstrip("@")
        if not channel:
            return jsonify({"error": "channel required"}), 400
        _ensure_data_dir()
        existing = _load_channels()
        if channel not in existing:
            existing.append(channel)
            TELEGRAM_CHANNELS_FILE.write_text("\n".join(existing) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/telegram/channels", methods=["DELETE"])
@require_login
def api_telegram_channels_delete():
    try:
        body = request.get_json()
        channel = (body.get("channel") or "").strip().lstrip("@")
        if not channel:
            return jsonify({"error": "channel required"}), 400
        _ensure_data_dir()
        channels = [c for c in _load_channels() if c != channel]
        TELEGRAM_CHANNELS_FILE.write_text("\n".join(channels) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
        from io import BytesIO
        from datetime import datetime as dt
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
                [k["keyword"], str(k["count"])] for k in stats["top_keywords"]
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
            sess_data.append([started, s.get("status") or "—", str(s.get("pages_crawled") or 0), str(s.get("hits_found") or 0)])
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
                    Paragraph(h.keyword or "", s_small),
                    Paragraph(h.category or "", s_small),
                    Paragraph(h.url or "", s_mono),
                    Paragraph(ctx, s_small),
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

    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# ── Investigations API ─────────────────────────────────────────────────────────


@dashboard_bp.route("/api/investigations", methods=["GET"])
@require_login
def api_investigations_list():
    storage = get_storage()
    return jsonify(storage.get_investigations(limit=50))


@dashboard_bp.route("/api/investigations", methods=["POST"])
@require_login
def api_investigations_create():
    import asyncio
    from ..investigations import run_investigation

    body = request.get_json()
    name = (body.get("name") or "").strip()
    targets = body.get("targets") or []

    if not name:
        return jsonify({"error": "Investigation name required"}), 400
    if not targets:
        return jsonify({"error": "At least one target required"}), 400

    # Validate targets
    valid = []
    for t in targets:
        val = (t.get("value") or "").strip()
        ttype = (t.get("type") or "keyword").strip()
        if val and ttype in ("email", "name", "keyword"):
            valid.append({"value": val, "type": ttype})

    if not valid:
        return jsonify({"error": "No valid targets provided"}), 400

    storage = get_storage()
    api_key = os.getenv("HIBP_API_KEY", "")

    try:
        inv_id = asyncio.run(run_investigation(
            name=name,
            targets=valid,
            storage=storage,
            api_key=api_key,
        ))
        return jsonify({"ok": True, "id": inv_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
@require_login
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
def api_ip_investigations_create():
    import re
    from ..ip_lookup import investigate_ip

    body = request.get_json()
    ip = (body.get("ip") or "").strip()

    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
    if not ip or (not ipv4.match(ip) and not ipv6.match(ip)):
        return jsonify({"error": "Invalid IP address"}), 400

    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    if not abuse_key and not vt_key:
        return jsonify({"error": "No API keys configured. Add ABUSEIPDB_API_KEY and/or VIRUSTOTAL_API_KEY to .env"}), 400

    storage = get_storage()
    try:
        result = investigate_ip(ip, abuse_key, vt_key)
        inv_id = storage.save_ip_investigation(
            ip=ip,
            abuseipdb_data=result.get("abuseipdb") or {},
            virustotal_data=result.get("virustotal") or {},
        )
        return jsonify({"ok": True, "id": inv_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/ip-investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_ip_investigations_get(inv_id):
    storage = get_storage()
    data = storage.get_ip_investigation(inv_id)
    if not data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(data)


@dashboard_bp.route("/api/ip-investigations/<int:inv_id>", methods=["DELETE"])
@require_login
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
    enriched = []
    for group in all_groups:
        hit_count = 0
        recent_hits = []
        keywords = group.get("keywords", [])
        for kw in keywords:
            hits = storage.get_hits_by_keyword(kw, limit=5)
            hit_count += len(hits)
            for h in hits:
                recent_hits.append({
                    "keyword": h.keyword,
                    "url": h.url,
                    "found_at": h.found_at.isoformat() if h.found_at else None,
                    "context": (h.context or "")[:200],
                })
        last_seen = storage.get_last_hit_date(keywords)
        is_custom = group.get("slug") not in static_slugs
        enriched.append({
            **group,
            "hit_count": hit_count,
            "recent_hits": recent_hits[:10],
            "last_seen": last_seen,
            "is_custom": is_custom,
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
    _ensure_data_dir()
    existing = _load_seeds()
    added = 0
    for url in RANSOMWARE_ONION_SEEDS:
        if url not in existing:
            existing.append(url)
            added += 1
    SEEDS_FILE.write_text("\n".join(existing) + "\n")
    return jsonify({"ok": True, "added": added, "total": len(RANSOMWARE_ONION_SEEDS)})


@dashboard_bp.route("/api/ransomware/add-keywords", methods=["POST"])
@require_admin
def api_ransomware_add_keywords():
    """Add all ransomware group names as keywords."""
    import yaml
    from ..ransomware_data import RANSOMWARE_GROUPS
    _ensure_data_dir()
    cats = _load_keywords()
    cats.setdefault("ransomware", [])
    added = 0
    for group in RANSOMWARE_GROUPS:
        for kw in group.get("keywords", []):
            if kw not in cats["ransomware"]:
                cats["ransomware"].append(kw)
                added += 1
    KEYWORDS_FILE.write_text(
        yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
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
    enriched = []
    for actor in all_actors:
        hit_count = 0
        recent_hits = []
        keywords = actor.get("keywords", [])
        for kw in keywords:
            hits = storage.get_hits_by_keyword(kw, limit=5)
            hit_count += len(hits)
            for h in hits:
                recent_hits.append({
                    "keyword": h.keyword,
                    "url": h.url,
                    "found_at": h.found_at.isoformat() if h.found_at else None,
                    "context": (h.context or "")[:200],
                })
        last_seen = storage.get_last_hit_date(keywords)
        is_custom = actor.get("slug") not in static_slugs
        enriched.append({
            **actor,
            "hit_count": hit_count,
            "recent_hits": recent_hits[:10],
            "last_seen": last_seen,
            "is_custom": is_custom,
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
    import yaml
    from ..threat_actors import THREAT_ACTORS
    _ensure_data_dir()
    cats = _load_keywords()
    cats.setdefault("threat-actors", [])
    added = 0
    for actor in THREAT_ACTORS:
        for kw in actor.get("keywords", []):
            if kw not in cats["threat-actors"]:
                cats["threat-actors"].append(kw)
                added += 1
    KEYWORDS_FILE.write_text(
        yaml.dump({"keywords": cats}, default_flow_style=False, allow_unicode=True)
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
    body = request.get_json()
    email = (body.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "valid email required"}), 400
    added = add_subscriber(email)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/digest/subscribers", methods=["DELETE"])
@require_admin
def api_digest_subscribers_remove():
    from ..digest import remove_subscriber
    body = request.get_json()
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    remove_subscriber(email)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/digest/send", methods=["POST"])
@require_admin
def api_digest_send():
    from ..digest import send_digest
    body = request.get_json() or {}
    # Optional: send to specific emails instead of subscriber list
    recipients = body.get("recipients") or None
    storage = get_storage()
    result = send_digest(storage, recipients=recipients)
    if result["ok"]:
        return jsonify(result)
    return jsonify(result), 500


@dashboard_bp.route("/api/digest/preview", methods=["GET"])
@require_login
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
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@dashboard_bp.route("/api/digest/feeds", methods=["GET"])
@require_login
def api_digest_feeds():
    """Preview feed data without building PDF."""
    from ..feeds import fetch_all_feeds
    try:
        data = fetch_all_feeds()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/digest/subscribe", methods=["POST"])
def api_public_subscribe():
    """Public endpoint — no auth required. For static website subscribe form."""
    from ..digest import add_subscriber
    body = request.get_json() or {}
    email = (body.get("email") or "").strip().lower()
    name = (body.get("name") or "").strip()[:100]
    org = (body.get("org") or "").strip()[:200]
    # Honeypot
    if body.get("website"):
        return jsonify({"ok": True})  # silently drop bots
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Valid email required"}), 400
    added = add_subscriber(email, name=name, org=org)
    return jsonify({"ok": True, "new": added})


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
    import threading
    from ..dns_crawler import run_dns_recon

    body = request.get_json() or {}
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    # Basic sanity check
    if len(domain) > 253 or " " in domain:
        return jsonify({"error": "invalid domain"}), 400

    storage = get_storage()
    inv_id = storage.create_dns_investigation(domain)

    def run():
        try:
            result = run_dns_recon(domain)
            storage.complete_dns_investigation(inv_id, result)
        except Exception as e:
            import traceback
            storage.fail_dns_investigation(inv_id, str(e))
            print(f"DNS investigation {inv_id} failed: {traceback.format_exc()}", flush=True)

    t = threading.Thread(target=run, daemon=True)
    t.start()

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
@require_login
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
    import re as _re

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        return jsonify({"error": "not found"}), 404

    api_key = os.getenv("DNSDUMPSTER_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "DNSDUMPSTER_API_KEY not configured"}), 500

    domain = inv["domain"]

    # ── Call DNSDumpster API ──────────────────────────────────────────────────
    status, body = _fetch_url(
        f"https://api.dnsdumpster.com/domain/{domain}",
        headers={
            "X-API-Key": api_key,
            "Accept": "application/json",
            "User-Agent": "OSINTPH-DNSCrawler/1.0",
        },
        timeout=20,
    )

    if status != 200:
        return jsonify({"error": f"DNSDumpster API returned {status}", "body": body[:200].decode("utf-8", errors="replace")}), 502

    try:
        dd_data = _json.loads(body)
    except Exception as e:
        return jsonify({"error": f"Failed to parse DNSDumpster response: {e}"}), 502

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
    import requests as _requests

    domain = domain.strip().lower().split("/")[0]

    # Query crt.sh — use the deduplicated JSON endpoint
    try:
        resp = _requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers={"User-Agent": "OSINTPH-DNSCrawler/1.0", "Accept": "application/json"},
            timeout=30,
            verify=False,
        )
    except _requests.exceptions.Timeout:
        return jsonify({"error": "crt.sh timed out — try again in a moment"}), 502
    except Exception as e:
        return jsonify({"error": f"crt.sh connection failed: {str(e)}"}), 502

    if resp.status_code != 200:
        return jsonify({"error": f"crt.sh returned HTTP {resp.status_code}"}), 502

    try:
        raw = resp.json()
    except Exception:
        preview = resp.text[:120]
        return jsonify({"error": f"crt.sh returned non-JSON: {preview}"}), 502

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
    from io import BytesIO
    from datetime import datetime as dt
    from collections import Counter

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.style.use('dark_background')
    import matplotlib.patches as mpatches
    import math

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable, Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
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
        return Paragraph(f'<font color="{fg}"><b>{text}</b></font>',
                         S(f"bd_{text[:4]}", fontSize=7, backColor=colors.HexColor(bg),
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
            from playwright.sync_api import sync_playwright as _swp
            import tempfile as _tmp, os as _os
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
            Paragraph(f'<font color="#f85149"><b>⬡</b></font>', S("logo", fontSize=28, leading=32, textColor=C_RED)),
            Table([
                [Paragraph("Infrastructure Recon Report", s_h1)],
                [Paragraph(f'<font color="#f85149">OSINT PH  ·  osintph.info</font>',
                            S("tl", fontSize=9, fontName="Helvetica-Bold", textColor=C_RED, leading=13))],
                [Paragraph(f'Target: <font color="#58a6ff"><b>{domain}</b></font>  ·  '
                           f'Investigated: {created}  ·  Generated: {dt.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M UTC")}',
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
            [Paragraph(f'<b>{val}</b>', S(f"sv_{lbl}", fontSize=14, fontName="Helvetica-Bold", textColor=vc, leading=17))],
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
                      f"Nameserver(s) {', '.join(ns_vuln)} are leaking full DNS zone data. "
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
            story.append(Paragraph(f"⚠ {issue}", s_warn))
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
                Paragraph(org[:45], s_body),
                Paragraph(info.get("asn",""), s_small),
                Paragraph(info.get("country",""), s_small),
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
    except Exception as e:
        story.append(Paragraph(f"Graph generation failed: {e}", s_warn))

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
                Paragraph(val, s_mono),
                Paragraph(ptr_s, s_small),
                Paragraph(geo_s, s_small),
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
         Paragraph(email_sec.get("spf") or "—", s_mono)],
        [Paragraph("DMARC", s_body),
         Paragraph("✓ Valid" if dmarc_v else "✗ Missing", S("dv2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREEN if dmarc_v else C_RED, leading=12)),
         Paragraph(email_sec.get("dmarc") or "—", s_mono)],
        [Paragraph("DKIM", s_body),
         Paragraph(f"✓ {len(dkim_sel)} selector(s)" if dkim_sel else "✗ Not detected",
                   S("kv2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREEN if dkim_sel else C_MUTED, leading=12)),
         Paragraph(", ".join(dkim_sel) or "No selectors found", s_small)],
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
            Paragraph(sub["subdomain"], s_mono),
            Paragraph(ips, s_mono),
            Paragraph(geo, s_small),
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
            import requests as _req
            _cr = _req.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "OSINTPH-PDFGen/1.0", "Accept": "application/json"},
                timeout=20, verify=False,
            )
            if _cr.status_code == 200:
                from datetime import datetime as _dt
                _now = _dt.now(timezone.utc).replace(tzinfo=None)
                _raw = _cr.json()
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
                    [Paragraph(f'<b>{val}</b>', S(f"csv_{lbl[:4]}", fontSize=13,
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
                    Paragraph(san_preview, s_mono),
                    Paragraph(issuer_s, s_small),
                    Paragraph((c.get("not_after") or "")[:10], s_small),
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
                    Paragraph(c.get("subdomain",""), s_mono),
                    Paragraph(issuer, s_small),
                    Paragraph((c.get("not_after") or "")[:10], s_small),
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
                f'<font color="#58a6ff"><b>{ip}</b></font> — '
                f'<font color="#3fb950"><b>{len(open_p)} open</b></font>'
                + (f', <font color="#d29922">{len(filt_p)} filtered</font>' if filt_p else ""),
                S(f"ip_{ip}", fontSize=8, textColor=C_TEXT, leading=12, spaceBefore=6, spaceAfter=3)
            ))
            if open_p:
                port_rows = [[
                    Paragraph(str(p["port"]), S("pn", fontSize=7, fontName="Helvetica-Bold", textColor=C_GREEN, leading=10)),
                    Paragraph(p["service"], s_body),
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
                    f'<font color="#58a6ff"><b>{target}</b></font> — {len(interesting)} paths',
                    S(f"dt_{target[:8]}", fontSize=8, textColor=C_TEXT, leading=12, spaceBefore=6, spaceAfter=3)
                ))
                dir_rows = []
                for p in interesting:
                    sc = p["status_code"]
                    sc_col = "#3fb950" if sc==200 else "#58a6ff" if 300<=sc<400 else "#d29922" if sc in (401,403) else "#f85149"
                    dir_rows.append([
                        Paragraph(f'<font color="{sc_col}"><b>{sc}</b></font>',
                                  S(f"dsc{sc}", fontSize=8, fontName="Helvetica-Bold", leading=12)),
                        Paragraph(p.get("path",""), s_mono),
                        Paragraph(p.get("content_length","") or "—", s_small),
                        Paragraph(p.get("redirect_to","") or "—", s_small),
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
            story.append(Paragraph(f"Nameserver: {ns} — {info.get('record_count',0)} records exposed", s_warn))
            zt_rows = [
                [Paragraph(rec["name"], s_mono), Paragraph(rec["type"], s_body), Paragraph(rec["value"], s_mono)]
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
        f"Target: {domain}  ·  Report ID: OSINTPH-DNS-{inv_id}-{dt.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}",
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
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin and project["owner_id"] != session["user_id"]:
        return None, (jsonify({"error": "Access denied"}), 403)
    return project, None


@dashboard_bp.route("/api/projects", methods=["GET"])
@require_login
def api_projects_list():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if user.is_admin:
        projects = storage.list_projects()
    else:
        projects = storage.list_projects(owner_id=session["user_id"])
    # attach owner username
    for p in projects:
        owner = storage.get_user_by_id(p["owner_id"])
        p["owner_username"] = owner.username if owner else "unknown"
    return jsonify(projects)


@dashboard_bp.route("/api/projects", methods=["POST"])
@require_login
def api_projects_create():
    body = request.get_json() or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Project name required"}), 400
    storage = get_storage()
    project_id = storage.create_project(
        name=name,
        owner_id=session["user_id"],
        description=(body.get("description") or "").strip() or None,
        color=body.get("color") or "#f85149",
        tags=body.get("tags") or [],
        alert_threshold=int(body.get("alert_threshold") or 1),
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
    body = request.get_json() or {}
    allowed = ["name", "description", "status", "color", "tags", "alert_threshold"]
    updates = {k: v for k, v in body.items() if k in allowed}
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
    body = request.get_json() or {}
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
    body = request.get_json() or {}
    keyword = (body.get("keyword") or "").strip()
    if not keyword:
        return jsonify({"error": "keyword required"}), 400
    kid = get_storage().add_project_keyword(
        project_id, keyword,
        category=body.get("category") or "custom",
        is_regex=bool(body.get("is_regex", False)),
    )
    return jsonify({"ok": True, "id": kid})


@dashboard_bp.route("/api/projects/<int:project_id>/keywords/<int:keyword_id>", methods=["DELETE"])
@require_login
def api_project_keywords_delete(project_id, keyword_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    get_storage().delete_project_keyword(keyword_id)
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
    body = request.get_json() or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    did = get_storage().add_project_domain(
        project_id, domain,
        priority=int(body.get("priority") or 3),
        notes=body.get("notes"),
    )
    return jsonify({"ok": True, "id": did})


@dashboard_bp.route("/api/projects/<int:project_id>/domains/<int:domain_id>", methods=["DELETE"])
@require_login
def api_project_domains_delete(project_id, domain_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    get_storage().delete_project_domain(domain_id)
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
    body = request.get_json() or {}
    entity_type = (body.get("entity_type") or "").strip()
    value = (body.get("value") or "").strip()
    valid_types = ("person", "organization", "brand", "ip", "email", "bitcoin_address")
    if entity_type not in valid_types:
        return jsonify({"error": f"entity_type must be one of {valid_types}"}), 400
    if not value:
        return jsonify({"error": "value required"}), 400
    eid = get_storage().add_project_entity(project_id, entity_type, value, body.get("notes"))
    return jsonify({"ok": True, "id": eid})


@dashboard_bp.route("/api/projects/<int:project_id>/entities/<int:entity_id>", methods=["DELETE"])
@require_login
def api_project_entities_delete(project_id, entity_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    get_storage().delete_project_entity(entity_id)
    return jsonify({"ok": True})


# Hits & Stats
@dashboard_bp.route("/api/projects/<int:project_id>/hits", methods=["GET"])
@require_login
def api_project_hits(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    limit = int(request.args.get("limit", 100))
    return jsonify(get_storage().get_project_hits(project_id, limit=limit))


@dashboard_bp.route("/api/projects/<int:project_id>/stats", methods=["GET"])
@require_login
def api_project_stats(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_stats(project_id))




# ── Paste Monitor API ──────────────────────────────────────────────────────────

@dashboard_bp.route("/api/paste/hits", methods=["GET"])
@require_login
def api_paste_hits():
    limit = int(request.args.get("limit", 100))
    source = request.args.get("source")
    pattern = request.args.get("pattern")
    return jsonify(get_storage().get_recent_paste_hits(limit=limit, source=source, pattern=pattern))


@dashboard_bp.route("/api/paste/stats", methods=["GET"])
@require_login
def api_paste_stats():
    return jsonify(get_storage().get_paste_stats())


@dashboard_bp.route("/api/paste/scan", methods=["POST"])
@require_login
def api_paste_scan():
    """Trigger a one-shot paste scan (admin only)."""
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        from darkweb_scanner.paste_monitor import run_paste_monitor
        result = run_paste_monitor(storage, single_run=True)
        return jsonify({"ok": True, **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── OSINT Toolkit Proxy Routes ────────────────────────────────────────────────
# Server-side proxy so browser CORS restrictions don't block external APIs

def _fetch_url(url, headers=None, timeout=10):
    """Simple HTTP GET helper, returns (status, body_bytes)."""
    req = urllib.request.Request(url, headers=headers or {
        "User-Agent": "Mozilla/5.0 (compatible; OsintBot/1.0)",
        "Accept": "application/json, text/html, */*",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@dashboard_bp.route("/api/osint/github/<username>")
@require_login
def osint_github(username):
    """Proxy GitHub public API."""
    import json as _json
    status, body = _fetch_url(f"https://api.github.com/users/{username}", headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "OsintTool/1.0",
    })
    # Also fetch events for email extraction
    _, ev_body = _fetch_url(f"https://api.github.com/users/{username}/events/public?per_page=10", headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "OsintTool/1.0",
    })
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/osint/reddit/<username>")
@require_login
def osint_reddit(username):
    import json as _json
    status, body = _fetch_url(f"https://www.reddit.com/user/{username}/about.json", headers={
        "User-Agent": "OsintTool/1.0 (research)",
        "Accept": "application/json",
    })
    try:
        return jsonify(_json.loads(body)), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/osint/discord/<user_id>")
@require_login
def osint_discord(user_id):
    import json as _json
    status, body = _fetch_url(f"https://discordlookup.mesalytic.moe/v1/user/{user_id}")
    try:
        return jsonify(_json.loads(body)), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/osint/domain/<path:domain>")
@require_login
def osint_domain(domain):
    import json as _json
    domain = domain.strip().lower().split("/")[0]
    results = {}
    # RDAP
    rdap_status, rdap_body = _fetch_url(f"https://rdap.org/domain/{domain}")
    try:
        results["rdap"] = _json.loads(rdap_body)
        results["rdap_status"] = rdap_status
    except Exception:
        results["rdap"] = None
        results["rdap_status"] = rdap_status
    # crt.sh
    crt_status, crt_body = _fetch_url(f"https://crt.sh/?q={domain}&output=json", headers={
        "User-Agent": "OsintTool/1.0",
        "Accept": "application/json",
    })
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
    # TikTok timestamp trick: user ID is encoded in the video ID
    status, body = _fetch_url(
        f"https://www.tiktok.com/api/user/detail/?uniqueId={username}&aid=1988",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://www.tiktok.com/",
            "Accept": "application/json",
        }
    )
    try:
        data = _json.loads(body)
        return jsonify(data), status
    except Exception as e:
        return jsonify({"error": str(e), "raw": body[:200].decode("utf-8", errors="replace")}), 500


@dashboard_bp.route("/api/osint/username/<username>")
@require_login
def osint_username_check(username):
    """Check a username against WhatsMyName dataset."""
    import json as _json
    import concurrent.futures
    _, wmn_body = _fetch_url(
        "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
    )
    try:
        wmn = _json.loads(wmn_body)
    except Exception as e:
        return jsonify({"error": f"Could not fetch WMN data: {e}"}), 500

    sites = [s for s in wmn.get("sites", []) if s.get("uri_check") and s.get("e_code") == 200][:200]
    found = []

    def check(site):
        url = site["uri_check"].replace("{account}", username)
        try:
            st, body_b = _fetch_url(url, timeout=6)
            text = body_b.decode("utf-8", errors="replace")
            e_string = site.get("e_string", "")
            m_string = site.get("m_string", "")
            if st == site["e_code"] and (not e_string or e_string in text) and (not m_string or m_string not in text):
                return {"name": site["name"], "url": url, "pretty": site.get("uri_pretty", "").replace("{account}", username)}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        for result in pool.map(check, sites):
            if result:
                found.append(result)

    return jsonify({"found": found, "checked": len(sites)})


# ── ThreatFox proxy (avoids browser CORS) ─────────────────────────────────────

@dashboard_bp.route("/api/proxy/threatfox", methods=["POST"])
@require_login
def proxy_threatfox():
    """Proxy ThreatFox API — avoids CORS from browser."""
    import json as _json
    try:
        body = request.get_data()
        api_key = os.getenv("THREATFOX_API_KEY", "")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "OSINTPH/1.0",
        }
        if api_key:
            headers["Auth-Key"] = api_key
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=body,
            headers=headers,
            method="POST",
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return Response(resp.read(), mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/proxy/urlhaus", methods=["POST"])
@require_login
def proxy_urlhaus():
    """Proxy URLhaus recent URLs."""
    import json as _json
    try:
        body = b"limit=200"
        req = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "OSINTPH/1.0"},
            method="POST",
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return Response(resp.read(), mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/proxy/feodo")
@require_login
def proxy_feodo():
    """Proxy Feodo Tracker C2 blocklist."""
    status, body = _fetch_url("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    return Response(body, mimetype="application/json")


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

    page     = request.args.get("page", "1")
    limit    = request.args.get("limit", "50")
    severity = request.args.get("severity", "")

    params = f"?page={page}&limit={limit}"
    if severity:
        params += f"&severity={severity}"

    status, body = _fetch_url(
        f"https://whiteintel.io/api/v1/alerts{params}",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": "OSINTPH/1.0",
        },
    )
    try:
        data = _json.loads(body)
        return jsonify({"ok": True, "data": data})
    except Exception:
        return jsonify({"ok": False, "error": f"HTTP {status}", "raw": body[:200].decode("utf-8", errors="replace")}), 200


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

    status, body = _fetch_url(
        f"https://whiteintel.io/api/v1/search?domain={domain}",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": "OSINTPH/1.0",
        },
    )
    try:
        data = _json.loads(body)
        return jsonify({"ok": True, "data": data})
    except Exception:
        return jsonify({"ok": False, "error": f"HTTP {status}"}), 200


# ── Health ─────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()})
