"""
ransomware_live_routes.py
Place at: src/darkweb_scanner/dashboard/ransomware_live_routes.py
"""

import logging

from flask import Blueprint, Response, jsonify, request

from ..auth import require_login

logger = logging.getLogger(__name__)
rw_live_bp = Blueprint("rw_live", __name__)


def _rw():
    from .. import ransomware_live as rw
    return rw


def _ok(data):
    return jsonify({"ok": True, "data": data})


def _err(msg, status=400):
    return jsonify({"ok": False, "error": msg}), status


# ── Status / Stats ─────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/status")
@require_login
def rwlive_status():
    rw = _rw()
    validation = rw.validate_key()
    stats = rw.get_stats()
    return _ok({
        "key_valid":   validation.get("valid", False),
        "key_message": validation.get("message", ""),
        "has_pro_key": rw.has_pro_key(),
        "stats":       stats,
    })


@rw_live_bp.route("/api/rwlive/stats")
@require_login
def rwlive_stats():
    return _ok(_rw().get_stats())


# ── Groups ─────────────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/groups")
@require_login
def rwlive_groups():
    """
    All ransomware groups merged with local RANSOMWARE_GROUPS definitions.
    ?sea=1  — SEA-targeting only
    ?active=1 — active only
    """
    rw = _rw()
    from ..ransomware_data import RANSOMWARE_GROUPS as LOCAL

    live_groups = rw.get_all_groups()

    local_idx = {
        lg["slug"].lower().replace("-", ""): lg for lg in LOCAL
    }
    for g in live_groups:
        slug_key = (g.get("slug") or g.get("name", "")).lower().replace(" ", "").replace("-", "")
        local = local_idx.get(slug_key)
        if local:
            g["_sea_targeting"]  = local.get("targeting_sea", False)
            g["_sea_victims"]    = local.get("sea_victims", [])
            g["_local_ttps"]     = local.get("ttps", [])
            g["_local_desc"]     = local.get("description", "")
            g["_local_origin"]   = local.get("origin", "")
            g["_local_keywords"] = local.get("keywords", [])

    live_names = {g.get("name", "").lower() for g in live_groups}
    for lg in LOCAL:
        if lg["name"].lower() not in live_names:
            lg["_local_only"] = True
            live_groups.append(lg)

    if request.args.get("sea"):
        live_groups = [g for g in live_groups if g.get("_sea_targeting") or g.get("targeting_sea")]
    if request.args.get("active"):
        live_groups = [g for g in live_groups if g.get("status", "").lower() == "active"]

    return _ok(live_groups)


@rw_live_bp.route("/api/rwlive/groups/<group_name>")
@require_login
def rwlive_group_detail(group_name: str):
    """Full group profile + victims, IOCs, negotiations, ransom notes, YARA."""
    return _ok(_rw().build_group_profile(group_name))


# ── Victims ────────────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/victims/recent")
@require_login
def rwlive_victims_recent():
    """?sea=1  ?limit=N (default 40, max 200)"""
    rw = _rw()
    limit   = min(int(request.args.get("limit", 40)), 200)
    victims = rw.get_recent_victims(limit=limit)
    if request.args.get("sea"):
        victims = [v for v in victims if (v.get("country") or "").upper() in rw.SEA_ISO2]
    return _ok(victims)


@rw_live_bp.route("/api/rwlive/victims/sea")
@require_login
def rwlive_sea_victims():
    """All recent SEA victims deduplicated."""
    limit = min(int(request.args.get("limit", 50)), 200)
    return _ok(_rw().get_sea_victims(limit=limit))


@rw_live_bp.route("/api/rwlive/victims/search")
@require_login
def rwlive_victims_search():
    """?q=keyword"""
    q = request.args.get("q", "").strip()
    if not q:
        return _err("q parameter required")
    limit = min(int(request.args.get("limit", 50)), 200)
    return _ok(_rw().search_victims(q, limit=limit))


@rw_live_bp.route("/api/rwlive/victims")
@require_login
def rwlive_victims():
    """?group ?country ?sector ?year ?month ?query ?limit ?sea"""
    rw    = _rw()
    group   = request.args.get("group")
    country = request.args.get("country")
    sector  = request.args.get("sector")
    year    = request.args.get("year",  type=int)
    month   = request.args.get("month", type=int)
    query   = request.args.get("query")
    limit   = min(int(request.args.get("limit", 50)), 500)
    if request.args.get("sea"):
        return _ok(rw.get_sea_victims(limit=limit))
    return _ok(rw.get_victims(
        group=group, country=country, sector=sector,
        year=year, month=month, query=query, limit=limit,
    ))


@rw_live_bp.route("/api/rwlive/victims/<victim_id>")
@require_login
def rwlive_victim_detail(victim_id: str):
    result = _rw().get_victim_by_id(victim_id)
    if result is None:
        return _err("Victim not found or PRO key required", 404)
    return _ok(result)


# ── IOCs ───────────────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/iocs")
@require_login
def rwlive_ioc_groups():
    return _ok(_rw().get_ioc_groups())


@rw_live_bp.route("/api/rwlive/iocs/<group_name>")
@require_login
def rwlive_group_iocs(group_name: str):
    """?type=ip|domain|url|hash"""
    ioc_type = request.args.get("type")
    return _ok(_rw().get_group_iocs(group_name, ioc_type=ioc_type))


# ── Negotiations ───────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/negotiations")
@require_login
def rwlive_negotiation_groups():
    return _ok(_rw().get_negotiation_groups())


@rw_live_bp.route("/api/rwlive/negotiations/<group_name>")
@require_login
def rwlive_group_negotiations(group_name: str):
    return _ok(_rw().get_group_negotiations(group_name))


@rw_live_bp.route("/api/rwlive/negotiations/<group_name>/<chat_id>")
@require_login
def rwlive_negotiation_chat(group_name: str, chat_id: str):
    result = _rw().get_negotiation_chat(group_name, chat_id)
    if result is None:
        return _err("Chat not found or PRO key required", 404)
    return _ok(result)


# ── Press ──────────────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/press/recent")
@require_login
def rwlive_press_recent():
    """?country=ISO2  ?sea=1"""
    rw      = _rw()
    country = request.args.get("country")
    if request.args.get("sea"):
        return _ok(rw.get_sea_press(limit=30))
    return _ok(rw.get_press_recent(country=country))


@rw_live_bp.route("/api/rwlive/press/all")
@require_login
def rwlive_press_all():
    """?country=ISO2"""
    return _ok(_rw().get_press_all(country=request.args.get("country")))


# ── Ransom Notes ───────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/ransomnotes")
@require_login
def rwlive_ransomnote_groups():
    return _ok(_rw().get_ransomnote_groups())


@rw_live_bp.route("/api/rwlive/ransomnotes/<group_name>")
@require_login
def rwlive_group_ransomnotes(group_name: str):
    return _ok(_rw().get_group_ransomnotes(group_name))


@rw_live_bp.route("/api/rwlive/ransomnotes/<group_name>/<note_name>")
@require_login
def rwlive_ransomnote_content(group_name: str, note_name: str):
    content = _rw().get_ransomnote_content(group_name, note_name)
    if content is None:
        return _err("Note not found or PRO key required", 404)
    return Response(content, mimetype="text/plain")


# ── YARA ───────────────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/yara")
@require_login
def rwlive_yara_groups():
    return _ok(_rw().get_yara_groups())


@rw_live_bp.route("/api/rwlive/yara/<group_name>")
@require_login
def rwlive_group_yara(group_name: str):
    content = _rw().get_group_yara(group_name)
    if content is None:
        return _err("No YARA rules found", 404)
    return Response(content, mimetype="text/plain")


# ── 8-K Filings ────────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/8k")
@require_login
def rwlive_8k():
    return _ok(_rw().get_8k_filings())


# ── CSIRT ──────────────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/csirt/<country_code>")
@require_login
def rwlive_csirt(country_code: str):
    return _ok(_rw().get_csirt(country_code))


@rw_live_bp.route("/api/rwlive/csirt/sea/all")
@require_login
def rwlive_sea_csirts():
    return _ok(_rw().get_sea_csirts())


# ── Sectors ────────────────────────────────────────────────────────────────────

@rw_live_bp.route("/api/rwlive/sectors")
@require_login
def rwlive_sectors():
    return _ok(_rw().list_sectors())


# ── Composite bundles (single-call for frontend tabs) ─────────────────────────

@rw_live_bp.route("/api/rwlive/home-data")
@require_login
def rwlive_home_data():
    """Everything the Home tab needs in one call."""
    return _ok(_rw().get_home_dashboard_data())


@rw_live_bp.route("/api/rwlive/ransomware-tab-data")
@require_login
def rwlive_ransomware_tab_data():
    """Everything the Ransomware tab needs in one call."""
    return _ok(_rw().get_ransomware_tab_data())
