#!/usr/bin/env python3
"""
Headless-browser check of the dashboard pages against hostile data.

Run inside the application image, which has Flask, playwright and Chromium
(but no pytest):

    python tests/browser/xss_check.py

The script does not start the real application and does not sign in. It serves
the two page templates and the static files from a small Flask app, with the
response headers of the real application (``init_security_headers``: the
Content-Security-Policy with ``script-src 'self'``), answers every /api/ call
with fixtures in which every string a third party could influence is a hostile
value, opens every tab and sub-view, and checks that

  * the browser reports no violation of the policy and logs no error: no
    inline script, no inline event handler, nothing loaded from another host;
  * no value from the data ran as script, became an element, an attribute or an
    event handler, or ended up as a javascript: link;
  * the values are on the page as plain text;
  * buttons built from data still send exactly the value they were built from;
  * every write request carries the CSRF token, signing out is a POST form,
    an expired session leads to the sign-in page, and "admin required" is
    reported as "Admin only";
  * an API answer that is not a success is shown with the server's text and
    its error id, and the polls (crawl, Channel Monitor, quick scan) stop
    with a reason;
  * a non-admin does not get the admin-only controls.

The markers are inert: they set ``window.__xss`` or add a ``data-audit-*``
attribute, nothing else.

XSS_CHECK_TEMPLATES=<dir> points the script at another copy of the templates
(static files are then served from ``<dir>/../static`` when that exists). The
policy is the current one either way, so a run against the templates of an
older release shows what the policy would have blocked there.
Exit status: 0 when every check passes, 1 otherwise.
"""

import json
import logging
import os
import re
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, render_template, request
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

REPO = Path(__file__).resolve().parents[2]
# The headers come from this checkout, not from the copy inside the image.
sys.path.insert(0, str(REPO / "src"))
from darkweb_scanner import __version__  # noqa: E402
from darkweb_scanner.dashboard.security_headers import (  # noqa: E402
    CONTENT_SECURITY_POLICY,
    STATIC_CACHE_CONTROL,
    init_security_headers,
)

TEMPLATES = Path(
    os.environ.get("XSS_CHECK_TEMPLATES")
    or REPO / "src" / "darkweb_scanner" / "dashboard" / "templates"
)
STATIC = TEMPLATES.parent / "static"
CSRF = "csrf-fixture-token"

# ── Hostile values ─────────────────────────────────────────────────────────────

MARK = '"><img src=x onerror="window.__xss=(window.__xss||0)+1">'
ATTR_SQ = "x' data-audit-sub='1"
ATTR_DQ = 'x" data-audit-sub="1'
CALL = "x');window.__xss=(window.__xss||0)+1;//"
JS_URL = "javascript:window.__xss=1"
WHEN = "2026-01-01T00:00:00"


def X(tag: str) -> str:
    """A hostile value that can be told apart from the others."""
    return tag + MARK


def _intel(prefix: str, **extra) -> dict:
    entry = {
        "name": X(prefix),
        "slug": X(prefix + "-slug"),
        "risk_level": "critical",
        "status": "active",
        "origin": X(prefix + "-origin"),
        "first_seen": X(prefix + "-first"),
        "last_seen": "2026-01-01",
        "description": X(prefix + "-desc"),
        "ttps": [X(prefix + "-ttp")],
        "hit_count": 1,
        "is_custom": True,
        "targeting_sea": True,
        "sea_victims": [X(prefix + "-victim")],
        "sectors": [X(prefix + "-sector")],
        "countries_targeted": [X(prefix + "-country")],
        "known_malware": [X(prefix + "-mal")],
        "keywords": [X(prefix + "-kw")],
        "recent_hits": [
            {
                "keyword": X(prefix + "-hkw"),
                "found_at": WHEN,
                "url": X(prefix + "-hurl"),
                "context": X(prefix + "-hctx"),
            }
        ],
    }
    entry.update(extra)
    return entry


def _geo(prefix: str) -> dict:
    return {
        "city": X(prefix + "-city"),
        "countryCode": "PH",
        "country": X(prefix + "-country"),
        "org": X(prefix + "-org"),
        "isp": X(prefix + "-isp"),
        "as": X(prefix + "-as"),
    }


def _dns(inv_id: int, domain: str, scanned: bool) -> dict:
    return {
        "id": inv_id,
        "domain": domain,
        "status": "complete",
        "created_at": WHEN,
        "result": {
            "dns_records": {
                "A": ["192.0.2.1"],
                "MX": [X("mx")],
                "NS": [X("ns")],
                "TXT": [X("txt")],
            },
            "zone_transfer": {
                X("zt-ns"): {
                    "success": True,
                    "record_count": 1,
                    "records": [{"name": X("zt-name"), "type": X("zt-type"), "value": X("zt-val")}],
                }
            },
            "email_security": {
                "spf_valid": False,
                "dmarc_valid": False,
                "spf": X("spf"),
                "dmarc": X("dmarc"),
                "dkim_selectors_found": [X("dkim")],
                "issues": [X("issue")],
            },
            "subdomains_resolved": [
                {"subdomain": X("sub"), "ips": [X("sub-ip")], "geo": [_geo("sub")]}
            ],
            "subdomains_passive": [{"subdomain": X("sub")}],
            "subdomains_bruteforce": [{"subdomain": X("brute"), "ips": ["192.0.2.2"], "geo": []}],
            "ip_geo": {"192.0.2.1": _geo("ip")},
            "ptr_records": {"192.0.2.1": X("ptr")},
            "port_scan": {X("ps-ip"): [{"port": 80, "service": X("svc"), "status": "open"}]}
            if scanned
            else {},
            "dir_enum": {
                X("de-target"): [
                    {
                        "status_code": 200,
                        "path": X("de-path"),
                        "content_length": 10,
                        "redirect_to": X("de-redir"),
                    }
                ]
            }
            if scanned
            else {},
            "services": {
                X("sub"): {
                    "server": X("server"),
                    "tech": [X("tech")],
                    "status_code": 200,
                    "title": X("title"),
                }
            },
        },
    }


SESSION = {
    "id": 1,
    "started_at": WHEN,
    "ended_at": "2026-01-01T00:10:00",
    "pages_crawled": 10,
    "hits_found": 2,
    "status": "completed",
}
PROJECT = {
    "id": 1,
    "name": X("proj"),
    "status": "active",
    "description": X("proj-desc"),
    "hit_count": 1,
    "owner_username": X("owner"),
    "tags": [X("tag")],
    "color": 'red" data-audit-attr="1',
    "keywords": [],
    "domains": [],
    "entities": [],
    "created_at": WHEN,
    "alert_threshold": X("thr"),
}
DNS_ROW = {
    "created_at": WHEN,
    "subdomain_count": 2,
    "resolved_count": 1,
    "zone_transfer_success": True,
    "has_spf": False,
    "has_dmarc": False,
    "status": "complete",
}
THREATFOX = {
    "data": [
        {
            "ioc_type": "domain",
            "ioc": X("tf"),
            "malware": X("tf-mal"),
            "confidence_level": 100,
            "tags": [X("tf-tag")],
            "first_seen": "2026-01-01 00:00:00",
            "reporter": X("tf-rep"),
        }
    ]
}
VICTIMS = {
    "ok": True,
    "data": [
        {
            "group": X("v-group"),
            "victim": X("victim"),
            "website": X("v-site"),
            "country": "PH",
            "attackdate": "2026-01-01",
        }
    ],
}
PRESS = {
    "ok": True,
    "data": [{"title": X("press"), "url": JS_URL, "date": "2026-01-01", "source": X("press-src")}],
}

# Answers by path below /api/. A (METHOD, path) key wins over a bare path.
FIXTURES = {
    "stats": {
        "total_sessions": 1,
        "total_pages": 10,
        "total_hits": 2,
        "top_keywords": [{"keyword": X("topkw"), "count": 2}, {"keyword": CALL, "count": 1}],
    },
    "crawl/status": {
        "active": False,
        "session": None,
        "stats": {},
        "last_session": {
            "id": 7,
            "status": "failed",
            "started_at": WHEN,
            "ended_at": WHEN,
            "error": X("crawl-err"),
        },
    },
    "sessions": [SESSION],
    "keywords": {"categories": {X("cat"): [X("kw"), CALL]}},
    ("POST", "keywords/generate"): {"ok": True, "keywords": {X("gen-cat"): [X("gen-kw")]}},
    "seeds": {"seeds": [X("seed"), CALL]},
    "admin/auth-events": [
        {
            "ts": WHEN,
            "event": X("ev"),
            "username": X("ev-user"),
            "user_id": 2,
            "ip": X("ev-ip"),
            "detail": X("ev-detail"),
        },
        {
            "ts": WHEN,
            "event": "login_failed",
            "username": CALL,
            "user_id": None,
            "ip": None,
            "detail": None,
        },
    ],
    "users": [
        {
            "id": 2,
            "username": X("user"),
            "email": X("mail"),
            "is_admin": False,
            "totp_enabled": True,
            "last_login": WHEN,
        },
        {
            "id": 3,
            "username": CALL,
            "email": X("mail2"),
            "is_admin": False,
            "totp_enabled": False,
            "last_login": None,
        },
    ],
    "projects": [PROJECT],
    "settings/profile": {
        "username": X("me"),
        "email": X("me-mail"),
        "is_admin": True,
        "last_login": WHEN,
        "totp_enabled": True,
    },
    "investigations": [
        {"id": 1, "name": X("inv"), "target_count": 1, "status": "completed", "created_at": WHEN}
    ],
    "ip-investigations": [
        {
            "id": 1,
            "ip": X("ip"),
            "country": X("ip-country"),
            "isp": X("ip-isp"),
            "abuse_score": 90,
            "vt_malicious": 6,
            "created_at": WHEN,
        }
    ],
    "ransomware/groups": [_intel("rw")],
    "threat-actors": [_intel("ta", type="nation-state", aliases=[X("ta-alias")])],
    "digest/subscribers": {"subscribers": [X("sub-mail"), ATTR_SQ, ATTR_DQ, CALL]},
    "dns/investigations": [
        dict(DNS_ROW, id=1, domain=X("dns")),
        dict(DNS_ROW, id=2, domain=X("dns2")),
    ],
    "channel-monitor/credentials": {
        "configured": True,
        "limits": {"max_messages": 5000, "max_video_mb": 200, "max_file_mb": 100, "max_job_gb": 2},
    },
    # One job per status the page knows, one with a status it does not know.
    "channel-monitor/jobs": [
        {"id": "job1", "channel": X("cm"), "started_at": WHEN, "status": "completed"},
        {
            "id": CALL,
            "channel": X("cm2"),
            "started_at": WHEN,
            "status": "error",
            "error": X("cm-err"),
        },
        {"id": "job-int", "channel": X("cm3"), "started_at": WHEN, "status": "interrupted"},
        {"id": "job-arch", "channel": X("cm4"), "started_at": None, "status": "archived"},
        {"id": "job-odd", "channel": X("cm5"), "started_at": WHEN, "status": X("cm-status")},
        {"id": "job-run", "channel": X("cm6"), "started_at": WHEN, "status": "running"},
    ],
    "channel-monitor/jobs/job1": {
        "channel": X("cm"),
        "log": [X("cm-log")],
        "total": 1,
        "status": "completed",
    },
    "channel-monitor/jobs/job-int": {
        "channel": X("cm3"),
        "log": [X("cm-int-log")],
        "status": "interrupted",
        "error": X("cm-int-err"),
    },
    # An archive from before this release: no log, no details.
    "channel-monitor/jobs/job-arch": {"channel": X("cm4"), "status": "archived"},
    "channel-monitor/jobs/job-odd": {"channel": X("cm5"), "log": [], "status": X("cm-status")},
    "channel-monitor/jobs/job-run": {
        "channel": X("cm6"),
        "log": [X("cm-run-log")],
        "status": "running",
    },
    "channel-monitor/jobs/job-new/log": {
        "status": "completed",
        "log": [X("cm-new-log")],
        "total": 1,
    },
    ("POST", "channel-monitor/start"): {"ok": True, "job_id": "job-new"},
    ("POST", "crawl/start"): {"ok": True},
    "rwlive/stats": {
        "ok": True,
        "data": {"stats": {"groups": 1, "victims": 1, "press": 1}, "last_update": WHEN},
    },
    "rwlive/status": {"ok": True, "data": {"key_valid": True}},
    "rwlive/victims/recent": VICTIMS,
    "rwlive/victims/sea": VICTIMS,
    "rwlive/groups": {"ok": True, "data": [{"group": X("leak-group"), "victims": 600}]},
    "rwlive/press/recent": PRESS,
    ("POST", "proxy/threatfox"): THREATFOX,
    ("POST", "proxy/urlhaus"): {
        "urls": [
            {
                "url": X("uh"),
                "tags": [X("uh-tag")],
                "date_added": "2026-01-01",
                "host": X("uh-host"),
                "url_status": "online",
            }
        ]
    },
    "proxy/feodo": [
        {
            "ip_address": X("fe"),
            "port": 443,
            "malware": X("fe-mal"),
            "country": X("fe-country"),
            "first_seen": "2026-01-01",
        }
    ],
    "quick-scan/sessions": [
        {
            "id": 1,
            "target_value": X("qs-target"),
            "target_type": X("qs-type"),
            "status": "completed",
            "urls_visited": 1,
            "findings_count": 2,
            "started_at": WHEN,
        }
    ],
    ("POST", "quick-scan/start"): {"session_id": 1},
}

# Answers for paths with an id or a looked-up name in them, first match wins.
PATTERNS = [
    (
        r"sessions/[^/]+/hits",
        [
            {
                "keyword": X("s-kw"),
                "category": X("s-cat"),
                "url": X("s-url"),
                "context": X("s-ctx"),
                "found_at": WHEN,
            }
        ],
    ),
    (
        r"projects/[^/]+/keywords",
        [{"id": 1, "keyword": X("pk"), "category": X("pk-cat"), "is_regex": False}],
    ),
    (
        r"projects/[^/]+/domains",
        [{"id": 1, "domain": X("pd"), "priority": 3, "notes": X("pd-note")}],
    ),
    (
        r"projects/[^/]+/entities",
        [{"id": 1, "entity_type": X("pe-type"), "value": X("pe"), "notes": X("pe-note")}],
    ),
    (
        r"projects/[^/]+/hits",
        [
            {
                "keyword": X("ph-kw"),
                "matched_on": X("ph-on"),
                "matched_value": X("ph-val"),
                "url": JS_URL,
                "context": X("ph-ctx"),
                "found_at": WHEN,
            }
        ],
    ),
    (r"projects/[^/]+", PROJECT),
    (
        r"investigations/.+",
        {
            "targets": [
                {
                    "target_type": "email",
                    "value": X("t-val"),
                    "error": X("t-err"),
                    "breaches": [
                        {
                            "breach_name": X("br"),
                            "breach_date": X("br-date"),
                            "description": X("br-desc"),
                            "data_classes": [X("br-class")],
                        }
                    ],
                    "darkweb_hits": [
                        {"url": X("dw-url"), "context": X("dw-ctx"), "found_at": X("dw-at")}
                    ],
                }
            ]
        },
    ),
    (
        r"ip-investigations/.+",
        {
            "abuseipdb": {
                "ip": X("a-ip"),
                "abuse_confidence_score": 90,
                "country_name": X("a-country"),
                "country_code": "PH",
                "isp": X("a-isp"),
                "domain": X("a-dom"),
                "usage_type": X("a-use"),
                "is_tor": True,
                "total_reports": 3,
                "num_distinct_users": 2,
                "last_reported_at": WHEN,
                "hostnames": [X("a-host")],
                "reports": [
                    {
                        "categories": [X("a-cat")],
                        "reporter_country": X("a-rc"),
                        "comment": X("a-cmt"),
                    }
                ],
            },
            "virustotal": {
                "ip": X("v-ip"),
                "analysis_stats": {"malicious": 6, "suspicious": 1, "harmless": 1, "undetected": 1},
                "total_engines": 9,
                "asn": 1,
                "as_owner": X("v-as"),
                "country": X("v-country"),
                "continent": X("v-cont"),
                "network": X("v-net"),
                "regional_internet_registry": X("v-rir"),
                "reputation": 0,
                "jarm": X("v-jarm"),
                "tags": [X("v-tag")],
                "last_analysis_date": WHEN,
                "malicious_engines": [
                    {"engine": X("v-eng"), "category": "malicious", "result": X("v-res")}
                ],
                "ssl_certificate": {
                    "subject_cn": X("v-cn"),
                    "issuer_org": X("v-iss"),
                    "valid_from": X("v-from"),
                    "valid_to": X("v-to"),
                },
                "resolutions": [{"hostname": X("v-host"), "date": 1767225600}],
                "communicating_files": [
                    {"name": X("v-file"), "type": X("v-type"), "sha256": "ab" * 32, "malicious": 3}
                ],
                "whois": X("v-whois"),
            },
        },
    ),
    (r"dns/investigations/2", _dns(2, X("dns2"), scanned=False)),
    (r"dns/investigations/.+", _dns(1, X("dns"), scanned=True)),
    (
        r"dns/certs/.+",
        {
            "total": 1,
            "expired": 0,
            "expiring_soon": 1,
            "active": 1,
            "unique_sans": 2,
            "all_sans": [X("san"), "*." + X("wild")],
            "issuers": {X("issuer"): 1},
            "certs": [
                {
                    "id": X("cert-id"),
                    "not_before": "2025-01-01T00:00:00",
                    "not_after": "2026-02-01T00:00:00",
                    "is_expired": False,
                    "expiring_soon": True,
                    "days_remaining": X("days"),
                    "issuer_cn": X("cn"),
                    "sans": [X("cert-san")],
                    "san_count": 1,
                }
            ],
        },
    ),
    # The job whose id is the hostile value CALL.
    (
        r"channel-monitor/jobs/.+",
        {
            "channel": X("cm2"),
            "log": [X("cm2-log")],
            "total": 1,
            "status": "error",
            "error": X("cm-err"),
        },
    ),
    (
        r"osint/github/.+",
        {
            "login": X("gh-login"),
            "name": X("gh-name"),
            "bio": X("gh-bio"),
            "avatar_url": JS_URL,
            "html_url": JS_URL,
            "id": 1,
            "company": X("gh-co"),
            "location": X("gh-loc"),
            "email": X("gh-mail"),
            "blog": X("gh-blog"),
            "twitter_username": X("gh-tw"),
            "public_repos": 1,
            "followers": 1,
            "following": 1,
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2020-01-01T00:00:00Z",
            "hireable": True,
            "_extracted_emails": [X("gh-mail2")],
        },
    ),
    (
        r"osint/reddit/.+",
        {
            "data": {
                "name": X("rd-name"),
                "icon_img": JS_URL,
                "id": X("rd-id"),
                "created_utc": 1600000000,
                "link_karma": 1,
                "comment_karma": 1,
                "has_verified_email": True,
                "subreddit": {"public_description": X("rd-desc"), "subscribers": 5},
            }
        },
    ),
    (
        r"osint/discord/.+",
        {
            "id": X("dc-id"),
            "username": X("dc-user"),
            "global_name": X("dc-name"),
            "avatar": {"link": JS_URL},
            "badges": [X("dc-badge")],
            "accent_color": X("dc-color"),
            "banner": {"link": X("dc-banner")},
        },
    ),
    (
        r"osint/tiktok/.+",
        {
            "userInfo": {
                "user": {
                    "uniqueId": X("tt-id"),
                    "nickname": X("tt-nick"),
                    "signature": X("tt-sig"),
                    "avatarMedium": JS_URL,
                    "id": X("tt-uid"),
                    "region": X("tt-region"),
                    "language": X("tt-lang"),
                    "createTime": 1600000000,
                },
                "stats": {
                    "followerCount": 1,
                    "followingCount": 1,
                    "heartCount": 1,
                    "videoCount": 1,
                },
            }
        },
    ),
    (
        r"osint/domain/.+",
        {
            "rdap_status": 200,
            "rdap": {
                "ldhName": X("rdap-name"),
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", X("rdap-reg")]]],
                    }
                ],
                "status": [X("rdap-status")],
                "nameservers": [{"ldhName": X("rdap-ns")}],
                "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
            },
            "crtsh": [X("crt-name")],
        },
    ),
    (r"osint/username/.+", {"found": [{"url": JS_URL, "name": X("un-name")}], "checked": 1}),
    (
        r"quick-scan/status/.+",
        {
            "status": "completed",
            "urls_visited": 1,
            "findings_count": 2,
            "error_message": X("qs-err"),
        },
    ),
    (
        r"quick-scan/findings/.+",
        [
            {
                "source_name": X("qs-src"),
                "url": JS_URL,
                "matched_variant": X("qs-var"),
                "context": X("qs-ctx"),
                "high_signal": True,
                "found_at": WHEN,
            },
            {
                "source_name": "ahmia",
                "url": "http://example.onion/" + MARK,
                "matched_variant": "x",
                "context": "x",
                "high_signal": False,
                "found_at": WHEN,
            },
        ],
    ),
]

# ── The stub application ───────────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=str(TEMPLATES),
    static_folder=str(STATIC) if STATIC.is_dir() else None,
    static_url_path="/static",
)
app.jinja_env.globals["csrf_token"] = lambda: CSRF
# The same after_request hook and asset_url() helper as the real application.
init_security_headers(app)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

writes = []  # every request to /api/ that is not a GET
missing = set()  # GET paths without a fixture
asked = []  # every /api/ path that was requested
asked_queries = []  # the same, as (path, query string)
provoked = set()  # paths the stub answered with an error status on purpose
# (METHOD, path) -> (status, body): set by a step that wants one answer to be an error.
overrides = {}
# (METHOD, path) -> answers in order, the last one repeated: a poll that is
# answered first and then meets an error.
SEQUENCES = {
    ("GET", "channel-monitor/jobs/job-run/log"): [
        (200, {"status": "running", "log": [X("cm-live")], "total": 2}),
        (404, {"error": "Job not found"}),
    ],
    ("GET", "quick-scan/status/2"): [
        (200, {"status": "running", "urls_visited": 1, "findings_count": 0, "error_message": None}),
        (500, {"error": X("qs-stop"), "error_id": "0f0f0f0f"}),
    ],
}
served = {}  # (METHOD, path) -> how many times a sequence was asked
# Paths of the features removed in v1.3.0: the page must not ask for them.
REMOVED = re.compile(
    r"paste(/|$)|seeds/(clearnet|paste)|telegram/channels|digest/subscribe$|send-brief|dns/investigations/[^/]+/scan"
)


@app.route("/")
@app.route("/dashboard")
def dashboard():
    return render_template(
        "index.html", username="auditor", is_admin=request.args.get("admin") != "0"
    )


@app.route("/quick-scan")
def quick_scan():
    sources = [{"name": "ahmia", "label": "Ahmia", "transport": "tor", "enabled": True}]
    return render_template("quick_scan.html", username="auditor", is_admin=True, sources=sources)


@app.route("/login")
@app.route("/help")
@app.route("/logout", methods=["POST"])
def plain_page():
    return "<!doctype html><title>stub</title><p>stub</p>"


@app.route("/api/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def api(path):
    if request.method != "GET":
        writes.append(
            {
                "method": request.method,
                "path": "/api/" + path,
                "page": urlsplit(request.headers.get("Referer", "")).path,
                "token": request.headers.get("X-CSRF-Token"),
                "body": request.get_data(as_text=True),
            }
        )
    asked.append(path)
    asked_queries.append((path, request.query_string.decode()))
    if path == "audit-401":
        provoked.add(path)
        return jsonify({"error": "unauthorized"}), 401
    if path == "audit-403":
        provoked.add(path)
        return jsonify({"error": "admin required"}), 403
    if (request.method, path) in overrides:
        status, body = overrides[(request.method, path)]
        provoked.add(path)
        if isinstance(body, str):
            return Response(body, status=status, mimetype="text/html")
        return jsonify(body), status
    if (request.method, path) in SEQUENCES:
        answers = SEQUENCES[(request.method, path)]
        n = served.get((request.method, path), 0)
        served[(request.method, path)] = n + 1
        status, body = answers[min(n, len(answers) - 1)]
        if status != 200:
            provoked.add(path)
        return jsonify(body), status
    for key in ((request.method, path), path):
        if key in FIXTURES:
            return jsonify(FIXTURES[key])
    for pattern, answer in PATTERNS:
        if re.fullmatch(pattern, path):
            return jsonify(answer)
    if request.method == "GET":
        missing.add(path)
        return jsonify({})
    return jsonify({"ok": True, "added": 1})


# ── The browser side ───────────────────────────────────────────────────────────

INSPECT = """
() => {
  const out = [];
  const tag = el => '<' + el.tagName.toLowerCase() + '>';
  if (window.__xss !== undefined) {
    out.push('script from data ran (window.__xss = ' + window.__xss + ')');
    window.__xss = undefined;
  }
  for (const el of document.querySelectorAll('[data-audit-sub], [data-audit-attr]'))
    out.push('attribute injected from data on ' + tag(el));
  for (const el of document.querySelectorAll('img[src="x"]'))
    out.push('element injected from data: ' + el.outerHTML.slice(0, 70));
  for (const el of document.querySelectorAll('*')) {
    for (const a of el.attributes) {
      if (/^on/i.test(a.name) && a.value.includes('__xss'))
        out.push('event handler built from data: ' + tag(el) + ' ' + a.name + '="' + a.value.slice(0, 50) + '"');
    }
  }
  for (const el of document.querySelectorAll('[href], [src]')) {
    const url = (el.getAttribute('href') || el.getAttribute('src') || '').trim().toLowerCase();
    if (url.startsWith('javascript:')) out.push('javascript: URL in ' + tag(el));
  }
  for (const el of document.querySelectorAll('a[target="_blank"]')) {
    if (!/noopener/.test(el.rel)) out.push('new-tab link without rel="noopener": ' + el.outerHTML.slice(0, 70));
  }
  return out;
}
"""


class Checker:
    def __init__(self, page):
        self.page = page
        self.failures = []
        self._seen = set()
        self.steps = 0

    def fail(self, where, message):
        if message not in self._seen:
            self._seen.add(message)
            self.failures.append(f"{where}: {message}")

    def settle(self):
        try:
            self.page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        self.page.wait_for_timeout(120)

    def step(self, where, action=None, expect=()):
        """Run ``action``, let the page finish loading, then inspect it."""
        self.steps += 1
        if action is not None:
            try:
                action()
            except Exception as exc:
                self.fail(where, "could not drive the page: " + str(exc).splitlines()[0][:160])
        self.settle()
        try:
            for problem in self.page.evaluate(INSPECT):
                self.fail(where, problem)
            text = self.page.evaluate("() => document.body.textContent")
        except Exception as exc:
            self.fail(where, "could not inspect the page: " + str(exc).splitlines()[0][:160])
            return
        for value in expect:
            if value not in text:
                self.fail(where, f"value not shown as text: {value!r}")

    # Ways to drive the page. ``js_click`` reaches elements whatever their
    # visibility and triggers the delegated listeners. A control names its
    # function in data-act and its arguments in data-args; the second half of
    # each selector is the markup before v1.3.0 (inline handlers), so that a
    # run against an older copy still presses the same buttons.
    def tab(self, name):
        return lambda: self.page.click(
            f"button.nav-tab[data-args='[\"{name}\"]'], button.nav-tab[onclick*=\"'{name}'\"]"
        )

    def osint_tab(self, tool):
        self.page.click(
            f"button.osint-sub-tab[data-args='[\"{tool}\"]'], button.osint-sub-tab[onclick*=\"'{tool}'\"]"
        )

    def toast(self):
        return self.page.evaluate("() => document.getElementById('toast').textContent")

    def expect_toast(self, where, text):
        shown = self.toast()
        if shown != text:
            self.fail(where, f"the toast shows {shown!r}, not {text!r}")

    def text_of(self, selector):
        return self.page.evaluate(
            "selector => (document.querySelector(selector) || {textContent: ''}).textContent",
            selector,
        )

    def js_click(self, selector, skip_text=None):
        def run():
            clicked = self.page.evaluate(
                """([selector, skip]) => {
                  const els = [...document.querySelectorAll(selector)].filter(e => !skip || !e.textContent.includes(skip));
                  els.forEach(e => e.click());
                  return els.length;
                }""",
                [selector, skip_text],
            )
            if not clicked:
                raise RuntimeError(f"nothing matches {selector}")

        return run

    def nth(self, selector, index):
        return lambda: self.page.locator(selector).nth(index).click()

    def lookup(self, tool, value, button="button.btn-primary"):
        def run():
            self.osint_tab(tool)
            self.page.fill(f"#osint-{tool}-input", value)
            self.page.click(f"#osint-{tool} {button}")

        return run

    def expect_write(self, where, method, path_part, *values):
        """A recorded request whose JSON body holds every one of ``values``, unchanged."""
        for call in writes:
            if call["method"] != method or path_part not in call["path"]:
                continue
            if not values:
                return
            try:
                body = json.loads(call["body"] or "null")
            except ValueError:
                continue
            sent = list(body.values()) if isinstance(body, dict) else []
            if all(v in sent for v in values):
                return
        what = f" carrying {list(values)!r}" if values else ""
        self.fail(where, f"no {method} request to {path_part}{what} was sent")


def check_dashboard(c, base):
    page = c.page
    page.goto(base + "/dashboard")
    c.step(
        "home",
        expect=[
            X("v-group"),
            X("victim"),
            X("leak-group"),
            X("tf")[:45],
            X("tf-mal"),
            X("press"),
            X("press-src"),
        ],
    )
    # A row built by the script leads to another tab.
    c.step("home: group row", c.js_click("#hdGroupFeed .hd-group-row"))
    if not page.evaluate(
        "() => document.getElementById('panel-ransomware').classList.contains('active')"
    ):
        c.fail("home: group row", "the row did not open the Ransomware tab")

    # REL-4: how the last crawl ended is on the card, with the server's text.
    c.step("crawls", c.tab("dashboard"), [X("topkw"), CALL, "Last crawl failed", X("crawl-err")])
    # A refused start shows the server's text; a start that worked polls the status.
    overrides[("POST", "crawl/start")] = (409, {"error": X("crawl-409")})
    c.step("crawls: start refused", c.js_click("#crawlBtn"))
    c.expect_toast("crawls: start refused", X("crawl-409"))
    del overrides[("POST", "crawl/start")]
    polls = asked.count("crawl/status")
    c.step("crawls: start", c.js_click("#crawlBtn"))
    c.expect_toast("crawls: start", "Crawl started.")
    if asked.count("crawl/status") <= polls:
        c.fail("crawls: start", "the crawl status was not asked for after the start")
    c.step("crawls: keyword pills", c.js_click("#topKeywords .kw-pill"))
    c.step(
        "crawls: session hits",
        c.js_click("#sess-1"),
        [X("s-kw"), X("s-cat"), X("s-url"), X("s-ctx")],
    )

    c.step("keywords", c.tab("keywords"), [X("cat"), X("kw"), CALL])
    c.step("keywords: remove", c.js_click("#keywordsList button"))
    c.expect_write("keywords: remove", "DELETE", "/api/keywords", X("kw"), X("cat"))
    c.expect_write("keywords: remove", "DELETE", "/api/keywords", CALL, X("cat"))

    def generate():
        page.evaluate(
            "() => { document.getElementById('genName').value = 'acme'; document.getElementById('genBtn').click(); }"
        )

    c.step("keywords: generator", generate, [X("gen-cat"), X("gen-kw")])
    c.step(
        "keywords: generated, select none and all", c.js_click("#genResults button.btn-secondary")
    )
    c.step("keywords: generated, toggle one", c.js_click("#genResults .gen-kw-item"))

    # The project dropdown reads the list GET /api/projects answers with.
    c.step("keywords: project scope", c.js_click("#kwProjectScope"))
    options = page.evaluate(
        "() => [...document.querySelectorAll('#kwProjectSelect option')].map(o => o.textContent)"
    )
    if options != [X("proj")]:
        c.fail("keywords: project scope", f"the project dropdown holds {options!r}")
    c.step("keywords: search", lambda: page.fill("#keywordSearch", "kw"), [X("kw")])

    c.step("seeds", c.tab("seeds"), [X("seed")])
    c.step(
        "seeds: sub-tabs",
        c.js_click(".seeds-tab-btn"),
        ["reads its channels from TELEGRAM_CHANNELS in .env"],
    )
    if page.evaluate("() => document.querySelectorAll('.seeds-tab-btn').length") != 2:
        c.fail("seeds: sub-tabs", "expected the two sub-tabs Onion Seeds and Telegram")
    c.step("seeds: remove", c.js_click("#seedsList button"))
    c.expect_write("seeds: remove", "DELETE", "/api/seeds", X("seed"))
    c.expect_write("seeds: remove", "DELETE", "/api/seeds", CALL)

    c.step(
        "users",
        c.tab("users"),
        [X("user"), X("mail"), CALL, X("ev"), X("ev-user"), X("ev-ip"), X("ev-detail")],
    )
    c.step("users: reset 2FA and remove", c.js_click("#usersList button"))
    c.expect_write("users: reset 2FA", "POST", "/api/users/2/mfa/reset")
    c.expect_write("users: remove", "DELETE", "/api/users/2")
    c.expect_write("users: remove", "DELETE", "/api/users/3")

    c.step("investigations", c.tab("investigations"), [X("inv")])
    c.step(
        "investigations: result",
        c.js_click("#inv-1"),
        [
            X("t-val"),
            X("t-err"),
            X("br"),
            X("br-date"),
            X("br-class"),
            X("dw-url"),
            X("dw-ctx"),
            X("dw-at"),
        ],
    )

    c.step("ip lookup", c.tab("iplookup"), [X("ip"), X("ip-country"), X("ip-isp")])
    c.step(
        "ip lookup: report",
        c.js_click("#ipinv-1"),
        [
            X("a-ip"),
            X("a-isp"),
            X("a-host"),
            X("a-cat"),
            X("a-cmt"),
            X("v-as"),
            X("v-eng"),
            X("v-res"),
            X("v-cn"),
        ]
        + [X("v-host"), X("v-file"), X("v-whois")],
    )

    for name, grid, key in (
        ("ransomware", "#ransomwareGrid", "rw"),
        ("threatactors", "#threatActorsGrid", "ta"),
    ):
        c.step(
            name,
            c.tab(name),
            [X(key), X(key + "-origin"), X(key + "-first"), X(key + "-desc"), X(key + "-ttp")],
        )
        c.step(
            name + ": detail",
            c.js_click(grid + " .intel-card"),
            [
                X(key + "-victim"),
                X(key + "-sector"),
                X(key + "-country"),
                X(key + "-mal"),
                X(key + "-kw"),
            ]
            + [X(key + "-hkw"), X(key + "-hurl"), X(key + "-hctx")],
        )
        # A click inside the detail keeps it open; a click on the overlay around it closes it.
        is_open = "() => document.getElementById('intelDetailOverlay').classList.contains('open')"
        c.step(name + ": click inside the detail", c.js_click("#intelDetailModal"))
        if not page.evaluate(is_open):
            c.fail(name + ": detail", "a click inside the detail closed it")
        c.step(name + ": close detail", c.js_click("#intelDetailOverlay"))
        if page.evaluate(is_open):
            c.fail(name + ": detail", "a click on the overlay did not close the detail")
        c.step(name + ": delete", c.js_click(grid + " .intel-card button"))
        c.expect_write(name + ": delete", "DELETE", key + "-slug")

    c.step("ioc feed", c.tab("iocfeed"), [X("tf"), X("tf-mal"), X("tf-rep")])
    c.step("ioc feed: urlhaus", c.nth(".ioc-abuse-tab", 1), [X("uh"), X("uh-tag"), X("uh-host")])
    c.step("ioc feed: feodo", c.nth(".ioc-abuse-tab", 2), [X("fe"), X("fe-mal"), X("fe-country")])

    c.step("projects", c.tab("projects"), [X("proj"), X("proj-desc"), X("owner"), X("tag")])
    c.step("projects: detail", c.js_click("#projectsGrid .project-card"), [X("thr")])
    c.step("projects: keywords", c.nth(".proj-subtab", 1), [X("pk"), X("pk-cat")])
    c.step("projects: domains", c.nth(".proj-subtab", 2), [X("pd"), X("pd-note")])
    c.step("projects: entities", c.nth(".proj-subtab", 3), [X("pe-type"), X("pe"), X("pe-note")])
    c.step(
        "projects: hits",
        c.nth(".proj-subtab", 4),
        [X("ph-kw"), X("ph-on"), X("ph-val"), X("ph-ctx")],
    )

    if page.evaluate("() => !!document.querySelector('#panel-paste, [data-args*=\"paste\"]')"):
        c.fail("paste", "the Paste Monitor tab is still on the page")

    c.step("dns", c.tab("dns"), [X("dns"), X("dns2")])
    c.step("dns: result", c.js_click("#dnsContent > div > div:nth-child(1)"))
    for i in range(7):
        c.step(f"dns: view {i + 1}", c.nth(".dns-view-btn", i))
    c.step(
        "dns: all views",
        expect=[
            X("server"),
            X("tech"),
            X("title")[:50],
            X("sub"),
            X("sub-ip"),
            X("zt-ns"),
            X("zt-name"),
            X("ps-ip"),
        ]
        + [X("svc"), X("de-target"), X("de-path"), X("txt"), X("ptr"), X("san"), X("cert-san")],
    )
    # The world map and its library come from /static/ and run under the policy.
    c.step(
        "dns: graph reset, section headers, copy",
        c.js_click(
            "#dnsContent [data-act='dnsResetGraph'], #dnsContent .is-hdr, #dnsContent [data-act='copyCertSANs']"
        ),
    )
    c.step(
        "dns: refresh certificates",
        c.js_click("#dnsContent [data-act='dnsRefreshCerts']"),
        [X("san")],
    )
    if page.evaluate("() => typeof jsVectorMap") != "function":
        c.fail("dns: map", "the map library did not load from /static/vendor/jsvectormap")
    elif not page.evaluate("() => !!document.querySelector('#infra-world-map svg')"):
        c.fail("dns: map", "the world map was not drawn")
    c.step(
        "dns: back to the list", c.js_click("#dnsContent [data-act='showDNSHistory']"), [X("dns2")]
    )
    c.step(
        "dns: result without a scan",
        c.js_click("#dnsContent > div > div:nth-child(2)"),
        [
            "There are no port scan results for " + X("dns2") + ".",
            "There are no directory scan results for " + X("dns2") + ".",
        ],
    )
    if page.evaluate(
        "() => [...document.querySelectorAll('#dnsContent button')].some(b => /scan|enum/i.test(b.textContent))"
    ):
        c.fail(
            "dns: result without a scan",
            "a button that starts a port or directory scan is on the page",
        )

    check_channel_monitor(c)

    c.step("reports", c.tab("reports"), [X("sub-mail"), ATTR_SQ, ATTR_DQ, CALL])
    c.step("reports: remove subscribers", c.js_click("#subscribersList button"))
    for value in (X("sub-mail"), ATTR_SQ, ATTR_DQ, CALL):
        c.expect_write("reports: remove subscribers", "DELETE", "/api/digest/subscribers", value)

    c.step("osint", c.tab("osint"))
    c.step("osint: username", c.lookup("username", "alice", "#osintUsernameBtn"), [X("un-name")])
    c.step(
        "osint: github",
        c.lookup("github", "alice"),
        [X("gh-login"), X("gh-name"), X("gh-bio"), X("gh-co"), X("gh-blog"), X("gh-mail")],
    )
    c.step("osint: reddit", c.lookup("reddit", "alice"), [X("rd-name"), X("rd-desc")])
    c.step("osint: tiktok", c.lookup("tiktok", "alice"), [X("tt-id"), X("tt-nick"), X("tt-sig")])
    c.step("osint: google", c.lookup("google", "alice@example.com"))
    c.step(
        "osint: discord",
        c.lookup("discord", "123456789012345678"),
        [X("dc-user"), X("dc-name"), X("dc-badge"), X("dc-banner")],
    )
    c.step(
        "osint: domain",
        c.lookup("domain", "example.com"),
        [X("rdap-name"), X("rdap-reg"), X("rdap-ns"), X("crt-name")],
    )
    c.step("osint: email", c.lookup("email", "alice@example.com"))
    c.step("osint: resources", lambda: c.osint_tab("resources"))

    c.step("settings", c.tab("settings"), [X("me"), X("me-mail")])

    check_errors(c)
    check_shell(c, "dashboard")

    # "admin required" is reported, an ended session goes to the sign-in page.
    try:
        answer = page.evaluate(
            "() => fetch('/api/audit-403', {method: 'POST'}).then(r => r.json())"
        )
        shown = page.evaluate("() => document.getElementById('toast').textContent")
        if answer != {"ok": False, "error": "Admin only"} or shown != "Admin only":
            c.fail(
                "dashboard",
                f'403 "admin required" is not reported as "Admin only" (got {answer!r}, toast {shown!r})',
            )
    except Exception as exc:
        c.fail("dashboard", "403 handling: " + str(exc).splitlines()[0][:160])
    try:
        page.evaluate("() => { fetch('/api/audit-401').catch(() => {}); }")
        page.wait_for_url(re.compile(r"/login\?next=%2Fdashboard$"), timeout=4000)
    except Exception:
        c.fail("dashboard", "401 from the API does not lead to /login?next=<current path>")


def check_channel_monitor(c):
    """REL-1: heading, badge, note and download button follow the job's status."""
    page = c.page
    unknown = "Finished (" + X("cm-status") + ")"

    def state():
        return page.evaluate(
            """() => ({
              heading: document.getElementById('cmActiveState').textContent,
              badge: document.getElementById('cmStatusBadge').textContent,
              note: document.getElementById('cmStatusNote').textContent,
              download: document.getElementById('cmDownloadBtn').style.display !== 'none',
              log: document.getElementById('cmLogBox').textContent,
            })"""
        )

    def view(job_id):
        def run():
            clicked = page.evaluate(
                """id => {
                  const els = [...document.querySelectorAll("#cmJobsTable [data-act='cmViewJob']")]
                    .filter(e => JSON.parse(e.dataset.args)[0] === id);
                  els.forEach(e => e.click());
                  return els.length;
                }""",
                job_id,
            )
            if clicked != 1:
                raise RuntimeError(f"{clicked} Log buttons for job {job_id!r}")

        return run

    def expect_state(where, label, download, note_part=""):
        got = state()
        if got["heading"] != label or got["badge"] != label:
            c.fail(
                where, f"heading {got['heading']!r} and badge {got['badge']!r}, expected {label!r}"
            )
        if got["download"] != download:
            c.fail(where, "the download button is " + ("shown" if got["download"] else "hidden"))
        if note_part not in got["note"]:
            c.fail(where, f"the note is {got['note']!r}, expected {note_part!r} in it")
        return got

    c.step(
        "channel monitor",
        c.tab("channelmonitor"),
        [
            X("cm"),
            X("cm2"),
            "✓ Completed",
            "✗ Error",
            "✗ Interrupted",
            "Archived",
            unknown,
            "⏳ Running",
        ]
        + [
            "Limits of one job: 5,000 messages, a video up to 200 MB, any other file up to 100 MB, 2 GB in total."
        ],
    )
    bounds = page.evaluate(
        "() => [document.getElementById('cmLimit').max, document.getElementById('cmMaxVideo').max, !!document.getElementById('cmMinSpace')]"
    )
    if bounds != ["5000", "200", False]:
        c.fail("channel monitor", f"form bounds and fields: {bounds!r}")

    c.step("channel monitor: completed job", view("job1"), [X("cm-log")])
    expect_state("channel monitor: completed job", "✓ Completed", True)
    c.step("channel monitor: failed job", view(CALL), [X("cm2-log"), X("cm-err")])
    expect_state("channel monitor: failed job", "✗ Error", True, X("cm-err"))
    c.step("channel monitor: interrupted job", view("job-int"), [X("cm-int-log"), X("cm-int-err")])
    expect_state("channel monitor: interrupted job", "✗ Interrupted", True, X("cm-int-err"))
    c.step("channel monitor: archive from an older release", view("job-arch"))
    expect_state("channel monitor: archive", "Archived", True, "Archive from before this release")
    c.step("channel monitor: status the page does not know", view("job-odd"), [unknown])
    expect_state("channel monitor: unknown status", unknown, True)

    # A running job: the log is polled, the first answer brings a line, the next
    # one is 404 (the application restarted). The poll stops and says why.
    log_path = "channel-monitor/jobs/job-run/log"
    c.step("channel monitor: running job", view("job-run"), [X("cm-run-log")])
    expect_state("channel monitor: running job", "⏳ Running", False)
    try:
        page.wait_for_function(
            "() => document.getElementById('cmLogBox').textContent.includes('Log updates stopped')",
            timeout=9000,
        )
    except Exception:
        c.fail("channel monitor: poll", "the log poll did not stop on a 404 answer")
    c.step(
        "channel monitor: poll stopped",
        expect=[X("cm-live"), "Log updates stopped: the server no longer knows this job"],
    )
    expect_state("channel monitor: poll stopped", "Status not known", False, "Log updates stopped")
    polls = asked.count(log_path)
    page.wait_for_timeout(3500)
    if asked.count(log_path) != polls or polls != 2:
        c.fail(
            "channel monitor: poll",
            f"the log was asked for {asked.count(log_path)} times, expected 2 and then silence",
        )

    # Start: a refusal (another job is running) shows the server's text; the
    # request says whether to translate and no longer carries min_space_gb.
    def start(translate):
        def run():
            page.fill("#cmChannel", "@example_channel")
            page.evaluate(
                "on => { document.getElementById('cmTranslate').checked = on; }", translate
            )
            page.evaluate("() => document.getElementById('cmStartBtn').click()")

        return run

    if not page.evaluate("() => document.getElementById('cmTranslate').defaultChecked"):
        c.fail("channel monitor: start", "translation is not on by default")
    overrides[("POST", "channel-monitor/start")] = (409, {"error": X("cm-409")})
    c.step("channel monitor: start refused", start(False), ["sent to translate.google.com"])
    c.expect_toast("channel monitor: start refused", X("cm-409"))
    del overrides[("POST", "channel-monitor/start")]
    c.step("channel monitor: start", start(True))
    sent = [json.loads(w["body"]) for w in writes if w["path"] == "/api/channel-monitor/start"]
    if [s.get("translate") for s in sent] != [False, True]:
        c.fail(
            "channel monitor: start",
            f"translate was sent as {[s.get('translate') for s in sent]!r}",
        )
    if any("min_space_gb" in s for s in sent) or any(
        s.get("channel") != "example_channel" for s in sent
    ):
        c.fail("channel monitor: start", f"unexpected start request: {sent!r}")
    try:
        page.wait_for_function(
            "() => document.getElementById('cmActiveState').textContent === '✓ Completed'",
            timeout=6000,
        )
    except Exception:
        c.fail("channel monitor: start", "the panel did not follow the new job to its end")
    c.step("channel monitor: started job finished", expect=[X("cm-new-log")])
    expect_state("channel monitor: started job finished", "✓ Completed", True)

    c.step("channel monitor: delete", c.js_click("#cmJobsTable [data-act='cmDeleteJob']"))
    c.expect_write("channel monitor: delete", "DELETE", "/api/channel-monitor/jobs/job1")
    if page.evaluate(
        "() => !!document.querySelector(\"#cmJobsTable [data-act='cmDeleteJob'][data-args*='job-run']\")"
    ):
        c.fail("channel monitor: delete", "a running job has a delete button")


def check_errors(c):
    """An API answer that is not a success is shown: the server's text and its error id."""
    page = c.page
    with_id = X("boom") + " (error id ab12cd34)"

    # A list that cannot be loaded says why, in its own place and as a toast.
    overrides[("GET", "investigations")] = (500, {"error": X("boom"), "error_id": "ab12cd34"})
    c.step("errors: list", c.tab("investigations"), [with_id])
    c.expect_toast("errors: list", with_id)
    if c.text_of("#investigationsList") != with_id:
        c.fail("errors: list", f"the list shows {c.text_of('#investigationsList')!r}")
    del overrides[("GET", "investigations")]

    # 429 from a heavy lookup, started with the Enter key.
    overrides[("POST", "ip-investigations")] = (429, {"error": X("slow")})

    def lookup():
        c.tab("iplookup")()
        page.fill("#ipInput", "192.0.2.7")
        page.press("#ipInput", "Enter")

    c.step("errors: 429", lookup)
    c.expect_toast("errors: 429", X("slow"))
    c.expect_write("errors: 429", "POST", "/api/ip-investigations", "192.0.2.7")
    del overrides[("POST", "ip-investigations")]

    # An answer that is not JSON (a proxy's error page).
    overrides[("POST", "ransomware/add-seeds")] = (502, "<html><body>Bad Gateway</body></html>")
    c.step("errors: not JSON", c.js_click("[data-act='addRansomwareSeeds']"))
    c.expect_toast("errors: not JSON", "The server answered with an error (502)")
    del overrides[("POST", "ransomware/add-seeds")]

    # A failed write is not reported as a success.
    overrides[("DELETE", "dns/investigations/1")] = (
        500,
        {"error": X("no-delete"), "error_id": "00ff00ff"},
    )
    c.step("errors: failed delete, list", c.tab("dns"), [X("dns")])
    c.step("errors: failed delete", c.nth("#dnsContent [data-act='deleteDNS']", 0))
    c.expect_toast("errors: failed delete", X("no-delete") + " (error id 00ff00ff)")
    del overrides[("DELETE", "dns/investigations/1")]

    # No answer at all.
    provoked.add("threat-actors/add-keywords")
    page.route("**/api/threat-actors/add-keywords", lambda route: route.abort())
    c.step("errors: no answer", c.js_click("[data-act='addThreatActorKeywords']"))
    c.expect_toast("errors: no answer", "Network error: no answer from the server")
    page.unroute("**/api/threat-actors/add-keywords")


def check_shell(c, where):
    """CSRF token on the page and on its write requests, sign-out form, help link."""
    facts = c.page.evaluate(
        """() => ({
          meta: (document.querySelector('meta[name="csrf-token"]') || {}).content || null,
          logoutLink: !!document.querySelector('a[href="/logout"]'),
          logoutForm: !!document.querySelector('form[action="/logout"][method="post" i] button[type="submit"]'),
          logoutToken: (document.querySelector('form[action="/logout"] input[name="csrf_token"]') || {}).value || null,
          help: !!document.querySelector('a[href="/help"]'),
        })"""
    )
    if facts["meta"] != CSRF:
        c.fail(where, 'no <meta name="csrf-token"> with the session token')
    if facts["logoutLink"]:
        c.fail(where, "sign-out is still a GET link to /logout")
    if not facts["logoutForm"] or facts["logoutToken"] != CSRF:
        c.fail(where, "no POST form to /logout carrying csrf_token")
    if not facts["help"]:
        c.fail(where, "no link to /help")
    mine = [w for w in writes if w["page"] == c.page.evaluate("() => location.pathname")]
    if not mine:
        c.fail(where, "the page sent no write request, so the CSRF header could not be checked")
    without = sorted({f"{w['method']} {w['path'][:60]}" for w in mine if w["token"] != CSRF})
    if without:
        c.fail(
            where,
            f"{len(without)} kind(s) of write request without X-CSRF-Token, e.g. {without[0]}",
        )


def check_roles(c, base):
    """A non-admin gets the read-only view: no admin-only tabs or controls."""
    page = c.page
    page.goto(base + "/dashboard?admin=0")
    c.settle()
    visits = [
        (None, ["button.nav-tab[data-args='[\"channelmonitor\"]']", "#tab-users", "#crawlBtn"]),
        ("keywords", ["#keywordsList button", 'input[data-act-change="importKeywords"]']),
        (
            "seeds",
            ["#seedsList button", 'button[data-act="addSeed"]', 'button[data-act="bulkAddSeeds"]'],
        ),
        ("investigations", ["#investigationsList button"]),
        ("iplookup", ["#ipInvestigationsList button"]),
        ("dns", ["#dnsContent button"]),
        ("reports", ["#digestSendBtn", 'button[data-act="addSubscriber"]']),
    ]
    for name, selectors in visits:
        where = "non-admin: " + (name or "header")
        if name:
            try:
                c.tab(name)()
            except Exception as exc:
                c.fail(where, "could not open the tab: " + str(exc).splitlines()[0][:160])
                continue
            c.settle()
        for selector in selectors:
            if not page.evaluate("selector => !!document.querySelector(selector)", selector):
                c.fail(
                    where,
                    f"nothing matches {selector}: the check looks for a control that is not there",
                )
                continue
            shown = page.evaluate(
                """selector => [...document.querySelectorAll(selector)].some(e => {
                  const target = e.type === 'file' ? e.closest('label') || e : e;
                  return target.getClientRects().length > 0;
                })""",
                selector,
            )
            if shown:
                c.fail(where, f"admin-only control is shown: {selector}")
    if not page.evaluate("() => !!document.querySelector('#panel-keywords .keyword-tag')"):
        c.fail("non-admin: keywords", "the read-only keyword list is missing")


def check_quick_scan(c, base):
    page = c.page
    page.goto(base + "/quick-scan")
    c.step("quick scan", expect=[X("qs-target"), X("qs-type")])
    c.step(
        "quick scan: session",
        c.js_click("#qs-sessions-body tr"),
        [X("qs-src"), X("qs-var"), X("qs-ctx"), X("qs-err"), "http://example.onion/" + MARK],
    )

    def start():
        page.fill("#qs-target", "example.com")
        page.click("#qs-start")

    c.step("quick scan: start", start)
    c.expect_write("quick scan: start", "POST", "/api/quick-scan/start", "example.com")
    c.step("quick scan: high-signal filter", c.js_click("#qs-hi-only"))
    if not any(
        p.startswith("quick-scan/findings/") and "high_signal_only=1" in q for p, q in asked_queries
    ):
        c.fail(
            "quick scan: high-signal filter",
            "the findings were not asked for again with the filter",
        )
    c.step(
        "quick scan: refresh sessions", c.js_click("[data-act='loadSessions']"), [X("qs-target")]
    )

    # A refused start shows the server's text.
    overrides[("POST", "quick-scan/start")] = (409, {"error": X("qs-409")})
    c.step("quick scan: start refused", start)
    c.expect_toast("quick scan: start refused", X("qs-409"))
    del overrides[("POST", "quick-scan/start")]

    # A running scan whose status can no longer be read: the poll stops and says why.
    status_path = "quick-scan/status/2"
    FIXTURES[("POST", "quick-scan/start")] = {"session_id": 2}
    c.step("quick scan: start, then the status fails", start)
    stopped = "Status updates stopped: " + X("qs-stop") + " (error id 0f0f0f0f)"
    try:
        page.wait_for_function(
            "text => document.getElementById('qs-warn').textContent.includes(text)",
            arg=stopped,
            timeout=8000,
        )
    except Exception:
        c.fail("quick scan: poll", f"the page shows {c.text_of('#qs-warn')!r}, not {stopped!r}")
    c.step("quick scan: poll stopped", expect=[stopped])
    polls = asked.count(status_path)
    page.wait_for_timeout(4500)
    if asked.count(status_path) != polls or polls != 2:
        c.fail(
            "quick scan: poll",
            f"the status was asked for {asked.count(status_path)} times, expected 2 and then silence",
        )
    check_shell(c, "quick scan")


def launch(playwright):
    try:
        return playwright.chromium.launch(headless=True)
    except Exception:
        # Containers that do not allow Chromium's own sandbox.
        return playwright.chromium.launch(headless=True, args=["--no-sandbox"])


# Reports every violation of the Content-Security-Policy to the check. Added by
# the browser before the page's own scripts; the policy does not apply to it.
REPORT_VIOLATIONS = """
document.addEventListener('securitypolicyviolation', e => {
  window.__policyViolation(JSON.stringify({
    directive: e.effectiveDirective || e.violatedDirective,
    blocked: e.blockedURI,
    sample: e.sample,
    line: e.lineNumber,
    page: location.pathname,
  }));
});
"""


def main() -> int:
    for name in ("index.html", "quick_scan.html"):
        if not (TEMPLATES / name).is_file():
            print(f"xss_check: {TEMPLATES / name} not found")
            return 1

    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"

    failures, steps, errors = [], 0, []
    violations, console_errors, outside, responses = [], [], [], []

    def on_console(msg):
        if msg.type != "error":
            return
        url = (msg.location or {}).get("url", "")
        # The browser logs every answer with an error status. The ones this
        # check asks the stub for are expected; anything else is a finding.
        if msg.text.startswith("Failed to load resource") and url.startswith(base + "/api/"):
            if urlsplit(url).path[len("/api/") :] in provoked:
                return
        console_errors.append(f"{msg.text[:200]} ({url[len(base) :] or 'no url'})")

    def on_response(response):
        if response.url.startswith(base):
            responses.append((urlsplit(response.url), response.status, response.headers))

    def route(route):
        if route.request.url.startswith(base):
            route.continue_()
        else:
            # Nothing but the stub: the page must not depend on, or talk to, the outside.
            outside.append(f"{route.request.resource_type} {route.request.url[:120]}")
            route.abort()

    with sync_playwright() as playwright:
        browser = launch(playwright)
        context = browser.new_context()
        context.expose_binding(
            "__policyViolation", lambda source, report: violations.append(json.loads(report))
        )
        context.add_init_script(REPORT_VIOLATIONS)
        context.route("**/*", route)
        context.on("response", on_response)
        for check in (check_dashboard, check_roles, check_quick_scan):
            page = context.new_page()
            page.set_default_timeout(4000)
            page.on("dialog", lambda dialog: dialog.accept())
            page.on("console", on_console)
            page.on(
                "pageerror",
                lambda exc, name=check.__name__: errors.append(f"{name}: {str(exc)[:200]}"),
            )
            checker = Checker(page)
            try:
                check(checker, base)
            except Exception as exc:
                checker.fail(check.__name__, "stopped: " + str(exc).splitlines()[0][:200])
            failures += checker.failures
            steps += checker.steps
            page.close()
        browser.close()
    server.shutdown()

    failures += [f"script error on the page: {e}" for e in dict.fromkeys(errors)]
    failures += [
        f"no fixture for GET /api/{p}: add one to FIXTURES or PATTERNS" for p in sorted(missing)
    ]
    failures += [
        f"the page asked for /api/{p}, which belongs to a removed feature"
        for p in sorted({p for p in asked if REMOVED.search(p)})
    ]
    failures += [f"request to another host: {r}" for r in dict.fromkeys(outside)]
    failures += [f"error in the browser console: {e}" for e in dict.fromkeys(console_errors)]
    seen = {}
    for v in violations:
        key = (v["page"], v["directive"], v["blocked"], (v["sample"] or "")[:40])
        seen[key] = seen.get(key, 0) + 1
    failures += [
        f"policy violation on {page}: {directive} blocked {blocked or 'inline'}"
        + (f" ({sample!r})" if sample else "")
        + (f", {count} times" if count > 1 else "")
        for (page, directive, blocked, sample), count in seen.items()
    ]
    failures += check_headers(responses)

    print(f"xss_check: templates {TEMPLATES}")
    print(f"xss_check: policy {CONTENT_SECURITY_POLICY}")
    print(f"xss_check: {steps} page states inspected, {len(writes)} write requests recorded")
    print(
        f"xss_check: {len(violations)} policy violations, {len(console_errors)} console errors, "
        f"{len(outside)} requests to other hosts"
    )
    if failures:
        print(f"xss_check: FAILED, {len(failures)} problem(s):")
        for failure in failures:
            print("  - " + failure)
        return 1
    print("xss_check: OK")
    return 0


def check_headers(responses) -> list[str]:
    """Every answer carried the policy; pages and API answers are not stored, static files are."""
    problems, static_seen = [], set()
    for url, status, headers in responses:
        policy, cache = headers.get("content-security-policy"), headers.get("cache-control", "")
        if policy != CONTENT_SECURITY_POLICY:
            problems.append(f"{url.path}: Content-Security-Policy is {policy!r}")
        if url.path.startswith("/static/"):
            static_seen.add(url.path)
            if status != 200 or url.query != f"v={__version__}" or cache != STATIC_CACHE_CONTROL:
                problems.append(f"{url.path}?{url.query}: status {status}, Cache-Control {cache!r}")
        elif url.path.startswith("/api/") or "text/html" in headers.get("content-type", ""):
            if cache != "no-store":
                problems.append(f"{url.path}: Cache-Control is {cache!r}, not no-store")
    if STATIC.is_dir():
        expected = {
            "/static/js/dashboard.js",
            "/static/js/quick_scan.js",
            "/static/vendor/jsvectormap/jsvectormap.min.css",
            "/static/vendor/jsvectormap/jsvectormap.min.js",
            "/static/vendor/jsvectormap/world.js",
        }
        problems += [f"{p} was never loaded" for p in sorted(expected - static_seen)]
    return list(dict.fromkeys(problems))


if __name__ == "__main__":
    sys.exit(main())
