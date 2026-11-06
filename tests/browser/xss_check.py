#!/usr/bin/env python3
"""
Headless-browser check of the dashboard pages against hostile data.

Run inside the application image, which has Flask, playwright and Chromium
(but no pytest):

    python tests/browser/xss_check.py

The script does not start the real application and does not sign in. It serves
the two page templates from a small Flask app, answers every /api/ call with
fixtures in which every string a third party could influence is a hostile
value, opens every tab and sub-view, and checks that

  * no value from the data ran as script, became an element, an attribute or an
    event handler, or ended up as a javascript: link;
  * the values are on the page as plain text;
  * buttons built from data still send exactly the value they were built from;
  * every write request carries the CSRF token, signing out is a POST form,
    an expired session leads to the sign-in page, and "admin required" is
    reported as "Admin only";
  * a non-admin does not get the admin-only controls.

The markers are inert: they set ``window.__xss`` or add a ``data-audit-*``
attribute, nothing else.

XSS_CHECK_TEMPLATES=<dir> points the script at another copy of the templates.
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

from flask import Flask, jsonify, render_template, request
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

REPO = Path(__file__).resolve().parents[2]
TEMPLATES = Path(
    os.environ.get("XSS_CHECK_TEMPLATES")
    or REPO / "src" / "darkweb_scanner" / "dashboard" / "templates"
)
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
    "crawl/status": {"active": False},
    "sessions": [SESSION],
    "keywords": {"categories": {X("cat"): [X("kw"), CALL]}},
    ("POST", "keywords/generate"): {"ok": True, "keywords": {X("gen-cat"): [X("gen-kw")]}},
    "seeds": {"seeds": [X("seed"), CALL]},
    "seeds/clearnet": {"seeds": [X("cseed"), CALL]},
    "seeds/paste": {"sources": [X("psrc"), CALL]},
    "telegram/channels": {"channels": [X("chan"), CALL]},
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
    "paste/stats": {
        "total_hits": 1,
        "total_scanned": 1,
        "total_with_hits": 1,
        "by_source": [{"source": X("paste-stat"), "count": 1}],
    },
    "paste/hits": [
        {
            "matched_pattern": X("paste-pat"),
            "matched_value": X("paste-val"),
            "source": X("paste-src"),
            "url": JS_URL,
            "context": X("paste-ctx"),
            "found_at": WHEN,
        },
        {
            "matched_pattern": "ph_mobile",
            "matched_value": "x",
            "source": "pastebin",
            "url": X("paste-url"),
            "context": "x",
            "found_at": WHEN,
        },
    ],
    "projects": [PROJECT],
    "settings/profile": {
        "username": X("me"),
        "email": X("me-mail"),
        "is_admin": True,
        "oauth_provider": X("oauth"),
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
    "channel-monitor/credentials": {"configured": True},
    "channel-monitor/jobs": [
        {"id": "job1", "channel": X("cm"), "started_at": WHEN, "status": "completed"},
        {"id": CALL, "channel": X("cm2"), "started_at": WHEN, "status": "error"},
    ],
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
    (
        r"channel-monitor/jobs/.+",
        {"channel": X("cm"), "log": [X("cm-log")], "total": 1, "status": "completed"},
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

app = Flask(__name__, template_folder=str(TEMPLATES))
app.jinja_env.globals["csrf_token"] = lambda: CSRF
logging.getLogger("werkzeug").setLevel(logging.ERROR)

writes = []  # every request to /api/ that is not a GET
missing = set()  # GET paths without a fixture


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
    if path == "audit-401":
        return jsonify({"error": "unauthorized"}), 401
    if path == "audit-403":
        return jsonify({"error": "admin required"}), 403
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
    # visibility and triggers inline handlers and delegated listeners alike.
    def tab(self, name):
        return lambda: self.page.click(f"button.nav-tab[onclick*=\"'{name}'\"]")

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
            self.page.click(f"button.osint-sub-tab[onclick*=\"'{tool}'\"]")
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

    c.step("crawls", c.tab("dashboard"), [X("topkw"), CALL])
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

    c.step("seeds", c.tab("seeds"), [X("seed")])
    c.step("seeds: sub-tabs", c.js_click(".seeds-tab-btn"), [X("cseed"), X("psrc"), X("chan")])
    c.step(
        "seeds: remove",
        c.js_click(
            "#seedsList button, #clearnetSeedsList button, #pasteSourcesList button, #channelsList button"
        ),
    )
    for path, field in (
        ("/api/seeds", "seed"),
        ("/api/seeds/clearnet", "cseed"),
        ("/api/seeds/paste", "psrc"),
    ):
        c.expect_write("seeds: remove", "DELETE", path, X(field))
        c.expect_write("seeds: remove", "DELETE", path, CALL)
    c.expect_write("seeds: remove", "DELETE", "/api/telegram/channels", X("chan"))
    c.expect_write("seeds: remove", "DELETE", "/api/telegram/channels", CALL)

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
        c.step(name + ": close detail", lambda: page.evaluate("() => closeIntelModalDirect()"))
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

    c.step(
        "paste",
        c.tab("paste"),
        [
            X("paste-stat"),
            X("paste-pat"),
            X("paste-val"),
            X("paste-src"),
            X("paste-ctx"),
            X("paste-url"),
        ],
    )

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
    c.step("dns: back to the list", c.tab("dns"))
    c.step(
        "dns: result without a scan",
        c.js_click("#dnsContent > div > div:nth-child(2)"),
        ["Probes " + X("dns2")],
    )

    c.step("channel monitor", c.tab("channelmonitor"), [X("cm"), X("cm2")])
    c.step("channel monitor: log and delete", c.js_click("#cmJobsTable button", skip_text="ZIP"))
    c.expect_write("channel monitor: delete", "DELETE", "/api/channel-monitor/jobs/job1")

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
    c.step("osint: resources", lambda: page.click("button.osint-sub-tab[onclick*=\"'resources'\"]"))

    c.step("settings", c.tab("settings"), [X("me"), X("me-mail"), X("oauth")])

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
        (None, ["button.nav-tab[onclick*=\"'channelmonitor'\"]", "#tab-users", "#crawlBtn"]),
        ("keywords", ["#keywordsList button", 'input[onchange="importKeywords(this)"]']),
        (
            "seeds",
            [
                "#seedsList button",
                'button[onclick="addSeed()"]',
                "button[onclick=\"bulkAddSeeds('onion')\"]",
            ],
        ),
        ("investigations", ["#investigationsList button"]),
        ("iplookup", ["#ipInvestigationsList button"]),
        ("dns", ["#dnsContent button"]),
        ("reports", ["#digestSendBtn", 'button[onclick="addSubscriber()"]']),
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
    check_shell(c, "quick scan")


def launch(playwright):
    try:
        return playwright.chromium.launch(headless=True)
    except Exception:
        # Containers that do not allow Chromium's own sandbox.
        return playwright.chromium.launch(headless=True, args=["--no-sandbox"])


def main() -> int:
    for name in ("index.html", "quick_scan.html"):
        if not (TEMPLATES / name).is_file():
            print(f"xss_check: {TEMPLATES / name} not found")
            return 1

    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"

    failures, steps, errors = [], 0, []
    with sync_playwright() as playwright:
        browser = launch(playwright)
        context = browser.new_context()
        # Nothing but the stub: the page must not depend on, or talk to, the outside.
        context.route(
            "**/*",
            lambda route: (
                route.continue_() if route.request.url.startswith(base) else route.abort()
            ),
        )
        for check in (check_dashboard, check_roles, check_quick_scan):
            page = context.new_page()
            page.set_default_timeout(4000)
            page.on("dialog", lambda dialog: dialog.accept())
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

    print(f"xss_check: templates {TEMPLATES}")
    print(f"xss_check: {steps} page states inspected, {len(writes)} write requests recorded")
    if failures:
        print(f"xss_check: FAILED, {len(failures)} problem(s):")
        for failure in failures:
            print("  - " + failure)
        return 1
    print("xss_check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
