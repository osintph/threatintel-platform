"""
Who may do what (D-8, AZ-3, AZ-4, AZ-5, AUTH-9, XSS-1 source).

Shared workspace: every signed-in user reads; global settings, crawl control
and deletes are for administrators; project rows can only be deleted through
the project they belong to.
"""

import json

import pytest

from tests.helpers import make_user, sign_in

ADMIN_ONLY = [
    ("POST", "/api/keywords", {"keyword": "x"}),
    ("DELETE", "/api/keywords", {"keyword": "x", "category": "custom"}),
    ("POST", "/api/keywords/bulk", {"keywords": [{"keyword": "x"}]}),
    ("POST", "/api/keywords/import", None),
    ("POST", "/api/seeds", {"url": "http://abcdefghijklmnop.onion/"}),
    ("DELETE", "/api/seeds", {"url": "http://abcdefghijklmnop.onion/"}),
    ("POST", "/api/crawl/start", None),
    ("POST", "/api/crawl/stop", None),
    ("DELETE", "/api/investigations/1", None),
    ("DELETE", "/api/ip-investigations/1", None),
    ("DELETE", "/api/dns/investigations/1", None),
    ("GET", "/api/users", None),
    ("POST", "/api/users", {"username": "new-user", "password": "Correct-Horse-9!"}),
    ("DELETE", "/api/users/1", None),
    ("POST", "/api/users/1/mfa/reset", None),
    ("GET", "/api/admin/auth-events", None),
    ("GET", "/api/digest/subscribers", None),
    ("POST", "/api/digest/subscribers", {"email": "a@example.com"}),
    ("DELETE", "/api/digest/subscribers", {"email": "a@example.com"}),
    ("POST", "/api/digest/send", {}),
]


@pytest.mark.parametrize("method,path,body", ADMIN_ONLY, ids=[f"{m} {p}" for m, p, _ in ADMIN_ONLY])
def test_admin_only_routes_refuse_a_normal_user(client, db, data_dir, method, path, body):
    make_user(db, "boss", admin=True)
    headers = sign_in(client, db, make_user(db, "analyst"))
    resp = client.open(path, method=method, json=body, headers=headers)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json() == {"error": "admin required"}
    assert list(data_dir.iterdir()) == [], "a refused request must not write anything"


@pytest.mark.parametrize(
    "path",
    [
        "/api/stats",
        "/api/keywords",
        "/api/seeds",
        "/api/investigations",
        "/api/dns/investigations",
        "/api/crawl/status",
        "/help",
    ],
)
def test_a_normal_user_can_still_read(client, db, data_dir, path):
    sign_in(client, db, make_user(db, "analyst"))
    assert client.get(path).status_code == 200


def test_admin_can_change_global_settings(client, db, data_dir):
    headers = sign_in(client, db, make_user(db, "boss", admin=True))
    assert (
        client.post(
            "/api/keywords", json={"keyword": "acme corp", "category": "brands"}, headers=headers
        ).status_code
        == 200
    )
    assert client.get("/api/keywords").get_json()["categories"] == {"brands": ["acme corp"]}
    assert (
        client.post(
            "/api/seeds", json={"url": "http://abcdefghijklmnop.onion/"}, headers=headers
        ).status_code
        == 200
    )
    assert client.get("/api/seeds").get_json()["seeds"] == ["http://abcdefghijklmnop.onion/"]


# ── AZ-3: project rows are deleted only through their own project ──────────────


def _two_projects(db):
    boss = make_user(db, "boss", admin=True)
    analyst = make_user(db, "analyst")
    theirs = db.create_project(name="boss project", owner_id=boss)
    mine = db.create_project(name="analyst project", owner_id=analyst)
    return analyst, mine, theirs


def test_project_keyword_delete_is_scoped_to_the_project(client, db):
    analyst, mine, theirs = _two_projects(db)
    foreign = db.add_project_keyword(theirs, "secret-keyword")
    own = db.add_project_keyword(mine, "my-keyword")
    headers = sign_in(client, db, analyst)

    assert (
        client.delete(f"/api/projects/{mine}/keywords/{foreign}", headers=headers).status_code
        == 404
    )
    assert (
        client.delete(f"/api/projects/{theirs}/keywords/{foreign}", headers=headers).status_code
        == 403
    )
    assert [k["keyword"] for k in db.get_project_keywords(theirs)] == ["secret-keyword"]

    assert client.delete(f"/api/projects/{mine}/keywords/{own}", headers=headers).status_code == 200
    assert db.get_project_keywords(mine) == []


def test_project_domain_and_entity_deletes_are_scoped(client, db):
    analyst, mine, theirs = _two_projects(db)
    foreign_domain = db.add_project_domain(theirs, "boss.example")
    foreign_entity = db.add_project_entity(theirs, "person", "Jane Doe")
    headers = sign_in(client, db, analyst)

    assert (
        client.delete(f"/api/projects/{mine}/domains/{foreign_domain}", headers=headers).status_code
        == 404
    )
    assert (
        client.delete(
            f"/api/projects/{mine}/entities/{foreign_entity}", headers=headers
        ).status_code
        == 404
    )
    assert len(db.get_project_domains(theirs)) == 1
    assert len(db.get_project_entities(theirs)) == 1


# ── AUTH-9: strict booleans, clamped parameters ────────────────────────────────


def test_is_admin_must_be_a_real_boolean(client, db):
    headers = sign_in(client, db, make_user(db, "boss", admin=True))
    resp = client.post(
        "/api/users",
        json={"username": "newbie", "password": "Correct-Horse-9!", "is_admin": "false"},
        headers=headers,
    )
    assert resp.status_code == 400
    assert db.get_user_by_username("newbie") is None

    resp = client.post(
        "/api/users",
        json={"username": "newbie", "password": "Correct-Horse-9!", "is_admin": False},
        headers=headers,
    )
    assert resp.status_code == 200
    created = db.get_user_by_username("newbie")
    assert created.is_admin is False and created.must_change_password is True


@pytest.mark.parametrize("query", ["limit=abc", "limit=-1", "limit=99999999999999999999", "limit="])
def test_bad_limit_is_not_a_server_error(client, db, query):
    sign_in(client, db, make_user(db))
    assert client.get(f"/api/hits?{query}").status_code == 200


@pytest.mark.parametrize("payload", ["not json", "[1, 2]", '"text"', "null"])
def test_a_body_that_is_not_a_json_object_is_a_400_not_a_500(client, db, data_dir, payload):
    headers = sign_in(client, db, make_user(db, "boss", admin=True))
    for path in (
        "/api/keywords",
        "/api/seeds",
        "/api/users",
        "/api/dns/investigate",
    ):
        resp = client.post(path, data=payload, content_type="application/json", headers=headers)
        assert resp.status_code == 400, (path, resp.status_code)


def test_admin_cannot_delete_themselves_and_user_admin_is_logged(client, db):
    boss = make_user(db, "boss", admin=True)
    other = make_user(db, "analyst")
    headers = sign_in(client, db, boss)
    assert client.delete(f"/api/users/{boss}", headers=headers).status_code == 400
    assert client.delete(f"/api/users/{other}", headers=headers).status_code == 200
    assert client.delete(f"/api/users/{other}", headers=headers).status_code == 404
    assert db.list_auth_events()[0]["event"] == "user_deleted"


def test_admin_can_reset_a_lost_second_factor(full_app, client, db):
    boss = make_user(db, "boss", admin=True)
    other = make_user(db, "analyst")
    theirs = full_app.test_client()
    sign_in(theirs, db, other)
    headers = sign_in(client, db, boss)

    assert client.post(f"/api/users/{other}/mfa/reset", headers=headers).status_code == 200
    assert db.get_user_by_id(other).totp_enabled is False
    assert theirs.get("/api/stats").status_code == 401  # their sessions ended


# ── Input validation at the door (XSS-1 and XSS-2 sources, AZ-5) ───────────────


HOSTILE = [
    ("/api/seeds", {"url": "javascript:alert(1)"}),
    ("/api/seeds", {"urls": ["http://ok.onion/", 'http://x.onion/"onmouseover="y']}),
    ("/api/keywords", {"keyword": "two\nlines"}),
    ("/api/keywords", {"keyword": "ok", "category": "x' onclick='y"}),
    ("/api/keywords/bulk", {"keywords": [{"keyword": "ok", "category": "<b>"}]}),
    ("/api/digest/subscribers", {"email": "x' data-audit-sub='1"}),
    ("/api/digest/subscribers", {"email": "a@example.com\nb@example.com"}),
    ("/api/dns/investigate", {"domain": '"><img src=x onerror=1>.example'}),
    ("/api/dns/investigate", {"domain": "example.com/path"}),
    ("/api/ip-investigations", {"ip": "1.2.3.4<script>"}),
    ("/api/projects", {"name": "<img src=x onerror=1>"}),
    ("/api/projects", {"name": "ok", "color": "red;background:url(//x)"}),
    ("/api/projects", {"name": "ok", "tags": ["<svg onload=1>"]}),
    (
        "/api/investigations",
        {"name": "<b>x</b>", "targets": [{"value": "a@example.com", "type": "email"}]},
    ),
]


@pytest.mark.parametrize(
    "path,body", HOSTILE, ids=[f"{p} {json.dumps(b)[:40]}" for p, b in HOSTILE]
)
def test_hostile_values_are_refused(client, db, data_dir, path, body):
    headers = sign_in(client, db, make_user(db, "boss", admin=True))
    resp = client.post(path, json=body, headers=headers)
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert list(data_dir.iterdir()) == []
    assert db.list_projects() == []


REMOVED_IN_1_3_0 = [
    ("POST", "/api/digest/subscribe"),  # D-9, AZ-5: the public subscribe form
    ("POST", "/api/send-brief"),  # D-9: was never registered
    ("GET", "/api/paste/hits"),  # D-10: paste monitor
    ("GET", "/api/paste/stats"),
    ("POST", "/api/paste/scan"),
    ("GET", "/api/seeds/paste"),  # REL-9: lists that nothing read
    ("POST", "/api/seeds/paste"),
    ("GET", "/api/seeds/clearnet"),
    ("POST", "/api/seeds/clearnet"),
    ("GET", "/api/telegram/channels"),
    ("POST", "/api/telegram/channels"),
]


@pytest.mark.parametrize("method,path", REMOVED_IN_1_3_0, ids=[f"{m} {p}" for m, p in REMOVED_IN_1_3_0])
def test_removed_routes_are_gone(client, db, data_dir, method, path):
    headers = sign_in(client, db, make_user(db, "boss", admin=True))
    resp = client.open(path, method=method, json={"email": "a@example.com"}, headers=headers)
    assert resp.status_code == 404, resp.get_data(as_text=True)
    assert list(data_dir.iterdir()) == []


def test_nothing_is_exempt_from_the_csrf_check(full_app):
    """AZ-5: the one exemption was the public subscribe form, which is gone."""
    from darkweb_scanner.dashboard import app as app_module

    assert not hasattr(app_module, "CSRF_EXEMPT_ENDPOINTS")
    client = full_app.test_client()
    for path in ("/api/digest/subscribe", "/api/digest/subscribers", "/api/keywords"):
        resp = client.post(path, json={"email": "a@example.com"})
        assert resp.status_code == 403 and resp.get_json()["error"] == "csrf", path


def test_project_fields_are_stored_validated(client, db):
    headers = sign_in(client, db, make_user(db))
    resp = client.post(
        "/api/projects",
        json={
            "name": "  O'Brien & Sons  ",
            "description": "line one\nline two",
            "alert_threshold": "abc",
            "tags": ["a"],
        },
        headers=headers,
    )
    assert resp.status_code == 200
    project = db.get_project(resp.get_json()["id"])
    assert project["name"] == "O'Brien & Sons"
    assert project["alert_threshold"] == 1
    pid = project["id"]
    assert (
        client.put(f"/api/projects/{pid}", json={"name": "<script>"}, headers=headers).status_code
        == 400
    )
    assert (
        client.put(f"/api/projects/{pid}", json={"owner_id": 99}, headers=headers).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/projects/{pid}/keywords",
            json={"keyword": "(", "is_regex": True},
            headers=headers,
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/projects/{pid}/keywords",
            json={"keyword": "x", "is_regex": "false"},
            headers=headers,
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/projects/{pid}/domains", json={"domain": "not a domain"}, headers=headers
        ).status_code
        == 400
    )


# ── ThreatFox relay: one fixed query (AZ-4) ────────────────────────────────────


def test_threatfox_relay_sends_only_the_recent_ioc_query(client, db, monkeypatch):
    from darkweb_scanner.dashboard import dashboard_routes as dr

    sent = []

    def fake_fetch(url, **kwargs):
        sent.append((url, kwargs.get("data")))
        return {"status": 200, "headers": {}, "body": b'{"query_status":"ok"}', "url": url}

    monkeypatch.setattr(dr, "safe_fetch", fake_fetch)
    headers = sign_in(client, db, make_user(db))

    for body in (
        {"query": "search_ioc", "search_term": "x"},
        {"query": "submit_ioc"},
        {},
        {"query": ["get_iocs"]},
    ):
        assert client.post("/api/proxy/threatfox", json=body, headers=headers).status_code == 400
    assert sent == []

    assert (
        client.post(
            "/api/proxy/threatfox",
            json={"query": "get_iocs", "days": 9999, "extra": "x"},
            headers=headers,
        ).status_code
        == 200
    )
    assert sent == [("https://threatfox-api.abuse.ch/api/v1/", b'{"query": "get_iocs", "days": 7}')]
