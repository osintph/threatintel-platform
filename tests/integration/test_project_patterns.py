"""
REL-3: project keyword patterns are checked when they are saved and again
before the crawl runs them, and they only ever see clipped text.
"""

import logging
import time

import pytest

from darkweb_scanner import main, regex_safety
from tests.helpers import make_user, sign_in


@pytest.fixture(autouse=True)
def _fresh_pattern_state():
    main._pattern_refusal.cache_clear()
    main._skipped_patterns.clear()
    regex_safety.compile_checked.cache_clear()
    yield


def _project(db, owner_id=None):
    owner_id = owner_id or make_user(db)
    return db.create_project(name="Bank watch", owner_id=owner_id), owner_id


def _add(client, headers, pid, pattern):
    return client.post(
        f"/api/projects/{pid}/keywords",
        json={"keyword": pattern, "is_regex": True},
        headers=headers,
    )


# ── At save ───────────────────────────────────────────────────────────────────


def test_a_safe_pattern_is_saved(client, db):
    uid = make_user(db)
    headers = sign_in(client, db, uid)
    pid, _ = _project(db, uid)
    resp = _add(client, headers, pid, r"\bbdo\b|\bbpi\b")
    assert resp.status_code == 200
    assert [k["keyword"] for k in db.get_project_keywords(pid)] == [r"\bbdo\b|\bbpi\b"]


@pytest.mark.parametrize(
    "pattern, reason",
    [
        ("(a+)+$", "overlap"),
        (r"(\w+\s?)+x", "overlap"),
        ("(a|aa)+c", "alternatives"),
        (r"(a)\1", "back-reference"),
        ("a" * (regex_safety.MAX_PATTERN_LENGTH + 1), "longer than"),
        ("(", "not a valid regular expression"),
    ],
)
def test_an_unsafe_pattern_is_refused_at_save(client, db, pattern, reason):
    uid = make_user(db)
    headers = sign_in(client, db, uid)
    pid, _ = _project(db, uid)
    resp = _add(client, headers, pid, pattern)
    assert resp.status_code == 400
    error = resp.get_json()["error"]
    assert db.get_project_keywords(pid) == []
    if reason == "longer than":
        # The keyword validator caps every keyword at the same length first.
        assert "too long" in error
        return
    assert error.startswith("The pattern is not accepted: ")
    # The reason is plain text from regex_safety, never a traceback.
    assert "Traceback" not in error and "re.error" not in error
    if reason == "not a valid regular expression":
        assert reason in error


# ── At crawl time ─────────────────────────────────────────────────────────────


def _hit(db, context):
    sid = db.create_crawl_session(["http://aaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"])
    return db.save_hit(
        url="http://aaaaaaaaaaaaaaaaaaaaaaaaaa.onion/p", keyword="acme", category="custom",
        context=context, position=0, depth=0, session_id=sid,
    )


def test_a_safe_stored_pattern_matches_at_crawl_time(db):
    pid, _ = _project(db)
    db.add_project_keyword(pid, r"acme\s+bank", is_regex=True)
    hit_id = _hit(db, "leak of acme  bank records")
    main.match_hit_to_projects(hit_id, "http://x.onion/p", "acme", "leak of acme  bank records", db)
    assert [h["hit_id"] for h in db.get_project_hits(pid)] == [hit_id]


def test_an_unsafe_stored_pattern_is_skipped_without_stalling(db, caplog):
    # Saved before 1.3.0, when only re.compile() was checked.
    pid, _ = _project(db)
    db.add_project_keyword(pid, "(a+)+$", is_regex=True)
    db.add_project_keyword(pid, "needle", is_regex=True)
    context = "a" * 40 + "! needle"  # (a+)+$ backtracks for minutes on this
    hit_id = _hit(db, context)

    caplog.set_level(logging.WARNING, logger="darkweb_scanner.main")
    started = time.monotonic()
    for _ in range(3):
        main.match_hit_to_projects(hit_id, "http://x.onion/p", "acme", context, db)
    assert time.monotonic() - started < 2

    # The other pattern of the project still matched.
    assert db.get_project_hits(pid)
    warnings = [r.getMessage() for r in caplog.records if "skipping keyword pattern" in r.getMessage()]
    assert len(warnings) == 1  # once per project and pattern, not per hit
    assert "Bank watch" in warnings[0] and "(a+)+$" in warnings[0]


def test_patterns_see_clipped_text_only(db, monkeypatch):
    seen = []

    class _Recorder:
        def search(self, text):
            seen.append(len(text))
            return "needle" in text

    monkeypatch.setattr(regex_safety, "compile_checked", lambda pattern: _Recorder())
    pid, _ = _project(db)
    db.add_project_keyword(pid, "needle", is_regex=True)
    context = "x" * 50_000 + "needle" + "y" * 50_000
    hit_id = _hit(db, context[:1000])
    main.match_hit_to_projects(hit_id, "http://x.onion/p", "acme", context, db)
    assert seen == [regex_safety.MAX_MATCH_TEXT]
    # The keyword at the centre of the context is inside the clipped text.
    assert db.get_project_hits(pid)


def test_text_far_from_the_centre_is_not_searched(db):
    pid, _ = _project(db)
    db.add_project_keyword(pid, "needle", is_regex=True)
    context = "needle" + "x" * 50_000
    hit_id = _hit(db, context[:1000])
    main.match_hit_to_projects(hit_id, "http://x.onion/p", "acme", context, db)
    assert db.get_project_hits(pid) == []
