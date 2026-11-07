"""
REL-4: which crawl is running is in the database (owner and heartbeat), a
crawl whose process is gone ends as interrupted, the stop flag is only cleared
once a new crawl owns the session, Tor being down is an answer and not an
exit, and the crawl routes do not send exception text to the browser.
"""

import asyncio
import json
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from darkweb_scanner import crawler as crawler_mod
from darkweb_scanner import main
from darkweb_scanner.crawler import CrawlAlreadyRunning, CrawlConfig, CrawlResult, crawl_owner
from darkweb_scanner.scanner import KeywordConfig
from darkweb_scanner.storage import CrawlSession, _utcnow
from darkweb_scanner.tor_client import TorNotReachable
from tests.helpers import make_user, sign_in

SEED = "http://aaaaaaaaaaaaaaaaaaaaaaaaaa.onion/"


def _row(db, session_id):
    with db.get_session() as s:
        r = s.get(CrawlSession, session_id)
        return {"status": r.status, "owner": r.owner, "heartbeat_at": r.heartbeat_at, "error": r.error}


def _running_session(db, owner, beat_age_seconds):
    sid = db.create_crawl_session([SEED], owner=owner)
    with db.get_session() as s:
        s.get(CrawlSession, sid).heartbeat_at = _utcnow() - timedelta(seconds=beat_age_seconds)
        s.commit()
    return sid


def _admin(client, db):
    return sign_in(client, db, make_user(db, username="admin", admin=True))


def _files(data_dir):
    (data_dir / "seeds.txt").write_text(SEED + "\n")
    (data_dir / "keywords.yaml").write_text("keywords:\n  custom:\n    - acme\n")


class _SlowCrawler:
    """Yields two pages with a pause, long enough for a few heartbeats."""

    def __init__(self, *args, **kwargs):
        self.stop_requested = False
        self.halted = False

    def halt(self):
        self.halted = True

    async def crawl(self, seeds):
        for i in range(2):
            await asyncio.sleep(0.3)
            yield CrawlResult(url=f"{SEED}{i}", status_code=200, html="", text="nothing", links=[], depth=0)


def _run(db, **kwargs):
    tor = AsyncMock()
    with (
        patch("darkweb_scanner.main.create_tor_client", return_value=tor),
        patch("darkweb_scanner.main.Crawler", _SlowCrawler),
    ):
        return asyncio.run(
            main.run_scan(
                seeds=[SEED], keyword_config=KeywordConfig.from_list(["acme"]),
                crawl_config=CrawlConfig(), storage=db, alerter=MagicMock(), check_tor=False, **kwargs,
            )
        )


# ── Claim and heartbeat ───────────────────────────────────────────────────────


def test_a_crawl_claims_its_session_and_keeps_a_heartbeat(db, monkeypatch):
    monkeypatch.setattr(main, "HEARTBEAT_SECONDS", 0.05)
    beats = []
    real = db.heartbeat_crawl_session

    def spy(session_id, *a, **kw):
        beats.append(_row(db, session_id)["owner"])
        return real(session_id, *a, **kw)

    monkeypatch.setattr(db, "heartbeat_crawl_session", spy)
    result = _run(db)
    assert result["pages_crawled"] == 2
    with db.get_session() as s:
        row = s.query(CrawlSession).order_by(CrawlSession.id.desc()).first()
        assert row.owner == crawl_owner()
        assert row.status == "completed"
        assert row.heartbeat_at is not None
    assert len(beats) >= 3 and set(beats) == {crawl_owner()}
    assert not crawler_mod.local_crawl_running()


def test_a_second_crawl_is_refused_while_one_is_running(db):
    _running_session(db, "scanner-host:7", beat_age_seconds=1)
    with pytest.raises(CrawlAlreadyRunning):
        _run(db)
    assert not crawler_mod.local_crawl_running()


def test_a_crawl_ended_elsewhere_stops_and_keeps_interrupted(db, monkeypatch):
    monkeypatch.setattr(main, "HEARTBEAT_SECONDS", 0.05)
    sid = db.create_crawl_session([SEED], owner=crawl_owner())
    with db.get_session() as s:
        s.get(CrawlSession, sid).status = "interrupted"
        s.commit()
    _run(db, session_id=sid)
    assert _row(db, sid)["status"] == "interrupted"


# ── Stale sessions ────────────────────────────────────────────────────────────


def test_status_ends_a_stale_session_as_interrupted_not_completed(client, db, data_dir):
    _admin(client, db)
    sid = _running_session(db, "gone-host:42", beat_age_seconds=crawler_mod.STALE_SECONDS + 60)
    body = client.get("/api/crawl/status").get_json()
    assert body["active"] is False
    row = _row(db, sid)
    assert row["status"] == "interrupted"
    assert "gone-host:42" in row["error"]
    assert body["last_session"]["status"] == "interrupted"


def test_status_leaves_a_live_crawl_of_another_process_running(client, db, data_dir):
    _admin(client, db)
    sid = _running_session(db, "scanner-host:7", beat_age_seconds=1)
    body = client.get("/api/crawl/status").get_json()
    assert body["active"] is True and body["session"]["id"] == sid
    assert _row(db, sid)["status"] == "running"


def test_status_ends_this_process_s_old_session_after_a_restart(client, db, data_dir):
    # Same host:pid as before the restart, heartbeat still fresh, no crawl running here.
    _admin(client, db)
    sid = _running_session(db, crawl_owner(), beat_age_seconds=1)
    client.get("/api/crawl/status")
    assert _row(db, sid)["status"] == "interrupted"


# ── Start: order of checks, Tor ───────────────────────────────────────────────


def test_start_while_running_leaves_the_stop_flag(client, db, data_dir):
    headers = _admin(client, db)
    _files(data_dir)
    _running_session(db, "scanner-host:7", beat_age_seconds=1)
    flag = data_dir / "crawl.stop"
    flag.write_text("stop requested")
    with patch("darkweb_scanner.tor_client.tor_reachable") as tor:
        resp = client.post("/api/crawl/start", headers=headers)
    assert resp.status_code == 409
    assert flag.exists()  # the running crawl still gets its stop request
    tor.assert_not_called()


def test_start_clears_a_stale_stop_flag_once_it_owns_the_session(client, db, data_dir, monkeypatch):
    headers = _admin(client, db)
    _files(data_dir)
    flag = data_dir / "crawl.stop"
    flag.write_text("left from an earlier crawl")
    started = []
    monkeypatch.setattr("darkweb_scanner.tor_client.tor_reachable", lambda timeout=None: True)
    monkeypatch.setattr("threading.Thread.start", lambda self: started.append(self.name))
    try:
        resp = client.post("/api/crawl/start", headers=headers)
        assert resp.status_code == 200
        sid = resp.get_json()["session_id"]
        assert not flag.exists()
        assert started == ["crawl_thread"]
        row = _row(db, sid)
        assert row["status"] == "running" and row["owner"] == crawl_owner()
    finally:
        crawler_mod.release_local_crawl()


def test_start_with_tor_down_is_a_clear_answer(client, db, data_dir, monkeypatch):
    headers = _admin(client, db)
    _files(data_dir)
    monkeypatch.setattr("darkweb_scanner.tor_client.tor_reachable", lambda timeout=None: False)
    resp = client.post("/api/crawl/start", headers=headers)
    assert resp.status_code == 503
    assert "Tor is not reachable" in resp.get_json()["error"]
    with db.get_session() as s:
        assert s.query(CrawlSession).count() == 0
    assert not crawler_mod.local_crawl_running()


def test_run_scan_with_tor_down_raises_and_does_not_exit(db):
    sid = db.create_crawl_session([SEED], owner=crawl_owner())
    tor = AsyncMock()
    tor.check_connectivity.return_value = False
    with patch("darkweb_scanner.main.create_tor_client", return_value=tor):
        with pytest.raises(TorNotReachable):  # SystemExit would not match
            asyncio.run(
                main.run_scan(
                    seeds=[SEED], keyword_config=KeywordConfig.from_list(["acme"]),
                    crawl_config=CrawlConfig(), storage=db, alerter=MagicMock(),
                    check_tor=True, session_id=sid,
                )
            )
    row = _row(db, sid)
    assert row["status"] == "failed" and row["error"] == main.TOR_DOWN_MESSAGE
    tor.close.assert_awaited()


def test_no_sys_exit_in_the_crawl_path():
    import inspect

    assert "sys.exit" not in inspect.getsource(main.run_scan)
    assert "sys.exit" not in inspect.getsource(main._heartbeat)


# ── Error answers ─────────────────────────────────────────────────────────────

SECRET = "psycopg2.OperationalError at /app/data/secret-path"


def test_status_error_has_no_exception_text(client, db, data_dir, monkeypatch):
    _admin(client, db)
    monkeypatch.setattr(db, "get_stats", lambda: (_ for _ in ()).throw(RuntimeError(SECRET)))
    resp = client.get("/api/crawl/status")
    assert resp.status_code == 500
    body = resp.get_json()
    assert SECRET not in json.dumps(body) and "psycopg2" not in json.dumps(body)
    assert body["error_id"]


def test_stop_error_has_no_exception_text(client, db, data_dir, monkeypatch):
    headers = _admin(client, db)
    from darkweb_scanner.dashboard import dashboard_routes as dr

    class _Unwritable:
        def write_text(self, *_):
            raise OSError(SECRET)

    monkeypatch.setattr(dr, "STOP_FLAG", _Unwritable())
    resp = client.post("/api/crawl/stop", headers=headers)
    assert resp.status_code == 500
    body = resp.get_json()
    assert SECRET not in json.dumps(body)
    assert body["error"] == "The stop signal could not be written."
