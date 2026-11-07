"""
Limits on work that runs long or fans out.

The dashboard is one process with eight request threads. Three things keep one
user from pinning it:

  * JobLimiter: at most HEAVY_JOBS_MAX heavy operations at once in the whole
    process and HEAVY_JOBS_PER_USER per user. Over the limit the answer comes
    at once: 429 with Retry-After.
  * fan_out(): an operation that makes many calls runs them on ONE shared pool
    of FANOUT_WORKERS threads, a few at a time and with a time limit. No
    operation starts threads of its own.
  * RateWindow / PacedQueue: a third-party rate limit is never waited out in a
    request thread. The request path asks try_take() and moves on; calls that
    have to wait run on the queue's own thread.

A background job (DNS recon, Quick Scan, a breach check with rate-limited
calls) runs on its own thread, started with start_background(). It keeps its
limiter slot until it ends, so there are never more than HEAVY_JOBS_MAX of them.

All state is in this process: the app runs as exactly one gunicorn worker.
"""

import logging
import os
import queue
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait
from functools import wraps
from typing import Any, Callable, Hashable, Iterable, Optional

logger = logging.getLogger(__name__)

RETRY_AFTER_SECONDS = 15


def env_int(name: str, default: int, low: int = 1, high: int = 256) -> int:
    try:
        value = int(os.getenv(name, "") or default)
    except ValueError:
        value = default
    return max(low, min(high, value))


# ── Heavy operations: how many at once ─────────────────────────────────────────


class Busy(Exception):
    """No slot is free. ``message`` is written for the user."""

    def __init__(self, message: str, retry_after: int = RETRY_AFTER_SECONDS):
        super().__init__(message)
        self.message = message
        self.retry_after = retry_after


class Slot:
    """One running heavy operation. release() may be called more than once."""

    def __init__(self, limiter: "JobLimiter", user: Hashable):
        self._limiter = limiter
        self._user = user
        self._released = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._limiter._release(self._user)

    def __enter__(self) -> "Slot":
        return self

    def __exit__(self, *exc_info) -> None:
        self.release()


class JobLimiter:
    """Counts running heavy operations, in total and per user.

    The limits come from HEAVY_JOBS_MAX (default 4) and HEAVY_JOBS_PER_USER
    (default 2) unless given here.
    """

    def __init__(self, max_total: Optional[int] = None, max_per_user: Optional[int] = None):
        self._max_total = max_total
        self._max_per_user = max_per_user
        self._lock = threading.Lock()
        self._total = 0
        self._per_user: dict = {}

    @property
    def max_total(self) -> int:
        return self._max_total or env_int("HEAVY_JOBS_MAX", 4)

    @property
    def max_per_user(self) -> int:
        return self._max_per_user or env_int("HEAVY_JOBS_PER_USER", 2)

    def acquire(self, user: Hashable) -> Slot:
        """Take a slot for ``user`` or raise Busy. Never waits."""
        with self._lock:
            mine = self._per_user.get(user, 0)
            if mine >= self.max_per_user:
                raise Busy(
                    f"You already have {mine} long requests running. Wait for one to finish and try again."
                )
            if self._total >= self.max_total:
                raise Busy("The server is busy with other long requests. Try again in a moment.")
            self._total += 1
            self._per_user[user] = mine + 1
        return Slot(self, user)

    def _release(self, user: Hashable) -> None:
        with self._lock:
            self._total = max(0, self._total - 1)
            left = self._per_user.get(user, 0) - 1
            if left > 0:
                self._per_user[user] = left
            else:
                self._per_user.pop(user, None)

    def running(self, user: Hashable = None) -> int:
        with self._lock:
            return self._total if user is None else self._per_user.get(user, 0)


limiter = JobLimiter()


def acquire_slot() -> Slot:
    """A slot for the signed-in user of the current request, or Busy."""
    from ..auth import current_user_id

    return limiter.acquire(current_user_id())


def heavy(f):
    """Route decorator: the handler runs inside a limiter slot. Goes below require_login."""

    @wraps(f)
    def decorated(*args, **kwargs):
        with acquire_slot():
            return f(*args, **kwargs)

    return decorated


def busy_answer(err: Busy, **extra):
    """The 429 answer for Busy. Blueprints register it as their handler for that exception.

    ``extra`` adds fields the blueprint's answers always carry (``ok``).
    """
    from flask import jsonify

    response = jsonify({**extra, "error": err.message})
    response.status_code = 429
    response.headers["Retry-After"] = str(err.retry_after)
    return response


def start_background(fn: Callable[[], Any], slot: Optional[Slot] = None, name: str = "job") -> None:
    """Run fn() on its own daemon thread and release ``slot`` when it ends, however it ends."""

    def run():
        try:
            fn()
        except Exception:
            logger.exception("background job %s failed", name)
        finally:
            if slot is not None:
                slot.release()

    try:
        threading.Thread(target=run, daemon=True, name=name).start()
    except BaseException:
        if slot is not None:
            slot.release()
        raise


# ── Fan-out: one shared pool ───────────────────────────────────────────────────

_pool: Optional[ThreadPoolExecutor] = None
_pool_lock = threading.Lock()
_worker = threading.local()


def _executor() -> ThreadPoolExecutor:
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ThreadPoolExecutor(
                    max_workers=env_int("FANOUT_WORKERS", 24, low=2), thread_name_prefix="fanout"
                )
    return _pool


def fan_out(fn: Callable[[Any], Any], items: Iterable, *, parallel: int = 8,
            timeout: Optional[float] = None, default: Any = None) -> list:
    """fn(item) for every item, on the shared pool. Returns the results in item order.

    At most ``parallel`` of this call's items are in the pool at a time, so one
    operation cannot take every worker. ``timeout`` is for the whole call:
    items that have not finished by then (or raised) give ``default``, and
    those that have not started are dropped.

    Work running in the pool must not wait for the pool: a call made from a
    pool thread runs its items in that thread, one after the other.
    """
    items = list(items)
    if not items:
        return []
    deadline = None if timeout is None else time.monotonic() + timeout

    def left() -> Optional[float]:
        return None if deadline is None else max(0.0, deadline - time.monotonic())

    def call(item):
        try:
            return fn(item)
        except Exception:
            logger.debug("fan_out: %r failed for %r", getattr(fn, "__name__", fn), item, exc_info=True)
            return default

    if len(items) == 1 or getattr(_worker, "busy", False):
        results = []
        for item in items:
            results.append(default if left() == 0.0 else call(item))
        return results

    results = [default] * len(items)
    gate = threading.Semaphore(max(1, parallel))

    def run(index: int, item) -> None:
        _worker.busy = True
        try:
            results[index] = call(item)
        finally:
            _worker.busy = False
            gate.release()

    futures = []
    pool = _executor()
    for index, item in enumerate(items):
        remaining = left()
        if remaining == 0.0 or not gate.acquire(timeout=remaining):
            break
        futures.append(pool.submit(run, index, item))
    wait(futures, timeout=left())
    for future in futures:
        future.cancel()
    # A copy: a call that ends after the time limit must not change what was returned.
    return list(results)


def call_all(calls: dict, *, timeout: Optional[float] = None, default: Any = None) -> dict:
    """Run independent calls ({name: function}) side by side. Returns {name: result}."""
    names = list(calls)
    results = fan_out(lambda name: calls[name](), names, parallel=len(names), timeout=timeout, default=default)
    return dict(zip(names, results))


# ── Third-party rate limits ────────────────────────────────────────────────────


def _in_request() -> bool:
    try:
        from flask import has_request_context

        return has_request_context()
    except ImportError:
        return False


class RateWindow:
    """At most ``max_calls`` calls in any ``per`` seconds, counted in this process."""

    def __init__(self, max_calls: int, per: float = 60.0):
        self.max_calls = max(1, max_calls)
        self.per = per
        self._calls: deque = deque()
        self._lock = threading.Lock()

    def _expire(self, now: float) -> None:
        while self._calls and now - self._calls[0] >= self.per:
            self._calls.popleft()

    def try_take(self) -> bool:
        """Count one call if the limit allows it. Never waits."""
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            if len(self._calls) >= self.max_calls:
                return False
            self._calls.append(now)
            return True

    def seconds_until_free(self) -> float:
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            if len(self._calls) < self.max_calls:
                return 0.0
            return max(0.0, self.per - (now - self._calls[0]))

    def wait_take(self, give_up: Optional[threading.Event] = None) -> bool:
        """Wait until a call is allowed, then count it. For background threads only."""
        if _in_request():
            raise RuntimeError("a rate limit must not be waited out in a request thread")
        give_up = give_up or threading.Event()
        while not self.try_take():
            if give_up.wait(min(1.0, max(0.05, self.seconds_until_free()))):
                return False
        return True


class PacedQueue:
    """Rate-limited calls, run one at a time on one daemon thread.

    submit() never waits: it queues the call, or answers False when
    ``max_pending`` calls are already waiting. The thread takes each call's
    turn from ``window`` before it runs it.
    """

    def __init__(self, name: str, window: RateWindow, max_pending: int = 40):
        self.name = name
        self.window = window
        self._queue: queue.Queue = queue.Queue(maxsize=max_pending)
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def submit(self, fn: Callable[[], Any]) -> bool:
        try:
            self._queue.put_nowait(fn)
        except queue.Full:
            return False
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, daemon=True, name=f"paced-{self.name}")
                self._thread.start()
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            fn = self._queue.get()
            try:
                if self.window.wait_take(self._stop):
                    fn()
            except Exception:
                logger.exception("paced queue %s: a call failed", self.name)
            finally:
                self._queue.task_done()

    def pending(self) -> int:
        return self._queue.unfinished_tasks

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """True once every submitted call has run. For tests."""
        end = time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if time.monotonic() >= end:
                return False
            self._stop.wait(0.01)
        return True
