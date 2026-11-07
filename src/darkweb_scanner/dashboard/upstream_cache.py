"""
In-process cache for answers from third-party services.

    value = cache.get(key, fetch)

  * An answer is reused for ``ttl`` seconds.
  * One fetch at a time per key. While it runs, other callers get the last
    good answer if there is one, and wait for the fetch if there is none.
  * When the fetch fails (it raises), the last good answer is served for up
    to ``stale_for`` seconds, and the service is left alone for ``error_ttl``
    seconds: an outage costs one failed call per key per minute, not one per
    page load.

The cache lives in this process and is empty after a restart. The app runs as
one gunicorn worker, so there is one copy.
"""

import copy
import logging
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Hashable, Optional

logger = logging.getLogger(__name__)

_caches: list = []


def default_ttl() -> int:
    """UPSTREAM_CACHE_SECONDS: how long an upstream answer is reused (default 300, 0 to 86400)."""
    try:
        value = int(os.getenv("UPSTREAM_CACHE_SECONDS", "") or 300)
    except ValueError:
        value = 300
    return max(0, min(86400, value))


class _Entry:
    __slots__ = ("value", "has_value", "fetched_at", "failed_at", "flight")

    def __init__(self):
        self.value = None
        self.has_value = False
        self.fetched_at = 0.0
        self.failed_at: Optional[float] = None
        self.flight: Optional[threading.Event] = None


class TTLCache:
    def __init__(self, name: str, ttl: float, *, stale_for: float = 86400, error_ttl: float = 60,
                 max_entries: int = 256, wait_timeout: float = 30, copy_values: bool = True,
                 clock: Callable[[], float] = time.monotonic):
        self.name = name
        self.ttl = ttl
        self.stale_for = stale_for
        self.error_ttl = error_ttl
        self.max_entries = max_entries
        self.wait_timeout = wait_timeout
        self.copy_values = copy_values
        self._clock = clock
        self._entries: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self.hits = self.fetches = self.failures = self.stale_served = 0
        _caches.append(self)

    def _out(self, value):
        # Callers add fields to what they get; the cached answer must not change under them.
        return copy.deepcopy(value) if self.copy_values else value

    def _stale(self, entry: _Entry, now: float, default):
        """The last good answer if it is still usable, else ``default``. Lock held."""
        if entry.has_value and now - entry.fetched_at < self.ttl + self.stale_for:
            self.stale_served += 1
            return self._out(entry.value)
        return default

    def get(self, key: Hashable, fetch: Callable[[], Any], default: Any = None) -> Any:
        """The cached answer for ``key``, fetched with ``fetch()`` when there is none in date.

        ``fetch`` raises when the upstream fails. Then the last good answer is
        returned, or ``default`` when there is none.
        """
        with self._lock:
            now = self._clock()
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _Entry()
                while len(self._entries) > self.max_entries:
                    oldest = next(iter(self._entries))
                    if self._entries[oldest].flight is not None:
                        break
                    del self._entries[oldest]
            self._entries.move_to_end(key)
            if entry.has_value and now - entry.fetched_at < self.ttl:
                self.hits += 1
                return self._out(entry.value)
            if entry.failed_at is not None and now - entry.failed_at < self.error_ttl:
                return self._stale(entry, now, default)
            flight = entry.flight
            if flight is not None and entry.has_value:
                return self._stale(entry, now, default)
            if flight is None:
                entry.flight = threading.Event()

        if flight is not None:
            # Someone else is fetching this key and there is nothing to serve yet.
            flight.wait(self.wait_timeout)
            with self._lock:
                now = self._clock()
                if entry.has_value and now - entry.fetched_at < self.ttl:
                    return self._out(entry.value)
                return self._stale(entry, now, default)

        try:
            value = fetch()
        except Exception as exc:
            with self._lock:
                self.failures += 1
                now = self._clock()
                entry.failed_at = now
                answer = self._stale(entry, now, default)
                served_stale = entry.has_value and answer is not default
                done, entry.flight = entry.flight, None
            logger.warning(
                "%s: fetch failed (%s: %s); %s", self.name, type(exc).__name__, exc,
                "serving the last good answer" if served_stale else "nothing cached to serve",
            )
            done.set()
            return answer
        except BaseException:
            with self._lock:
                done, entry.flight = entry.flight, None
            done.set()
            raise
        with self._lock:
            self.fetches += 1
            entry.value = value
            entry.has_value = True
            entry.fetched_at = self._clock()
            entry.failed_at = None
            done, entry.flight = entry.flight, None
        done.set()
        return self._out(value)

    def peek(self, key: Hashable) -> Any:
        """The answer for ``key`` if one in date is cached, else None. Never fetches."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry.has_value and self._clock() - entry.fetched_at < self.ttl:
                self.hits += 1
                return self._out(entry.value)
            return None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self.hits = self.fetches = self.failures = self.stale_served = 0


def clear_all() -> None:
    """Empty every cache. For tests."""
    for cache in list(_caches):
        cache.clear()
