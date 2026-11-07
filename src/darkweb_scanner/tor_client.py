"""
Tor client manager — handles session creation, circuit rotation, and connectivity checks.

There is no Tor control port. A new circuit is obtained by opening a session
with fresh SOCKS credentials: Tor keeps streams with different SOCKS user names
on different circuits (IsolateSOCKSAuth, on by default).

fetch_page() is the one way the crawler and Quick Scan read a page: the body
is read up to a byte cap, and a redirect is only followed to another .onion
address.
"""

import asyncio
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp_socks import ProxyConnector

logger = logging.getLogger(__name__)


def _env_number(name: str, default: float, minimum: float) -> float:
    try:
        return max(minimum, float(os.getenv(name, "") or default))
    except ValueError:
        logger.warning("%s is not a number; using %s", name, default)
        return default


# Most bytes read from one response body (after decompression). The rest is not read.
MAX_PAGE_BYTES = int(_env_number("MAX_PAGE_BYTES", 2 * 1024 * 1024, 1024))
MAX_REDIRECTS = 5
# Longest a caller waits for the "is Tor reachable" answer before a crawl starts.
TOR_CHECK_TIMEOUT = _env_number("TOR_CHECK_TIMEOUT", 15, 1)

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class TorNotReachable(RuntimeError):
    """Tor did not answer, or the answer did not come through Tor."""


class RedirectRefused(Exception):
    """A page redirected to an address that is not fetched."""


@dataclass
class FetchedPage:
    url: str  # after redirects
    status: int
    content_type: str
    text: str
    truncated: bool = False  # the body was longer than the cap
    skipped: bool = False  # the content type was not wanted; the body was not read


def is_onion_url(url: str) -> bool:
    """An http(s) URL whose host is a .onion name."""
    try:
        parts = urlparse(url)
        host = parts.hostname or ""
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and host.lower().endswith(".onion")


async def read_capped(resp, limit: int) -> tuple[bytes, bool]:
    """Read at most ``limit`` bytes of a response body. Returns (body, truncated)."""
    chunks = []
    size = 0
    async for chunk in resp.content.iter_chunked(64 * 1024):
        room = limit - size
        if len(chunk) > room:
            chunks.append(chunk[:room])
            return b"".join(chunks), True
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks), False


def _decode(body: bytes, charset: Optional[str]) -> str:
    try:
        return body.decode(charset or "utf-8", errors="replace")
    except (LookupError, ValueError):
        return body.decode("utf-8", errors="replace")


async def fetch_page(
    session,
    url: str,
    *,
    max_bytes: Optional[int] = None,
    timeout=None,
    content_types: Optional[tuple] = None,
    onion_only: bool = True,
) -> FetchedPage:
    """GET ``url`` through ``session`` (a Tor session) with a capped body.

    onion_only (the default): the URL and every redirect target must be a
    .onion address; anything else raises RedirectRefused and is not requested.
    Without it (a clearnet source, still through Tor) the certificate is
    checked and no redirect is followed at all.

    content_types: when given, a response of another type is returned with
    ``skipped`` set and its body unread.
    """
    limit = MAX_PAGE_BYTES if max_bytes is None else max_bytes
    kwargs: dict = {"allow_redirects": False}
    if onion_only:
        # An onion address authenticates the service; its certificate, if any, is self-signed.
        kwargs["ssl"] = False
    if timeout is not None:
        kwargs["timeout"] = timeout
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        if onion_only and not is_onion_url(current):
            raise RedirectRefused("Not an .onion address; not fetched")
        async with session.get(current, **kwargs) as resp:
            location = resp.headers.get("Location")
            if onion_only and resp.status in _REDIRECT_STATUSES and location:
                target = urljoin(current, location)
                if not is_onion_url(target):
                    raise RedirectRefused("Redirect to an address that is not .onion; not followed")
                current = target
                continue
            content_type = resp.headers.get("Content-Type", "")
            if content_types and not any(ct in content_type for ct in content_types):
                return FetchedPage(current, resp.status, content_type, "", skipped=True)
            body, truncated = await read_capped(resp, limit)
            if truncated:
                logger.info("Body of %s cut at %d bytes", current, limit)
            text = _decode(body, getattr(resp, "charset", None))
            return FetchedPage(current, resp.status, content_type, text, truncated=truncated)
    raise RedirectRefused("Too many redirects")


class TorClient:
    """Manages aiohttp sessions routed through the Tor SOCKS5 proxy."""

    def __init__(
        self,
        socks_host: str = "tor",
        socks_port: int = 9050,
        request_timeout: int = 30,
    ):
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.request_timeout = request_timeout
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_rotation: float = 0
        # SOCKS user name of the current circuit group; not a secret, Tor only compares it.
        self._isolation = secrets.token_hex(8)
        # Sessions of earlier circuits, waiting for their last requests to finish.
        self._retiring: dict[asyncio.Task, aiohttp.ClientSession] = {}

    def _proxy_url(self) -> str:
        return f"socks5://{self._isolation}:x@{self.socks_host}:{self.socks_port}"

    def _make_connector(self) -> ProxyConnector:
        return ProxyConnector.from_url(
            self._proxy_url(),
            rdns=True,  # resolve DNS through Tor
        )

    def _make_session(self) -> aiohttp.ClientSession:
        timeout = aiohttp.ClientTimeout(total=self.request_timeout)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        }
        return aiohttp.ClientSession(
            connector=self._make_connector(),
            timeout=timeout,
            headers=headers,
        )

    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = self._make_session()
        return self._session

    async def close(self):
        retiring, self._retiring = self._retiring, {}
        for task, old in retiring.items():
            task.cancel()
            if not old.closed:
                await old.close()
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def rotate_circuit_async(self) -> bool:
        """Move to a new Tor circuit: later requests use a session with new SOCKS credentials.

        Requests already in flight finish on the old session, which is closed afterwards.
        """
        old = self._session
        self._isolation = secrets.token_hex(8)
        self._session = None
        self._last_rotation = time.time()
        if old is not None and not old.closed:
            task = asyncio.get_running_loop().create_task(self._close_later(old))
            self._retiring[task] = old
            task.add_done_callback(lambda t: self._retiring.pop(t, None))
        logger.info("Tor circuit rotated (new SOCKS isolation)")
        return True

    async def _close_later(self, session: aiohttp.ClientSession) -> None:
        await asyncio.sleep(self.request_timeout + 5)
        await session.close()

    async def check_connectivity(self) -> bool:
        """Verify Tor is working by fetching the check.torproject.org endpoint."""
        try:
            session = await self.get_session()
            async with session.get("https://check.torproject.org/api/ip", ssl=False) as resp:
                body, _ = await read_capped(resp, 64 * 1024)
                data = json.loads(body)
                if data.get("IsTor"):
                    logger.info(f"Tor connectivity confirmed. Exit IP: {data.get('IP')}")
                    return True
                else:
                    logger.warning("Connected but not routing through Tor!")
                    return False
        except Exception as e:
            logger.error(f"Tor connectivity check failed: {e}")
            return False

    @asynccontextmanager
    async def session_context(self):
        """Context manager for safe session usage."""
        try:
            session = await self.get_session()
            yield session
        finally:
            pass  # keep session alive across requests


def create_tor_client() -> TorClient:
    """Factory using environment variables."""
    return TorClient(
        socks_host=os.getenv("TOR_SOCKS_HOST", "tor"),
        socks_port=int(os.getenv("TOR_SOCKS_PORT", "9050")),
        request_timeout=int(os.getenv("REQUEST_TIMEOUT", "30")),
    )


def tor_reachable(timeout: Optional[float] = None) -> bool:
    """Whether Tor answers within ``timeout`` seconds.

    For callers that are not in an event loop (a request thread): it runs its
    own loop and always returns, True or False.
    """
    limit = TOR_CHECK_TIMEOUT if timeout is None else timeout

    async def _check() -> bool:
        tor = create_tor_client()
        try:
            return bool(await asyncio.wait_for(tor.check_connectivity(), limit))
        except asyncio.TimeoutError:
            logger.error("Tor connectivity check gave no answer in %s s", limit)
            return False
        finally:
            await tor.close()

    return asyncio.run(_check())
