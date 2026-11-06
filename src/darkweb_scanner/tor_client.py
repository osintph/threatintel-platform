"""
Tor client manager — handles session creation, circuit rotation, and connectivity checks.

There is no Tor control port. A new circuit is obtained by opening a session
with fresh SOCKS credentials: Tor keeps streams with different SOCKS user names
on different circuits (IsolateSOCKSAuth, on by default).
"""

import asyncio
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Optional

import aiohttp
from aiohttp_socks import ProxyConnector

logger = logging.getLogger(__name__)


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
                data = await resp.json()
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
