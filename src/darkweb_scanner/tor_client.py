"""
Tor client manager — handles session creation, circuit rotation, and connectivity checks.
"""

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

import aiohttp
from aiohttp_socks import ProxyConnector
from stem import Signal
from stem.control import Controller

logger = logging.getLogger(__name__)


class TorClient:
    """Manages aiohttp sessions routed through the Tor SOCKS5 proxy."""

    def __init__(
        self,
        socks_host: str = "tor",
        socks_port: int = 9050,
        control_port: int = 9051,
        control_password: Optional[str] = None,
        request_timeout: int = 30,
    ):
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password or os.getenv("TOR_CONTROL_PASSWORD", "")
        self.request_timeout = request_timeout
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_rotation: float = 0

    def _make_connector(self) -> ProxyConnector:
        return ProxyConnector.from_url(
            f"socks5://{self.socks_host}:{self.socks_port}",
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
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def rotate_circuit(self) -> bool:
        """Request a new Tor identity via the control port."""
        try:
            with Controller.from_port(port=self.control_port) as controller:
                try:
                    controller.authenticate()
                    logger.warning(
                        "Tor control port %s accepted unauthenticated connection; "
                        "set HashedControlPassword in torrc to require authentication",
                        self.control_port,
                    )
                except Exception:
                    controller.authenticate(password=self.control_password)
                controller.signal(Signal.NEWNYM)
                self._last_rotation = time.time()
                logger.info("Tor circuit rotated successfully")
                return True
        except Exception as e:
            logger.warning(f"Failed to rotate Tor circuit: {e}")
            return False

    async def rotate_circuit_async(self) -> bool:
        """Non-blocking circuit rotation."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.rotate_circuit)

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
        control_port=int(os.getenv("TOR_CONTROL_PORT", "9051")),
        control_password=os.getenv("TOR_CONTROL_PASSWORD", ""),
        request_timeout=int(os.getenv("REQUEST_TIMEOUT", "30")),
    )
