"""D-12: no Tor control port. New circuits come from new SOCKS credentials."""

import inspect

import pytest

from darkweb_scanner import tor_client
from darkweb_scanner.tor_client import TorClient, create_tor_client


def test_no_control_port_code_left():
    source = inspect.getsource(tor_client)
    for word in (
        "import stem",
        "from stem",
        "Controller",
        "NEWNYM",
        "control_port",
        "control_password",
    ):
        assert word not in source
    assert set(inspect.signature(TorClient.__init__).parameters) == {
        "self",
        "socks_host",
        "socks_port",
        "request_timeout",
    }


def test_factory_ignores_old_control_settings(monkeypatch):
    monkeypatch.setenv("TOR_SOCKS_HOST", "tor.test")
    monkeypatch.setenv("TOR_SOCKS_PORT", "9150")
    monkeypatch.setenv("TOR_CONTROL_PORT", "9051")
    monkeypatch.setenv("TOR_CONTROL_PASSWORD", "not-used")
    client = create_tor_client()
    assert (client.socks_host, client.socks_port) == ("tor.test", 9150)
    assert "not-used" not in client._proxy_url() and "9051" not in client._proxy_url()


def test_each_client_has_its_own_isolation():
    assert TorClient()._proxy_url() != TorClient()._proxy_url()


@pytest.mark.asyncio
async def test_rotation_changes_socks_credentials_and_session():
    client = TorClient(socks_host="127.0.0.1", socks_port=9, request_timeout=1)
    first = await client.get_session()
    before = client._proxy_url()
    assert before.startswith("socks5://") and before.endswith("@127.0.0.1:9")

    assert await client.rotate_circuit_async() is True

    after = client._proxy_url()
    assert after != before and after.endswith("@127.0.0.1:9")
    second = await client.get_session()
    assert second is not first
    # A request that started before the rotation can still finish on the old session.
    assert not first.closed

    await client.close()
    assert first.closed and second.closed and not client._retiring
