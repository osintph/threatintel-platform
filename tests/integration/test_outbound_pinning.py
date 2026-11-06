"""
NET-2 (2026-11 audit): a request goes to the address that passed the check.

The SSRF guard used to resolve a host name, check the answer, and then hand
the name to requests, which resolved it again. These tests use real loopback
listeners and a scripted resolver (see _loopback.py) to show that the second
answer no longer matters, that the Host header and the TLS names still carry
the host name, and that the certificate is verified against that name.
"""

import shutil
import ssl
import subprocess

import pytest

from darkweb_scanner.dashboard.http_client import SafeFetchError, fetch_public

from ._loopback import INTERNAL, PUBLIC_STAND_IN, same_port_pair


def test_fetch_public_connects_to_the_checked_address_when_dns_changes(loopback, scripted_dns):
    public, internal = same_port_pair(
        loopback, public_kwargs={"body": b"public"}, internal_kwargs={"body": b"internal"}
    )
    dns = scripted_dns({"rebind.test": [[PUBLIC_STAND_IN], [INTERNAL]]})

    result = fetch_public(f"http://rebind.test:{public.port}/page?x=1", https_only=False)

    assert result["status"] == 200 and result["body"] == b"public"
    assert internal.hits == []
    assert dns.lookups("rebind.test") == 1
    assert public.hits == [("GET", "/page?x=1", f"rebind.test:{public.port}")]


def test_fetch_public_never_follows_a_redirect(loopback, scripted_dns):
    internal = loopback(INTERNAL, body=b"internal")
    location = f"http://{INTERNAL}:{internal.port}/"
    public = loopback(PUBLIC_STAND_IN, status=307, headers={"Location": location})
    scripted_dns({"site.test": [[PUBLIC_STAND_IN]]})

    result = fetch_public(f"http://site.test:{public.port}/", https_only=False)

    assert result["status"] == 307
    assert result["headers"]["Location"] == location
    assert internal.hits == []


def test_fetch_public_refuses_an_internal_address_before_connecting(loopback, scripted_dns):
    internal = loopback(INTERNAL)
    scripted_dns({"inside.test": [[INTERNAL]]})

    with pytest.raises(SafeFetchError, match="private/loopback"):
        fetch_public(f"http://inside.test:{internal.port}/", https_only=False)
    with pytest.raises(SafeFetchError, match="private/loopback"):
        fetch_public(f"http://{INTERNAL}:{internal.port}/", https_only=False)
    assert internal.hits == []


def test_fetch_public_tries_the_next_checked_address_when_one_refuses(
    loopback, scripted_dns, monkeypatch
):
    from darkweb_scanner.dashboard import http_client

    real_check = http_client._is_private_ip
    monkeypatch.setattr(
        http_client, "_is_private_ip", lambda a: False if a == "127.0.0.3" else real_check(a)
    )
    public = loopback(PUBLIC_STAND_IN, body=b"second address")
    scripted_dns({"two.test": [["127.0.0.3", PUBLIC_STAND_IN]]})  # nothing listens on 127.0.0.3

    result = fetch_public(f"http://two.test:{public.port}/", https_only=False, timeout=3)

    assert result["body"] == b"second address"


def test_body_is_cut_off_at_max_bytes(loopback, scripted_dns):
    public = loopback(PUBLIC_STAND_IN, body=b"x" * 100_000)
    scripted_dns({"big.test": [[PUBLIC_STAND_IN]]})

    result = fetch_public(f"http://big.test:{public.port}/", https_only=False, max_bytes=4096)

    assert len(result["body"]) == 4096


# ── TLS: the host name, not the address, is what the certificate must match ────


@pytest.fixture
def tls_listener(loopback, tmp_path, monkeypatch):
    """HTTPS listener on the public stand-in address with a certificate for pinned.test."""
    if not shutil.which("openssl"):
        pytest.skip("needs the openssl command to make a test certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=pinned.test",
            "-addext",
            "subjectAltName=DNS:pinned.test",
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(cert))  # trust only this certificate
    return loopback(PUBLIC_STAND_IN, body=b"over tls", tls_context=context)


def test_https_is_connected_by_address_with_the_host_name_as_sni_and_certificate_name(
    tls_listener, scripted_dns
):
    dns = scripted_dns({"pinned.test": [[PUBLIC_STAND_IN], [INTERNAL]]})

    result = fetch_public(f"https://pinned.test:{tls_listener.port}/")

    assert result["status"] == 200 and result["body"] == b"over tls"
    assert tls_listener.sni == ["pinned.test"], "SNI must carry the host name"
    assert tls_listener.hits == [("GET", "/", f"pinned.test:{tls_listener.port}")]
    assert dns.lookups("pinned.test") == 1


def test_certificate_for_another_name_is_rejected(tls_listener, scripted_dns):
    """Pinning the address must not turn certificate verification into a check of the address."""
    scripted_dns({"other.test": [[PUBLIC_STAND_IN]]})

    with pytest.raises(SafeFetchError, match="TLS verification failed"):
        fetch_public(f"https://other.test:{tls_listener.port}/")
    assert tls_listener.hits == []
