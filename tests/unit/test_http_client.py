"""
Unit tests for darkweb_scanner.dashboard.http_client.safe_fetch().

Covers:
  - HTTPS enforcement
  - Host allowlist
  - IP blocklist (RFC 1918, loopback, link-local, IPv6)
  - Successful fetch through public IP
  - Redirect disabled by default
  - Redirect target re-validation
  - Redirect cap at 3 hops
  - DNS resolution failure
  - TLS verify=True enforcement
"""

import socket
from unittest.mock import MagicMock, patch

import pytest

from darkweb_scanner.dashboard.http_client import (
    SafeFetchError,
    check_host_ssrf,
    safe_fetch,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

_PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]
_RFC1918 = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 443))]
_LOOPBACK = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]
_LINK_LOCAL = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.1.1", 443))]
_IPV6_LOOPBACK = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 443, 0, 0))]


def _resp_200():
    r = MagicMock()
    r.status_code = 200
    r.headers = {"Content-Type": "application/json"}
    r.content = b'{"ok": true}'
    r.url = "https://api.github.com/test"
    return r


def _resp_302(location: str):
    r = MagicMock()
    r.status_code = 302
    r.headers = {"Location": location}
    r.content = b""
    r.url = "https://api.github.com/"
    return r


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_blocks_non_https():
    with pytest.raises(SafeFetchError, match="HTTPS"):
        safe_fetch("http://api.github.com/users/test")


def test_blocks_ftp_scheme():
    with pytest.raises(SafeFetchError, match="HTTPS"):
        safe_fetch("ftp://api.github.com/users/test")


def test_blocks_disallowed_host():
    with pytest.raises(SafeFetchError, match="ALLOWED_EXTERNAL_HOSTS"):
        safe_fetch("https://evil.example.com/attack")


def test_blocks_private_ip():
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_RFC1918):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/users/test")


def test_blocks_loopback():
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_LOOPBACK):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/users/test")


def test_blocks_link_local():
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_LINK_LOCAL):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/users/test")


def test_blocks_ipv6_loopback():
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_IPV6_LOOPBACK):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/users/test")


def test_allows_public_ip_on_allowed_host():
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch("darkweb_scanner.dashboard.http_client._requests.request", return_value=_resp_200()),
    ):
        result = safe_fetch("https://api.github.com/users/test")

    assert result["status"] == 200
    assert result["body"] == b'{"ok": true}'


def test_redirects_disabled_by_default():
    """Without allow_redirects, a 302 is returned as-is without following."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.request",
            return_value=_resp_302("https://api.github.com/redirected"),
        ),
    ):
        result = safe_fetch("https://api.github.com/original")

    assert result["status"] == 302


def test_redirects_revalidate_target():
    """With allow_redirects, a redirect to a disallowed host raises SafeFetchError."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.request",
            return_value=_resp_302("https://evil.example.com/steal"),
        ),
    ):
        with pytest.raises(SafeFetchError, match="ALLOWED_EXTERNAL_HOSTS"):
            safe_fetch("https://api.github.com/original", allow_redirects=True)


def test_redirects_cap():
    """With allow_redirects, an infinite redirect loop raises after 3 hops."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.request",
            return_value=_resp_302("https://api.github.com/loop"),
        ),
    ):
        with pytest.raises(SafeFetchError, match="3 hops"):
            safe_fetch("https://api.github.com/start", allow_redirects=True)


def test_dns_resolution_failure():
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
        side_effect=socket.gaierror("name or service not known"),
    ):
        with pytest.raises(SafeFetchError, match="DNS resolution failed"):
            safe_fetch("https://api.github.com/users/test")


def test_tls_verify_true():
    """requests.request must always be called with verify=True."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.request",
            return_value=_resp_200(),
        ) as mock_req,
    ):
        safe_fetch("https://api.github.com/users/test")

    mock_req.assert_called_once()
    call_kwargs = mock_req.call_args[1]
    assert call_kwargs.get("verify") is True, (
        f"verify={call_kwargs.get('verify')!r} — must be True"
    )


# ── SEC-FABLE-1: IPv4-mapped IPv6 and new reserved ranges ─────────────────────

_IPV4_MAPPED_LOOPBACK = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::ffff:127.0.0.1", 443, 0, 0))]
_IPV4_MAPPED_METADATA = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::ffff:169.254.169.254", 443, 0, 0))]
_CGNAT            = [(socket.AF_INET,  socket.SOCK_STREAM, 0, "", ("100.64.1.1", 443))]
_IPV6_UNSPECIFIED = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::", 443, 0, 0))]
_NAT64            = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("64:ff9b::a9fe:a9fe", 443, 0, 0))]


def test_blocks_ipv4_mapped_ipv6_loopback():
    """::ffff:127.0.0.1 must be blocked (IPv4-mapped loopback bypass)."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_IPV4_MAPPED_LOOPBACK):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


def test_blocks_ipv4_mapped_ipv6_metadata():
    """::ffff:169.254.169.254 must be blocked (IPv4-mapped link-local bypass)."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_IPV4_MAPPED_METADATA):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


def test_blocks_cgnat():
    """100.64.1.1 (CGNAT) must be blocked."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_CGNAT):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


def test_blocks_ipv6_unspecified():
    """:: (IPv6 unspecified) must be blocked."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_IPV6_UNSPECIFIED):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


def test_blocks_nat64():
    """64:ff9b::a9fe:a9fe (NAT64) must be blocked."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_NAT64):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


# ── SEC-FABLE-4: check_host_ssrf and allow_redirects=False coverage ───────────

def test_check_host_ssrf_rejects_disallowed_scheme():
    """check_host_ssrf resolves and validates the host — private IPs are rejected."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_RFC1918):
        with pytest.raises(SafeFetchError):
            check_host_ssrf("internal-corp-host.example.com")


def test_check_host_ssrf_rejects_private_ip():
    """check_host_ssrf raises SafeFetchError when getaddrinfo returns 10.0.0.5."""
    _PRIVATE_10 = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 0))]
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_PRIVATE_10):
        with pytest.raises(SafeFetchError, match="private"):
            check_host_ssrf("internal.corp")


def test_check_host_ssrf_rejects_mapped_ipv6_loopback():
    """check_host_ssrf must reject ::ffff:127.0.0.1 (Finding 1 fix in check_host_ssrf)."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_IPV4_MAPPED_LOOPBACK):
        with pytest.raises(SafeFetchError, match="private"):
            check_host_ssrf("loopback-via-ipv6.example.com")


def test_check_host_ssrf_allows_public_ip():
    """check_host_ssrf does not raise for a globally routable IP."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
               return_value=_PUBLIC):
        check_host_ssrf("public-host.example.com")  # must not raise


def test_safe_fetch_default_no_redirect_follow():
    """_requests.request is always called with allow_redirects=False (mirror test_tls_verify_true)."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.request",
            return_value=_resp_200(),
        ) as mock_req,
    ):
        safe_fetch("https://api.github.com/test")

    call_kwargs = mock_req.call_args[1]
    assert call_kwargs.get("allow_redirects") is False, (
        f"allow_redirects={call_kwargs.get('allow_redirects')!r} — must be False to prevent "
        "requests from following redirects internally and bypassing per-hop re-validation"
    )


def test_safe_fetch_redirect_follow_requires_explicit_optin():
    """A 302 is returned as-is unless allow_redirects=True is explicitly passed."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.request",
            return_value=_resp_302("https://api.github.com/redirected"),
        ) as mock_req,
    ):
        result = safe_fetch("https://api.github.com/original")

    assert result["status"] == 302, "302 must be returned without following when allow_redirects not set"
    assert mock_req.call_count == 1, "request must be called exactly once (no follow)"
