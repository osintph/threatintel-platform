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
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_LINK_LOCAL
    ):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/users/test")


def test_blocks_ipv6_loopback():
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_IPV6_LOOPBACK
    ):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/users/test")


def test_allows_public_ip_on_allowed_host():
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.Session.request",
            return_value=_resp_200(),
        ),
    ):
        result = safe_fetch("https://api.github.com/users/test")

    assert result["status"] == 200
    assert result["body"] == b'{"ok": true}'


def test_redirects_disabled_by_default():
    """Without allow_redirects, a 302 is returned as-is without following."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.Session.request",
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
            "darkweb_scanner.dashboard.http_client._requests.Session.request",
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
            "darkweb_scanner.dashboard.http_client._requests.Session.request",
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
    """The request must always be sent with verify=True."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.Session.request",
            return_value=_resp_200(),
        ) as mock_req,
    ):
        safe_fetch("https://api.github.com/users/test")

    mock_req.assert_called_once()
    call_kwargs = mock_req.call_args[1]
    assert call_kwargs.get("verify") is True, f"verify={call_kwargs.get('verify')!r} — must be True"


# ── SEC-FABLE-1: IPv4-mapped IPv6 and new reserved ranges ─────────────────────

_IPV4_MAPPED_LOOPBACK = [
    (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::ffff:127.0.0.1", 443, 0, 0))
]
_IPV4_MAPPED_METADATA = [
    (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::ffff:169.254.169.254", 443, 0, 0))
]
_CGNAT = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("100.64.1.1", 443))]
_IPV6_UNSPECIFIED = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::", 443, 0, 0))]
_NAT64 = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("64:ff9b::a9fe:a9fe", 443, 0, 0))]


def test_blocks_ipv4_mapped_ipv6_loopback():
    """::ffff:127.0.0.1 must be blocked (IPv4-mapped loopback bypass)."""
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
        return_value=_IPV4_MAPPED_LOOPBACK,
    ):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


def test_blocks_ipv4_mapped_ipv6_metadata():
    """::ffff:169.254.169.254 must be blocked (IPv4-mapped link-local bypass)."""
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
        return_value=_IPV4_MAPPED_METADATA,
    ):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


def test_blocks_cgnat():
    """100.64.1.1 (CGNAT) must be blocked."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_CGNAT):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


def test_blocks_ipv6_unspecified():
    """:: (IPv6 unspecified) must be blocked."""
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_IPV6_UNSPECIFIED
    ):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


def test_blocks_nat64():
    """64:ff9b::a9fe:a9fe (NAT64) must be blocked."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_NAT64):
        with pytest.raises(SafeFetchError, match="private"):
            safe_fetch("https://api.github.com/test")


# ── SEC-FABLE-4: check_host_ssrf and allow_redirects=False coverage ───────────


def test_check_host_ssrf_rejects_disallowed_scheme():
    """check_host_ssrf resolves and validates the host — private IPs are rejected."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_RFC1918):
        with pytest.raises(SafeFetchError):
            check_host_ssrf("internal-corp-host.example.com")


def test_check_host_ssrf_rejects_private_ip():
    """check_host_ssrf raises SafeFetchError when getaddrinfo returns 10.0.0.5."""
    _PRIVATE_10 = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 0))]
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PRIVATE_10
    ):
        with pytest.raises(SafeFetchError, match="private"):
            check_host_ssrf("internal.corp")


def test_check_host_ssrf_rejects_mapped_ipv6_loopback():
    """check_host_ssrf must reject ::ffff:127.0.0.1 (Finding 1 fix in check_host_ssrf)."""
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
        return_value=_IPV4_MAPPED_LOOPBACK,
    ):
        with pytest.raises(SafeFetchError, match="private"):
            check_host_ssrf("loopback-via-ipv6.example.com")


def test_check_host_ssrf_allows_public_ip():
    """check_host_ssrf does not raise for a globally routable IP."""
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC):
        check_host_ssrf("public-host.example.com")  # must not raise


def test_safe_fetch_default_no_redirect_follow():
    """The request is always sent with allow_redirects=False (mirror test_tls_verify_true)."""
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.Session.request",
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
            "darkweb_scanner.dashboard.http_client._requests.Session.request",
            return_value=_resp_302("https://api.github.com/redirected"),
        ) as mock_req,
    ):
        result = safe_fetch("https://api.github.com/original")

    assert result["status"] == 302, (
        "302 must be returned without following when allow_redirects not set"
    )
    assert mock_req.call_count == 1, "request must be called exactly once (no follow)"


# ── NET-2 (2026-11 audit): the connection goes to the address that was checked ─

from darkweb_scanner.dashboard import http_client  # noqa: E402
from darkweb_scanner.dashboard.http_client import (  # noqa: E402
    _is_private_ip,
    _PinnedAdapter,
    fetch_public,
    resolve_and_check_target,
)


def _info(*addresses):
    return [
        (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 0, "", (a, 443))
        for a in addresses
    ]


class _Rebinding:
    """getaddrinfo stand-in: a public answer for the first lookup of a name, loopback after that."""

    def __init__(self):
        self.names = []

    def __call__(self, host, port, *args, **kwargs):
        try:
            socket.inet_aton(host)
            return _info(host)  # an address literal, as the socket layer passes when connecting
        except OSError:
            pass
        self.names.append(host)
        return _info("8.8.8.8") if len(self.names) == 1 else _info("127.0.0.1")


def test_safe_fetch_connects_to_the_checked_address_not_to_a_second_dns_answer():
    """DNS rebinding: the socket layer must be given the checked address, never the name."""
    dns = _Rebinding()
    targets = []

    def fake_create_connection(address, *args, **kwargs):
        targets.append(address)
        raise OSError("stopped by the test before any packet is sent")

    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", dns),
        patch("urllib3.util.connection.create_connection", fake_create_connection),
    ):
        with pytest.raises(SafeFetchError, match="Connection failed"):
            safe_fetch("https://api.github.com/users/test")

    assert targets == [("8.8.8.8", 443)], f"connected to {targets!r}"
    assert dns.names == ["api.github.com"], "the name must be resolved exactly once"


def test_pinned_adapter_keeps_the_host_name_for_tls_and_the_host_header():
    adapter = _PinnedAdapter("8.8.8.8")
    request = http_client._requests.Request("GET", "https://api.github.com/users/test").prepare()

    host_params, pool_kwargs = adapter.build_connection_pool_key_attributes(request, True)

    assert host_params["host"] == "8.8.8.8", "the TCP connection goes to the checked address"
    assert host_params["scheme"] == "https"
    assert pool_kwargs["server_hostname"] == "api.github.com", "SNI carries the host name"
    assert pool_kwargs["assert_hostname"] == "api.github.com", (
        "the certificate is checked against the host name"
    )
    assert http_client._host_header("https://api.github.com/users/test") == "api.github.com"
    assert http_client._host_header("http://example.org:8080/") == "example.org:8080"


def test_a_name_with_one_public_and_one_private_address_is_rejected():
    mixed = _info("8.8.8.8", "10.0.0.5")
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=mixed):
        with pytest.raises(SafeFetchError, match="private/loopback"):
            safe_fetch("https://api.github.com/users/test")
        with pytest.raises(SafeFetchError, match="private/loopback"):
            check_host_ssrf("mixed.example.com")
        with pytest.raises(SafeFetchError, match="private/loopback"):
            fetch_public("https://mixed.example.com/")


def test_checked_addresses_are_returned_ipv4_first():
    answers = _info("2606:4700:4700::1111", "8.8.8.8", "8.8.8.8", "1.1.1.1")
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=answers):
        assert resolve_and_check_target("example.com") == [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
        ]


@pytest.mark.parametrize(
    "address",
    [
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "2002:7f00:1::1",  # 6to4 carrying 127.0.0.1
        "2002:a9fe:a9fe::1",  # 6to4 carrying 169.254.169.254
        "2001:0:808:808:0:0:80ff:fffe",  # Teredo carrying client 127.0.0.1
        "fec0::1",  # site-local
        "64:ff9b:1::a00:1",  # local-use NAT64
        "100.100.100.100",  # CGNAT / tailnet
        "172.18.0.2",  # Docker bridge
    ],
)
def test_internal_addresses_in_other_notations_are_private(address):
    assert _is_private_ip(address) is True


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_not_private(address):
    assert _is_private_ip(address) is False


def test_fetch_public_rejects_ipv4_mapped_ipv6_loopback():
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
        return_value=_IPV4_MAPPED_LOOPBACK,
    ):
        with pytest.raises(SafeFetchError, match="private/loopback"):
            fetch_public("https://sneaky.example.com/")


@pytest.mark.parametrize(
    "url,message",
    [
        ("http://example.com/", "scheme"),
        ("ftp://example.com/", "scheme"),
        ("https://user:pw@example.com/", "credentials"),
        ("https://abcdefghijklmnop.onion/", "onion"),
        ("https:///path", "no host"),
        ("https://example.com:99999/", "port"),
    ],
)
def test_fetch_public_policy(url, message):
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC
    ) as dns:
        with pytest.raises(SafeFetchError, match=message):
            fetch_public(url)
    dns.assert_not_called()


def test_fetch_public_checks_addresses_handed_in_by_the_caller():
    with pytest.raises(SafeFetchError, match="private/loopback"):
        fetch_public("https://example.com/", addresses=["8.8.8.8", "127.0.0.1"])
    with pytest.raises(SafeFetchError, match="no checked address"):
        fetch_public("https://example.com/", addresses=[])


def test_fetch_public_does_not_follow_redirects():
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.Session.request",
            return_value=_resp_302("http://169.254.169.254/latest/meta-data/"),
        ) as mock_req,
    ):
        result = fetch_public("https://example.com/")

    assert result["status"] == 302
    assert mock_req.call_count == 1
    assert mock_req.call_args[1]["allow_redirects"] is False
    assert mock_req.call_args[1]["verify"] is True


def test_safe_fetch_rejects_credentials_in_the_url():
    with patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC):
        with pytest.raises(SafeFetchError, match="credentials"):
            safe_fetch("https://user:pw@api.github.com/")


# ── Redirects to another host do not carry the caller's headers ───────────────


def test_cross_host_redirect_does_not_forward_the_callers_headers():
    """An API key header is for the host it was sent to, not for wherever that host redirects."""
    responses = [_resp_302("https://raw.githubusercontent.com/elsewhere"), _resp_200()]
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.Session.request", side_effect=responses
        ) as mock_req,
    ):
        safe_fetch(
            "https://api.github.com/start",
            headers={"Auth-Key": "k-123", "Authorization": "Bearer t"},
            allow_redirects=True,
        )

    first, second = (call[1]["headers"] for call in mock_req.call_args_list)
    assert first["Auth-Key"] == "k-123"
    assert "Auth-Key" not in second and "Authorization" not in second
    assert second["User-Agent"] == "OSINTPH/1.0"


def test_same_host_redirect_keeps_the_callers_headers():
    responses = [_resp_302("https://api.github.com/next"), _resp_200()]
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.Session.request", side_effect=responses
        ) as mock_req,
    ):
        safe_fetch(
            "https://api.github.com/start", headers={"Auth-Key": "k-123"}, allow_redirects=True
        )

    assert mock_req.call_args_list[1][1]["headers"]["Auth-Key"] == "k-123"


def test_post_is_not_redirected_to_another_host():
    redirect = _resp_302("https://raw.githubusercontent.com/elsewhere")
    redirect.status_code = 307  # 307 keeps the method and the body
    with (
        patch("darkweb_scanner.dashboard.http_client.socket.getaddrinfo", return_value=_PUBLIC),
        patch(
            "darkweb_scanner.dashboard.http_client._requests.Session.request", return_value=redirect
        ) as mock_req,
    ):
        with pytest.raises(SafeFetchError, match="redirected to another host"):
            safe_fetch(
                "https://api.github.com/start", method="POST", data=b"secret", allow_redirects=True
            )

    assert mock_req.call_count == 1
