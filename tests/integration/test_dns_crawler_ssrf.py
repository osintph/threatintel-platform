"""
Integration tests for SEC-FABLE-3: SSRF guard on dns_crawler recon paths.

Verifies that enumerate_directories, probe_service, and scan_ports_multi
reject private/loopback targets rather than connecting to internal network
resources.

NET-1 / NET-2 (2026-11 audit): the tests in the second half run against real
loopback listeners with a scripted resolver (see _loopback.py), because a
guard that is only tested with DNS and requests both mocked cannot show what
happens after the first check: a redirect, or a second DNS answer.
"""

import socket
from unittest.mock import patch

import pytest

from darkweb_scanner.dns_crawler import (
    enumerate_directories,
    probe_service,
    scan_ports_multi,
)

from ._loopback import INTERNAL, PUBLIC_STAND_IN, same_port_pair

_LOOPBACK = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]
_LINK_LOCAL = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))]
_PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]


def test_dns_crawler_rejects_localhost_target():
    """enumerate_directories must refuse targets that resolve to loopback."""
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
        return_value=_LOOPBACK,
    ):
        result = enumerate_directories("localhost")

    assert result == [], "Expected empty list for private/loopback target"


def test_dns_crawler_rejects_metadata_target():
    """probe_service must refuse targets that resolve to link-local (cloud metadata)."""
    with patch(
        "darkweb_scanner.dashboard.http_client.socket.getaddrinfo",
        return_value=_LINK_LOCAL,
    ):
        result = probe_service("metadata.google.internal")

    assert result is None, "Expected None for link-local target"


def test_dns_crawler_skips_private_ip_from_resolution():
    """scan_ports_multi skips private IPs and only scans the public one."""
    with patch("darkweb_scanner.dns_crawler.scan_ports", return_value=[]) as mock_scan:
        result = scan_ports_multi(["10.0.0.1", "8.8.8.8"])

    assert "10.0.0.1" not in result, "Private IP must not be scanned"
    assert "8.8.8.8" in result, "Public IP must be scanned"

    scanned_hosts = [call.args[0] for call in mock_scan.call_args_list]
    assert "10.0.0.1" not in scanned_hosts
    assert "8.8.8.8" in scanned_hosts


# ── NET-1: the probes do not follow redirects ─────────────────────────────────

_INTERNAL_PAGE = b"<html><head><title>internal admin</title></head></html>"


def _redirect_cases(internal_port):
    return {
        "loopback address": f"http://{INTERNAL}:{internal_port}/secret",
        "internal name": f"http://internal.test:{internal_port}/secret",
        "metadata address": "http://169.254.169.254/latest/meta-data/",
    }


@pytest.mark.parametrize("case", ["loopback address", "internal name", "metadata address"])
def test_probe_service_reports_a_redirect_and_does_not_follow_it(loopback, scripted_dns, case):
    """A probed host that answers 302 to an internal URL gets no second request made for it."""
    internal = loopback(INTERNAL, body=_INTERNAL_PAGE)
    location = _redirect_cases(internal.port)[case]
    public = loopback(PUBLIC_STAND_IN, status=302, headers={"Location": location})
    dns = scripted_dns({"probe-target.test": [[PUBLIC_STAND_IN]], "internal.test": [[INTERNAL]]})

    result = probe_service(f"probe-target.test:{public.port}")

    assert internal.hits == [], "the redirect target was requested"
    for target in ("internal.test", INTERNAL, "169.254.169.254"):
        assert target not in dns.calls, f"a connection to {target} was attempted"
    assert result is not None
    assert result["status_code"] == 302
    assert result["redirect_to"] == location, "the redirect is recorded as data"
    assert result["final_url"] == result["url"] == f"http://probe-target.test:{public.port}"
    assert "internal admin" not in result["title"]
    assert [hit[:2] for hit in public.hits] == [("GET", "/")]


def test_enumerate_directories_does_not_follow_redirects(loopback, scripted_dns):
    """Neither the reachability check nor the path probes follow a redirect."""
    internal = loopback(INTERNAL, body=_INTERNAL_PAGE)
    location = f"http://{INTERNAL}:{internal.port}/secret"
    public = loopback(PUBLIC_STAND_IN, status=302, headers={"Location": location})
    dns = scripted_dns({"probe-target.test": [[PUBLIC_STAND_IN]]})

    results = enumerate_directories(f"probe-target.test:{public.port}", paths=["/", "/admin"])

    assert internal.hits == [], "the redirect target was requested"
    assert INTERNAL not in dns.calls
    assert sorted(r["path"] for r in results) == ["/", "/admin"]
    assert {r["status_code"] for r in results} == {302}
    assert {r["redirect_to"] for r in results} == {location}
    assert dns.lookups("probe-target.test") == 1, "the target is resolved once for the whole scan"


# ── NET-2: the probes connect to the address that was checked ─────────────────


def test_probe_service_connects_to_the_checked_address_when_dns_changes(loopback, scripted_dns):
    """DNS rebinding: the first answer is public and passes the check, the next one is internal."""
    public, internal = same_port_pair(
        loopback,
        public_kwargs={"body": b"<title>public site</title>"},
        internal_kwargs={"body": _INTERNAL_PAGE},
    )
    dns = scripted_dns({"rebind.test": [[PUBLIC_STAND_IN], [INTERNAL]]})

    result = probe_service(f"rebind.test:{public.port}")

    assert internal.hits == [], "the request went to the second, unchecked DNS answer"
    assert dns.lookups("rebind.test") == 1, "the name must be resolved once"
    assert result is not None and result["title"] == "public site"
    assert public.hits == [("GET", "/", f"rebind.test:{public.port}")], (
        "Host header carries the name"
    )


def test_enumerate_directories_connects_to_the_checked_address_when_dns_changes(
    loopback, scripted_dns
):
    public, internal = same_port_pair(loopback)
    dns = scripted_dns({"rebind.test": [[PUBLIC_STAND_IN], [INTERNAL]]})

    results = enumerate_directories(f"rebind.test:{public.port}", paths=["/", "/admin", "/login"])

    assert internal.hits == []
    assert dns.lookups("rebind.test") == 1
    assert len(results) == 3
    assert {hit[2] for hit in public.hits} == {f"rebind.test:{public.port}"}


def test_probe_service_refuses_a_name_with_a_public_and_an_internal_address(loopback, scripted_dns):
    public, internal = same_port_pair(loopback)
    scripted_dns({"mixed.test": [[PUBLIC_STAND_IN, INTERNAL]]})

    assert probe_service(f"mixed.test:{public.port}") is None
    assert public.hits == [] and internal.hits == []


# ── Stored probe text is cleaned and capped ───────────────────────────────────


def test_probe_service_caps_and_cleans_header_and_title_text(loopback, scripted_dns):
    public = loopback(
        PUBLIC_STAND_IN,
        headers={"Server": "nginx\x7f" + "A" * 500, "X-Powered-By": "PHP/8\x01" + "B" * 100},
        body=b"<title>  one\x00two\n three \xe2\x80\xae" + b"T" * 500 + b"</title>",
    )
    scripted_dns({"probe-target.test": [[PUBLIC_STAND_IN]]})

    result = probe_service(f"probe-target.test:{public.port}")

    assert len(result["server_raw"]) <= 120 and len(result["title"]) <= 80
    assert all(len(t) <= 20 for t in result["tech"])
    assert result["title"].startswith("one two three ")
    for value in (result["server_raw"], result["server"], result["title"], *result["tech"]):
        assert not any(ord(ch) < 32 or ord(ch) == 127 or ch == "\u202e" for ch in value), repr(
            value
        )


@pytest.mark.parametrize(
    "target",
    ["user@probe-target.test", "probe-target.test/path", "probe-target.test:99999", "a b", ""],
)
def test_probes_reject_targets_that_are_not_a_host_name(scripted_dns, target):
    dns = scripted_dns({"probe-target.test": [["8.8.8.8"]]})
    assert probe_service(target) is None
    assert enumerate_directories(target, paths=["/"]) == []
    assert dns.calls == [], "nothing may be resolved or contacted for such a target"
