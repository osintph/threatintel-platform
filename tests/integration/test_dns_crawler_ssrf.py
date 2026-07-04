"""
Integration tests for SEC-FABLE-3: SSRF guard on dns_crawler recon paths.

Verifies that enumerate_directories, probe_service, and scan_ports_multi
reject private/loopback targets rather than connecting to internal network
resources.
"""

import socket
from unittest.mock import patch

import pytest

from darkweb_scanner.dns_crawler import (
    COMMON_PORTS,
    enumerate_directories,
    probe_service,
    scan_ports_multi,
)

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
    with patch(
        "darkweb_scanner.dns_crawler.scan_ports", return_value=[]
    ) as mock_scan:
        result = scan_ports_multi(["10.0.0.1", "8.8.8.8"])

    assert "10.0.0.1" not in result, "Private IP must not be scanned"
    assert "8.8.8.8" in result, "Public IP must be scanned"

    scanned_hosts = [call.args[0] for call in mock_scan.call_args_list]
    assert "10.0.0.1" not in scanned_hosts
    assert "8.8.8.8" in scanned_hosts
