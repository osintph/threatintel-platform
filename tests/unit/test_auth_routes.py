"""Unit tests for auth_routes helpers."""

import pytest

from darkweb_scanner.dashboard.auth_routes import _safe_next


@pytest.mark.parametrize(
    "next_url,expected",
    [
        ("/dashboard", "/dashboard"),
        ("/some/deep/path?q=1", "/some/deep/path?q=1"),
        ("https://evil.com", "/default"),
        ("//evil.com", "/default"),
        ("http://evil.com/path", "/default"),
        ("", "/default"),
        ("javascript:alert(1)", "/default"),
    ],
)
def test_safe_next(next_url, expected):
    """SEC-04: only same-site paths beginning with '/' (not '//') are accepted."""
    assert _safe_next(next_url, "/default") == expected
