"""
Unit tests for Quick Scan target auto-detection and normalization.

Covers every target type and the normalized-variant expansion rules.
"""

import pytest

from darkweb_scanner.quick_scan import (
    TYPE_COMPANY,
    TYPE_DOMAIN,
    TYPE_EMAIL,
    TYPE_URL,
    detect_target_type,
    normalize_variants,
)


@pytest.mark.parametrize(
    "raw,expected_type",
    [
        # email: contains @ and matches the email regex
        ("john.doe@acme.com", TYPE_EMAIL),
        ("a@b.co", TYPE_EMAIL),
        # url: starts with http:// or https://
        ("http://acme.com/login", TYPE_URL),
        ("https://shop.acme.com/a/b?x=1", TYPE_URL),
        ("HTTPS://ACME.COM", TYPE_URL),
        # domain: label.tld pattern, no scheme
        ("acme.com", TYPE_DOMAIN),
        ("sub.acme.com", TYPE_DOMAIN),
        ("a-b.example.io", TYPE_DOMAIN),
        # company_name: everything else
        ("Acme Corporation", TYPE_COMPANY),
        ("Acme", TYPE_COMPANY),
        ("not a domain!", TYPE_COMPANY),
        # an @ present but not a valid email falls through to company
        ("john@doe@x", TYPE_COMPANY),
    ],
)
def test_detect_target_type(raw, expected_type):
    assert detect_target_type(raw) == expected_type


@pytest.mark.parametrize(
    "value,ttype,expected",
    [
        # email -> full address, local-part, domain
        ("john.doe@acme.com", TYPE_EMAIL, ["john.doe@acme.com", "john.doe", "acme.com"]),
        # url -> normalized (host+path), then bare host; query/fragment dropped
        ("https://shop.acme.com/a/b?x=1", TYPE_URL, ["shop.acme.com/a/b", "shop.acme.com"]),
        # url with no path -> host only (single entry after dedupe)
        ("https://acme.com", TYPE_URL, ["acme.com"]),
        # apex domain -> bare + www
        ("acme.com", TYPE_DOMAIN, ["acme.com", "www.acme.com"]),
        # subdomain -> bare + www + apex
        ("sub.acme.com", TYPE_DOMAIN, ["sub.acme.com", "www.sub.acme.com", "acme.com"]),
        # already-www domain -> not doubly prefixed
        ("www.acme.com", TYPE_DOMAIN, ["www.acme.com", "acme.com"]),
        # company -> exact string only, no fuzzy expansion
        ("Acme Corporation", TYPE_COMPANY, ["Acme Corporation"]),
    ],
)
def test_normalize_variants(value, ttype, expected):
    assert normalize_variants(value, ttype) == expected


def test_variants_are_deduplicated_and_ordered():
    variants = normalize_variants("acme.com", TYPE_DOMAIN)
    assert variants == list(dict.fromkeys(variants))  # order-preserving, no dupes


def test_detect_then_normalize_roundtrip():
    raw = "john.doe@acme.com"
    ttype = detect_target_type(raw)
    variants = normalize_variants(raw, ttype)
    assert ttype == TYPE_EMAIL
    assert raw in variants
    assert "acme.com" in variants
    assert "john.doe" in variants
