"""
Unit tests for Quick Scan high-signal classification and context extraction.
"""

import pytest

from darkweb_scanner.quick_scan import (
    HIGH_SIGNAL_KEYWORDS,
    extract_context,
    find_matches,
    is_high_signal,
)


@pytest.mark.parametrize("keyword", list(HIGH_SIGNAL_KEYWORDS))
def test_each_keyword_flags_high_signal(keyword):
    context = f"some text {keyword} more text"
    assert is_high_signal(context) is True


def test_no_keyword_is_not_high_signal():
    assert is_high_signal("nothing of interest in this window at all") is False


def test_empty_context_is_not_high_signal():
    assert is_high_signal("") is False
    assert is_high_signal(None) is False


@pytest.mark.parametrize("keyword", list(HIGH_SIGNAL_KEYWORDS))
def test_high_signal_is_case_insensitive(keyword):
    assert is_high_signal(f"XXX {keyword.upper()} YYY") is True
    assert is_high_signal(f"XXX {keyword.title()} YYY") is True


def test_extract_context_centers_on_match():
    text = ("a" * 100) + "TARGET" + ("b" * 100)
    start = text.index("TARGET")
    window = extract_context(text, start, start + len("TARGET"))
    # 100 before + match + 100 after
    assert window == ("a" * 100) + "TARGET" + ("b" * 100)
    assert "TARGET" in window


def test_extract_context_clamps_at_boundaries():
    text = "TARGET" + ("b" * 20)
    window = extract_context(text, 0, len("TARGET"))
    assert window.startswith("TARGET")
    assert len(window) <= len(text)


def test_find_matches_reports_variant_context_and_flag():
    text = "the acme.com account credentials were leaked online"
    matches = find_matches(text, ["acme.com", "absent-variant"])
    assert len(matches) == 1
    match = matches[0]
    assert match["variant"] == "acme.com"
    assert "acme.com" in match["context"]
    assert match["high_signal"] is True  # "credentials" and "leaked" present


def test_find_matches_low_signal_when_no_keyword():
    text = "the acme.com homepage is online and friendly"
    matches = find_matches(text, ["acme.com"])
    assert len(matches) == 1
    assert matches[0]["high_signal"] is False


def test_find_matches_is_case_insensitive():
    matches = find_matches("Visit ACME.COM today", ["acme.com"])
    assert len(matches) == 1
    assert matches[0]["variant"] == "acme.com"


def test_find_matches_empty_text_returns_nothing():
    assert find_matches("", ["acme.com"]) == []
