"""Unit tests for regex_safety (REL-3)."""

import time

import pytest

from darkweb_scanner import regex_safety as rs


@pytest.mark.parametrize(
    "pattern",
    ["acme", r"\bbdo\b|\bbpi\b", r"acme\s+bank", r"\d{4}-\d{4}", r"\b[\w.-]+\.ph\b", "foo|bar"],
)
def test_ordinary_patterns_are_accepted(pattern):
    rs.check_pattern(pattern)
    assert rs.is_safe(pattern)


@pytest.mark.parametrize(
    "pattern",
    ["", "(", "(a+)+$", r"(\w+\s?)+", "(a|aa)+", r"(a)\1", "(?P<x>a)(?P=x)", "(?=a+)b",
     ".*a.*b", "a" * (rs.MAX_PATTERN_LENGTH + 1)],
)
def test_unsafe_patterns_are_refused(pattern):
    with pytest.raises(rs.UnsafePattern):
        rs.check_pattern(pattern)
    assert rs.compile_checked(pattern) is None
    assert rs.search(pattern, "aaaa") is False


def test_clip_keeps_the_middle():
    assert rs.clip("short") == "short"
    text = "a" * 5000 + "HIT" + "b" * 5000
    clipped = rs.clip(text)
    assert len(clipped) == rs.MAX_MATCH_TEXT
    assert "HIT" in clipped
    assert rs.clip(None) == ""


def test_an_accepted_pattern_is_fast_on_clipped_text():
    # The slowest kind of accepted pattern (quadratic) on hostile input.
    started = time.monotonic()
    rs.search(r"\b[\w.-]+\.ph\b", "a." * 100_000)
    assert time.monotonic() - started < 1.5
