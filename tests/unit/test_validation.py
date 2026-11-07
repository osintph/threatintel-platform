"""Input validation helpers (F-4: server-side checks for addresses, domains, seeds, channels, project fields)."""

import pytest
from flask import Flask

from darkweb_scanner.dashboard import validation as v


@pytest.mark.parametrize(
    "value", ["example.com", "sub.example.co.uk", "EXAMPLE.com.", "xn--bcher-kva.example"]
)
def test_domain_accepts(value):
    assert v.domain(value) == value.lower().rstrip(".")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "exa mple.com",
        "example.com/path",
        "http://example.com",
        "-bad.example.com",
        "a" * 64 + ".com",
        '"><img src=x>.com',
        "example.com\nevil.com",
        "1.2.3.4",
        None,
        5,
    ],
)
def test_domain_rejects(value):
    with pytest.raises(v.Invalid):
        v.domain(value)


@pytest.mark.parametrize(
    "value", ["http://abcdefghijklmnop.onion/", "https://example.com/a?b=1&c=2"]
)
def test_http_url_accepts(value):
    assert v.http_url(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "ftp://example.com/",
        "//example.com",
        "http://",
        "http://user:pw@example.com/",
        'http://example.com/"onmouseover="x',
        "http://example.com/<script>",
        "http://exa mple.com/",
        "http://example.com/\nhttp://evil.example/",
        "x" * 3000,
        "data:text/html,x",
    ],
)
def test_http_url_rejects(value):
    with pytest.raises(v.Invalid):
        v.http_url(value)


@pytest.mark.parametrize("value", ["a@example.com", "First.Last+tag@sub.example.org"])
def test_email_accepts(value):
    assert v.email(value) == value.lower()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "no-at-sign",
        "a@b",
        "a@example.com\nb@example.com",
        'a"b@example.com',
        "x' data-audit-sub='1@example.com",
        "<a@example.com>",
        "a@exam ple.com",
        "a@example.com,b@example.com",
    ],
)
def test_email_rejects(value):
    with pytest.raises(v.Invalid):
        v.email(value)


def test_email_optional():
    assert v.email("", required=False) is None


def test_keyword_allows_regex_and_quotes_but_not_line_breaks():
    assert v.keyword(r'pass(word)?\s*[:=]\s*"') == r'pass(word)?\s*[:=]\s*"'
    for bad in ("a\nb", "a\x00b", "", "x" * 201, None, ["a"]):
        with pytest.raises(v.Invalid):
            v.keyword(bad)


def test_category():
    assert v.category(None) == "custom"
    assert v.category("ransomware / leaks") == "ransomware / leaks"
    for bad in ("<b>", "a\nb", "x" * 65, "'onclick=", 5):
        with pytest.raises(v.Invalid):
            v.category(bad)


def test_text_refuses_angle_brackets_and_keeps_apostrophes():
    assert v.text("O'Brien & Sons", "name", 50) == "O'Brien & Sons"
    for bad in ("<img src=x>", "a\tb", "x" * 51):
        with pytest.raises(v.Invalid):
            v.text(bad, "name", 50)


@pytest.mark.parametrize("value", ["false", "true", 1, 0, "0", [], "no"])
def test_strict_bool_refuses_everything_but_a_boolean(value):
    with pytest.raises(v.Invalid):
        v.strict_bool(value, "is_admin")


def test_strict_bool_accepts_booleans_and_absence():
    assert v.strict_bool(True, "f") is True
    assert v.strict_bool(False, "f") is False
    assert v.strict_bool(None, "f") is False


def test_username_color_tags_ip():
    assert v.username("alice.b-c_1") == "alice.b-c_1"
    for bad in ("ab", "a b", "<x>", "-lead", "x" * 65):
        with pytest.raises(v.Invalid):
            v.username(bad)
    assert v.color(None) == "#f85149" and v.color("#00ffAA") == "#00ffAA"
    with pytest.raises(v.Invalid):
        v.color("red;background:url(x)")
    assert v.tags(["a", "b"]) == ["a", "b"]
    with pytest.raises(v.Invalid):
        v.tags(["<x>"])
    with pytest.raises(v.Invalid):
        v.tags("not-a-list")
    assert v.ip_address("2001:DB8::1") == "2001:db8::1"
    for bad in ("999.1.1.1", "1.2.3", ":::", "1.2.3.4/8"):
        with pytest.raises(v.Invalid):
            v.ip_address(bad)


def test_int_arg_clamps_and_defaults():
    app = Flask(__name__)
    with app.test_request_context("/?limit=abc"):
        assert v.int_arg("limit", 100, 1, 1000) == 100
    with app.test_request_context("/?limit=999999"):
        assert v.int_arg("limit", 100, 1, 1000) == 1000
    with app.test_request_context("/?limit=-5"):
        assert v.int_arg("limit", 100, 1, 1000) == 1
    with app.test_request_context("/"):
        assert v.int_arg("limit", 100, 1, 1000) == 100
    assert v.to_int("7", 1, 1, 5) == 5
    assert v.to_int(True, 3, 1, 5) == 3
    assert v.to_int("x", 3, 1, 5) == 3


def test_json_body_is_a_dict_or_empty():
    app = Flask(__name__)
    with app.test_request_context("/", method="POST", json=["not", "an", "object"]):
        assert v.json_body() == {}
    with app.test_request_context(
        "/", method="POST", data="not json", content_type="application/json"
    ):
        assert v.json_body() == {}
    with app.test_request_context("/", method="POST", json={"a": 1}):
        assert v.json_body() == {"a": 1}
