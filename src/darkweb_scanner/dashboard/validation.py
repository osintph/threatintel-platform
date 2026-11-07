"""
Input validation for the dashboard API.

Every value that ends up in a config file, the database or a page is checked
here first. The front end escapes what it renders; this is the second line:
values with markup, control characters or line breaks are refused at the door.
"""

import ipaddress
import re
from typing import Any, Optional
from urllib.parse import urlsplit

from flask import request

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Angle brackets have no place in a name, tag or URL; quotes do (O'Brien), and pages escape them.
_MARKUP = re.compile(r"[<>]")
_URL_UNSAFE = re.compile(r"[\s\"'`\\^{}|]")

_HOST_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_DOMAIN = re.compile(rf"^(?:{_HOST_LABEL}\.)+[A-Za-z][A-Za-z0-9-]{{1,62}}$")
_EMAIL = re.compile(rf"^[A-Za-z0-9._%+-]{{1,64}}@(?:{_HOST_LABEL}\.)+[A-Za-z]{{2,63}}$")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
_CATEGORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.&/+-]{0,63}$")
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


class Invalid(ValueError):
    """Raised with a message that is safe to return to the client."""


def json_body() -> dict:
    """The request's JSON object, or an empty dict when there is none."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def int_arg(name: str, default: int, low: int, high: int) -> int:
    """An integer query parameter, clamped to [low, high]; ``default`` when absent or not a number."""
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def to_int(value: Any, default: int, low: int, high: int) -> int:
    """An integer from a JSON body, clamped; ``default`` when absent or not a number."""
    if isinstance(value, bool) or value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def strict_bool(value: Any, field: str, default: bool = False) -> bool:
    """A real JSON boolean. The string "false" is not one."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise Invalid(f"{field} must be true or false")


def text(value: Any, field: str, max_len: int, required: bool = True, allow_markup: bool = False) -> Optional[str]:
    """One line of text: a string, trimmed, no control characters, at most ``max_len`` long."""
    if value is None or value == "":
        if required:
            raise Invalid(f"{field} required")
        return None
    if not isinstance(value, str):
        raise Invalid(f"{field} must be text")
    value = value.strip()
    if not value:
        if required:
            raise Invalid(f"{field} required")
        return None
    if len(value) > max_len:
        raise Invalid(f"{field} is too long (max {max_len} characters)")
    if _CONTROL.search(value):
        raise Invalid(f"{field} must be a single line without control characters")
    if not allow_markup and _MARKUP.search(value):
        raise Invalid(f"{field} must not contain < or >")
    return value


def free_text(value: Any, field: str, max_len: int) -> Optional[str]:
    """Optional multi-line text (descriptions, notes). Stored as typed; pages escape it."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise Invalid(f"{field} must be text")
    value = value.strip()
    if len(value) > max_len:
        raise Invalid(f"{field} is too long (max {max_len} characters)")
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
        raise Invalid(f"{field} must not contain control characters")
    return value or None


def keyword(value: Any, field: str = "keyword") -> str:
    # Keywords may be regular expressions or phrases with quotes, so markup
    # characters are allowed; line breaks and control characters are not.
    return text(value, field, 200, allow_markup=True)  # type: ignore[return-value]


def category(value: Any, default: str = "custom") -> str:
    if value is None or value == "":
        return default
    if not isinstance(value, str) or not _CATEGORY.match(value.strip()):
        raise Invalid("category may contain letters, digits, spaces and _ . & / + - (max 64 characters)")
    return value.strip()


def http_url(value: Any, field: str = "url", onion_only: bool = False) -> str:
    """An absolute http(s) URL with a host name; no credentials, spaces, quotes or angle brackets."""
    value = text(value, field, 2048)
    assert value is not None
    if _URL_UNSAFE.search(value):
        raise Invalid(f"{field} must not contain spaces, quotes or backslashes")
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        _ = parts.port
    except ValueError:
        raise Invalid(f"{field} is not a valid URL") from None
    if parts.scheme not in ("http", "https") or not host:
        raise Invalid(f"{field} must start with http:// or https://")
    if parts.username or parts.password:
        raise Invalid(f"{field} must not contain a user name or password")
    if onion_only and not host.endswith(".onion"):
        raise Invalid(f"{field} must be a .onion address")
    return value


def domain(value: Any, field: str = "domain") -> str:
    value = text(value, field, 253)
    assert value is not None
    value = value.lower().rstrip(".")
    if not _DOMAIN.match(value):
        raise Invalid(f"{field} is not a valid domain name")
    return value


def ip_address(value: Any, field: str = "ip") -> str:
    value = text(value, field, 45)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise Invalid("Invalid IP address") from None


def email(value: Any, field: str = "email", required: bool = True) -> Optional[str]:
    value = text(value, field, 254, required=required)
    if value is None:
        return None
    value = value.lower()
    if not _EMAIL.match(value):
        raise Invalid("valid email required")
    return value


def username(value: Any) -> str:
    value = text(value, "username", 64)
    assert value is not None
    if not _USERNAME.match(value):
        raise Invalid("username may contain letters, digits and . _ - (3 to 64 characters)")
    return value


def color(value: Any, default: str = "#f85149") -> str:
    if value is None or value == "":
        return default
    if not isinstance(value, str) or not _COLOR.match(value):
        raise Invalid("color must look like #1a2b3c")
    return value


def tags(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if not isinstance(value, list) or len(value) > 20:
        raise Invalid("tags must be a list of at most 20 short strings")
    return [text(t, "tag", 40) for t in value]  # type: ignore[misc]
