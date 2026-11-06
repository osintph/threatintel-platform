"""
Text for ReportLab.

ReportLab's Paragraph reads its text as a small XML markup (<b>, <font>,
<link>, <img> ...). A value that reaches it unescaped is parsed as markup:
one stray "<" or "&" in a hit, a DNS record or a feed title makes the
paragraph fail to build, and the whole export with it.

Every value that does not come from this code base goes through pdf_text()
before it is put into a Paragraph, and through pdf_link() when it is a URL.
Plain strings placed directly in a Table cell are not parsed as markup; use
pdf_plain() for those, so they are cleaned but not escaped.
"""

import unicodedata
from typing import Optional
from urllib.parse import urlparse
from xml.sax.saxutils import escape, quoteattr

# Control, format (zero-width, bidi overrides) and surrogate characters.
_UNPRINTABLE = ("Cc", "Cf", "Cs")


def pdf_plain(value, max_len: int = 2000) -> str:
    """value as one line of plain text: no control characters, at most max_len characters."""
    text = "" if value is None else str(value)
    text = "".join(" " if unicodedata.category(ch) in _UNPRINTABLE else ch for ch in text)
    return text[:max_len]


def pdf_text(value, max_len: int = 2000) -> str:
    """value escaped for a ReportLab Paragraph: it is shown as text, never parsed as markup.

    The value is cut to max_len characters before it is escaped, so an entity
    is never cut in half.
    """
    return escape(pdf_plain(value, max_len))


def pdf_link(url, text: Optional[str] = None, color: str = "#0550ae", max_len: int = 90) -> str:
    """Paragraph markup for a clickable link showing text (default: the URL itself).

    Only http and https URLs become links. Anything else is shown as text.
    """
    target = pdf_plain(url, 2000).strip()
    label = pdf_text(target if text is None else text, max_len)
    try:
        parsed = urlparse(target)
    except ValueError:
        return label
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        return label
    return f"<link href={quoteattr(target)} color={quoteattr(color)}>{label}</link>"
