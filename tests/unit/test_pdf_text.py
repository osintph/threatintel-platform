"""
NET-3 (2026-11 audit): data placed in a ReportLab Paragraph is text, not markup.

A hit, a DNS record or a feed title containing "<" or "&" used to be parsed as
ReportLab markup, and one such value made the whole PDF export fail.
"""

from io import BytesIO

import pytest
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate

from darkweb_scanner.digest import build_digest_pdf
from darkweb_scanner.pdf_text import pdf_link, pdf_plain, pdf_text

_STYLE = getSampleStyleSheet()["Normal"]

HOSTILE = [
    "Jane <jane@example.com>",
    '<img src="http://127.0.0.1:1/x">',
    "a & b",
    "<b>unbalanced",
    "</para><para>",
    "tab\tnewline\nnull\x00 bell\x07 rtl‮ zero​width",
    '<link href="javascript:alert(1)">x</link>',
    "&#x41; &unknown; &lt;",
    "v=spf1 include:_spf.example.com ~all",
]


def _render(*paragraphs) -> bytes:
    buf = BytesIO()
    SimpleDocTemplate(buf).build(list(paragraphs))
    return buf.getvalue()


@pytest.mark.parametrize("value", HOSTILE)
def test_escaped_value_builds_and_renders_as_the_same_text(value):
    para = Paragraph(pdf_text(value), _STYLE)
    assert _render(para).startswith(b"%PDF")
    # What ReportLab will draw is the value itself, not a parse of it
    # (it folds runs of spaces, as it does for any paragraph).
    assert para.getPlainText().split() == pdf_plain(value).split()


def test_unescaped_values_are_parsed_as_markup_or_fail():
    """What happens without the helper: the export fails, or text silently disappears."""
    with pytest.raises(ValueError):
        Paragraph("<b>unbalanced", _STYLE)
    with pytest.raises((ValueError, OSError)):
        Paragraph('<img src="http://127.0.0.1:1/x">', _STYLE)
    assert Paragraph("Jane <jane@example.com>", _STYLE).getPlainText() == "Jane ", (
        "the address is dropped"
    )
    assert Paragraph("</para><para>", _STYLE).getPlainText() == ""


def test_pdf_text_escapes_cleans_and_caps():
    assert pdf_text("a & b < c > d") == "a &amp; b &lt; c &gt; d"
    assert pdf_text(None) == "" and pdf_text(0) == "0"
    assert pdf_text("x\x00y\nz‮") == "x y z "
    assert pdf_text("&" * 10, max_len=3) == "&amp;&amp;&amp;", (
        "cut before escaping, never inside an entity"
    )
    assert pdf_plain("a & <b>", max_len=5) == "a & <"


def test_pdf_link_allows_http_and_https_only():
    assert pdf_link("https://example.com/a?b=1&c=2") == (
        '<link href="https://example.com/a?b=1&amp;c=2" color="#0550ae">https://example.com/a?b=1&amp;c=2</link>'
    )
    assert pdf_link("http://example.com/", "CVE-2026-0001").endswith(">CVE-2026-0001</link>")
    for url in (
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,x",
        "//example.com/x",
        "",
        None,
    ):
        assert "<link" not in pdf_link(url), url
    quoted = pdf_link('https://example.com/"><b>x</b>')
    assert Paragraph(quoted, _STYLE).getPlainText() == 'https://example.com/"><b>x</b>'
    assert _render(Paragraph(pdf_link("https://example.com/a?b=1&c=2"), _STYLE)).startswith(b"%PDF")


def _hostile_feed():
    bad = "Jane <jane@example.com> & <b>co"
    return {
        "cisa_kev": [
            {
                "cve": bad,
                "url": 'https://example.com/"><b>',
                "title": bad,
                "vendor": bad,
                "product": bad,
                "due_date": bad,
            },
            {
                "cve": "CVE-2026-0001",
                "url": "https://example.com/kev",
                "title": "Fine",
                "vendor": "V",
                "product": "P",
                "due_date": "2026-12-01",
            },
        ],
        "otx_pulses": [
            {
                "author": bad,
                "title": bad,
                "description": bad * 40,
                "url": "javascript:alert(1)",
                "tags": [bad, "ok"],
                "sea_relevant": True,
            },
            {
                "author": "a",
                "title": None,
                "description": None,
                "url": "https://example.com/p",
                "tags": None,
            },
        ],
        "rss": [
            {"source": bad, "title": bad, "description": bad, "url": bad, "sea_relevant": True},
            {
                "source": "News",
                "title": "Readable headline",
                "description": "d",
                "url": "https://example.com/n",
            },
        ],
        "urlhaus": [{"host": 'evil.example/"><b>', "threat": bad, "tags": [bad], "status": bad}],
        "feodo": [
            {
                "ip": "203.0.113.9<b>",
                "port": 443,
                "malware": bad,
                "country": bad,
                "sea_relevant": True,
            }
        ],
    }


def test_digest_pdf_builds_with_markup_in_every_feed_field():
    pdf = build_digest_pdf(_hostile_feed())
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000


def test_one_item_that_cannot_be_laid_out_does_not_fail_the_digest(caplog):
    class Explodes:
        def __str__(self):
            raise RuntimeError("cannot be turned into text")

    feed = {
        "rss": [
            {
                "source": "News",
                "title": Explodes(),
                "description": "d",
                "url": "https://example.com/1",
            },
            {
                "source": "News",
                "title": "Second item",
                "description": "d",
                "url": "https://example.com/2",
            },
        ],
        "cisa_kev": [{"cve": Explodes()}],
    }
    with caplog.at_level("WARNING"):
        pdf = build_digest_pdf(feed)
    assert pdf.startswith(b"%PDF")
    assert caplog.text.count("skipped one") == 2
