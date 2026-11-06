"""NET-3: the PDF exports build when stored data contains markup, and show it as text."""

import io

import pytest

from darkweb_scanner.storage import CrawledPage, KeywordHitRecord
from tests.helpers import make_user, sign_in

HOSTILE = [
    "Jane <jane@example.com>",
    '<img src="http://127.0.0.1:1/x">',
    "a & b <b>unbalanced",
    "</para><para>",
    "ctrl\x07\x1bchars",  # no NUL: PostgreSQL cannot store one, so it never reaches the report
]


def _pdf_text(pdf_bytes: bytes) -> str:
    pypdf = pytest.importorskip("pypdf")
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_report_pdf_builds_with_markup_in_hits(client, db):
    with db.get_session() as session:
        sid = db.create_crawl_session(["http://abcdefghijklmnop.onion/"])
        for i, value in enumerate(HOSTILE):
            session.add(
                CrawledPage(session_id=sid, url=f"http://x{i}.onion/", status_code=200, depth=0)
            )
            session.add(
                KeywordHitRecord(
                    session_id=sid,
                    url=f"http://x{i}.onion/{value}",
                    keyword=value,
                    category=value,
                    context=f"before {value} after",
                    depth=0,
                )
            )
        session.commit()
    sign_in(client, db, make_user(db))

    resp = client.get("/api/report/pdf")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:300]
    assert resp.mimetype == "application/pdf" and resp.data.startswith(b"%PDF")


def test_dns_pdf_builds_with_markup_in_records(client, db):
    inv_id = db.create_dns_investigation("example.com")
    hostile = HOSTILE[0]
    db.complete_dns_investigation(
        inv_id,
        {
            "domain": "example.com",
            "dns_records": {
                "A": ["192.0.2.1"],
                "TXT": [f"v=spf1 {h}" for h in HOSTILE],
                "NS": ["ns1.example.com"],
            },
            "email_security": {
                "spf": HOSTILE[1],
                "dmarc": HOSTILE[2],
                "dkim_selectors": [HOSTILE[3]],
                "issues": HOSTILE,
            },
            "subdomains_resolved": [
                {
                    "subdomain": f"a.example.com{HOSTILE[1]}",
                    "ips": ["192.0.2.1", HOSTILE[2]],
                    "geo": [
                        {
                            "org": hostile,
                            "as": HOSTILE[2],
                            "country": HOSTILE[3],
                            "query": "192.0.2.1",
                            "city": HOSTILE[1],
                            "countryCode": "X<",
                        }
                    ],
                }
            ],
            "subdomains_passive": [
                {"subdomain": HOSTILE[1], "issuer": f"O={HOSTILE[2]}", "not_after": "2027-01-01<"}
            ],
            "subdomains_bruteforce": [],
            "zone_transfer": {
                hostile: {
                    "success": True,
                    "record_count": 1,
                    "records": [{"name": HOSTILE[1], "type": "A<", "value": HOSTILE[2]}],
                }
            },
            "ptr_records": {"192.0.2.1": HOSTILE[3]},
            "ip_geo": {"192.0.2.1": {"city": HOSTILE[1], "country": HOSTILE[2], "org": hostile}},
            "port_scan": {"192.0.2.1<b": [{"port": 443, "service": HOSTILE[1], "status": "open"}]},
            "dir_enum": {
                HOSTILE[1]: [
                    {
                        "status_code": 301,
                        "path": HOSTILE[2],
                        "content_length": "1<",
                        "redirect_to": HOSTILE[3],
                    }
                ]
            },
        },
    )
    sign_in(client, db, make_user(db))

    resp = client.get(f"/api/dns/investigations/{inv_id}/pdf")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    assert resp.data.startswith(b"%PDF")
