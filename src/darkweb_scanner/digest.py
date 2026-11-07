"""
Daily Threat Intelligence Digest — curated newsletter with feed data.
Separate from the crawl intelligence report (api/report/pdf).
API keys loaded from environment only — never hardcoded.
"""

import html
import logging
import os
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from urllib.parse import quote, urlparse

import requests

from .pdf_text import pdf_plain

logger = logging.getLogger(__name__)

MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY", "")
MAILGUN_DOMAIN = os.getenv("MAILGUN_DOMAIN", "intel.osintph.info")
MAILGUN_FROM = os.getenv("MAILGUN_FROM", "OSINT PH Threat Intel <digest@intel.osintph.info>")
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
SUBSCRIBERS_FILE = DATA_DIR / "digest_subscribers.txt"


def load_subscribers() -> list[str]:
    if not SUBSCRIBERS_FILE.exists():
        return []
    return [
        line.strip()
        for line in SUBSCRIBERS_FILE.read_text().splitlines()
        if line.strip() and "@" in line and not line.startswith("#")
    ]


def add_subscriber(email: str, name: str = "", org: str = "") -> bool:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    existing = load_subscribers()
    if email in existing:
        return False
    existing.append(email)
    SUBSCRIBERS_FILE.write_text("\n".join(existing) + "\n")
    meta_file = DATA_DIR / "digest_subscribers_meta.txt"
    with open(meta_file, "a") as f:
        f.write(f"{email}\t{name}\t{org}\t{datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}\n")
    return True


def remove_subscriber(email: str) -> bool:
    existing = load_subscribers()
    updated = [e for e in existing if e != email]
    if len(updated) == len(existing):
        return False
    SUBSCRIBERS_FILE.write_text("\n".join(updated) + "\n")
    return True


def build_digest_pdf(feed_data: dict, scanner_summary: dict = None, date: datetime = None) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    from .pdf_text import pdf_link, pdf_plain, pdf_text

    if date is None:
        date = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=8)

    date_str = date.strftime("%B %d, %Y")
    date_label = date.strftime("%Y-%m-%d")
    buf = BytesIO()
    W, H = A4
    M = 18 * mm
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=M, rightMargin=M, topMargin=M, bottomMargin=M)
    PW = W - 2 * M
    styles = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    s_h1 = S("h1", fontSize=24, fontName="Helvetica-Bold", textColor=colors.HexColor("#0d1117"), spaceAfter=2, leading=28)
    s_tagline = S("tl", fontSize=10, textColor=colors.HexColor("#f85149"), fontName="Helvetica-Bold", spaceAfter=4, leading=14)
    s_meta = S("meta", fontSize=8, textColor=colors.HexColor("#8b949e"), spaceAfter=0, leading=12)
    s_h3 = S("h3", fontSize=9.5, fontName="Helvetica-Bold", textColor=colors.HexColor("#f85149"), spaceBefore=8, spaceAfter=2)
    s_body = S("body", fontSize=8.5, textColor=colors.HexColor("#24292f"), leading=13, spaceAfter=3)
    s_small = S("small", fontSize=7.5, textColor=colors.HexColor("#57606a"), leading=11, spaceAfter=2)
    s_mono = S("mono", fontSize=7, fontName="Courier", textColor=colors.HexColor("#0550ae"), leading=10, wordWrap="CJK")
    s_link = S("link", fontSize=7.5, textColor=colors.HexColor("#0550ae"), leading=11, spaceAfter=2)
    s_src = S("src", fontSize=7, textColor=colors.HexColor("#8b949e"), fontName="Helvetica-Bold")
    s_footer = S("footer", fontSize=7, textColor=colors.HexColor("#8b949e"), leading=10)

    story = []

    # ── Masthead: two-column header with logo left, text right ──
    logo_cell = Table(
        [[
            Paragraph('<font color="#f85149" size="28"><b>⬡</b></font>', S("logo", fontSize=28, textColor=colors.HexColor("#f85149"), leading=32)),
        ]],
        colWidths=[14 * mm],
    )
    logo_cell.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    text_cell = Table(
        [[Paragraph("Daily Threat Intelligence", s_h1)],
         [Paragraph("powered by OSINT PH  ·  osintph.info", s_tagline)],
         [Paragraph(f"Edition: {date_str} (PHT)  ·  Generated: {datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M UTC')}", s_meta)]],
        colWidths=[PW - 16 * mm],
    )
    text_cell.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    header_tbl = Table([[logo_cell, text_cell]], colWidths=[16 * mm, PW - 16 * mm])
    header_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LINEBELOW", (0, 0), (-1, -1), 0, colors.white),
    ]))
    story.append(HRFlowable(width=PW, thickness=4, color=colors.HexColor("#f85149"), spaceAfter=10))
    story.append(header_tbl)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de"), spaceAfter=10))

    def sec(emoji, title, color="#0d1117"):
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"{emoji}  {title}", S(f"sec{title[:8]}", fontSize=12, fontName="Helvetica-Bold",
            textColor=colors.HexColor(color), spaceBefore=10, spaceAfter=4)))
        story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de"), spaceAfter=4))

    def skipped(section, exc):
        # Feed text is third-party data. One item that cannot be laid out is
        # left out; it must not take the whole digest down with it.
        logger.warning("digest PDF: skipped one %s item: %s", section, exc)

    def item_block(source, title, desc, url="", tags=None, highlight=False, max_tags=5):
        try:
            _item_block(source, title, desc, url, tags, highlight, max_tags)
        except Exception as exc:
            skipped("news", exc)

    def _item_block(source, title, desc, url, tags, highlight, max_tags):
        bg = colors.HexColor("#fff8f8") if highlight else colors.HexColor("#f6f8fa")
        border = colors.HexColor("#f85149") if highlight else colors.HexColor("#d0d7de")
        tag_str = "  ".join([f"[{pdf_text(t, 40)}]" for t in list(tags or [])[:max_tags]])
        title_para = Paragraph(f"<b>{pdf_text(title, 120)}</b>", s_body)
        desc_para = Paragraph(pdf_text(desc, 350) + ("..." if len(str(desc or "")) > 350 else ""), s_small)
        inner = [[title_para], [desc_para]]
        if tag_str:
            inner.append([Paragraph(tag_str, s_src)])
        if url:
            # Clickable link in PDF (http and https only)
            inner.append([Paragraph("\u2192 " + pdf_link(url, max_len=90), s_link)])
        inner.append([Paragraph(f"Source: {pdf_text(source, 120)}", s_src)])
        tbl = Table(inner, colWidths=[PW - 10])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("BOX", (0, 0), (-1, -1), 0.8, border),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (0, 0), 6),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
            ("TOPPADDING", (0, 1), (-1, -1), 2),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 5))

    kev = feed_data.get("cisa_kev", [])
    if kev:
        sec("🚨", "CISA Known Exploited Vulnerabilities", "#f85149")
        story.append(Paragraph("Patch immediately if affected products are in use.", s_small))
        story.append(Spacer(1, 4))
        kd = [["CVE", "Vulnerability", "Vendor / Product", "Due"]]
        for v in kev[:10]:
            try:
                cve_link = Paragraph(pdf_link(v.get("url"), v.get("cve"), max_len=30), s_mono)
                kd.append([cve_link, Paragraph(pdf_text(v.get("title"), 60), s_small),
                           Paragraph(pdf_text(f"{v.get('vendor', '')} - {v.get('product', '')}", 50), s_small),
                           Paragraph(pdf_text(v.get("due_date"), 20), s_small)])
            except Exception as exc:
                skipped("CISA KEV", exc)
        kt = Table(kd, colWidths=[PW*0.16, PW*0.36, PW*0.30, PW*0.18], repeatRows=1)
        kt.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#f85149")),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0),(-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#fff8f8"), colors.white]),
            ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#d0d7de")),
            ("PADDING", (0,0),(-1,-1), 5),
            ("VALIGN", (0,0),(-1,-1), "TOP"),
        ]))
        story.append(kt)

    otx = feed_data.get("otx_pulses", [])
    sea_otx = [p for p in otx if p.get("sea_relevant")]
    other_otx = [p for p in otx if not p.get("sea_relevant")]
    if sea_otx:
        sec("🌏", "Philippines & SEA Threat Intelligence")
        for p in sea_otx[:6]:
            item_block(f"OTX · {p.get('author','')}", p.get("title",""), p.get("description",""),
                      p.get("url",""), p.get("tags"), highlight=True)
    if other_otx:
        sec("🔭", "Global Threat Intelligence (OTX)")
        for p in other_otx[:4]:
            item_block(f"OTX · {p.get('author','')}", p.get("title",""), p.get("description",""),
                      p.get("url",""), p.get("tags"), max_tags=4)

    rss = feed_data.get("rss", [])
    sea_rss = [r for r in rss if r.get("sea_relevant")]
    other_rss = [r for r in rss if not r.get("sea_relevant")]
    if sea_rss:
        sec("📰", "SEA Cybersecurity News")
        for r in sea_rss[:5]:
            item_block(r.get("source",""), r.get("title",""), r.get("description",""), r.get("url",""), highlight=True)
    if other_rss:
        sec("🌐", "Global Cybersecurity News")
        for r in other_rss[:5]:
            item_block(r.get("source",""), r.get("title",""), r.get("description",""), r.get("url",""))

    urlhaus = feed_data.get("urlhaus", [])
    feodo = [f for f in feed_data.get("feodo", []) if f.get("sea_relevant")]
    if urlhaus or feodo:
        sec("🦠", "Active Malware Infrastructure (IOCs)")
        if urlhaus:
            story.append(Paragraph("Recent Malicious URLs — URLhaus (abuse.ch)", s_h3))
            ud = [["Host", "Threat", "Tags", "Status"]]
            for u in urlhaus[:8]:
                try:
                    host = pdf_plain(u.get("host"), 255)
                    host_link = Paragraph(
                        pdf_link(f"https://urlhaus.abuse.ch/host/{quote(host, safe='')}/", host, max_len=40),
                        s_mono
                    )
                    ud.append([host_link, Paragraph(pdf_text(u.get("threat"), 25), s_small),
                               Paragraph(pdf_text(", ".join(str(t) for t in (u.get("tags") or [])[:3]), 80), s_small),
                               Paragraph(pdf_text(u.get("status"), 20), s_small)])
                except Exception as exc:
                    skipped("URLhaus", exc)
            ut = Table(ud, colWidths=[PW*0.35, PW*0.22, PW*0.28, PW*0.15], repeatRows=1)
            ut.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#161b22")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f6f8fa"),colors.white]),
                ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0d7de")),("PADDING",(0,0),(-1,-1),4),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
            ]))
            story.append(ut)
        if feodo:
            story.append(Spacer(1, 6))
            story.append(Paragraph("SEA C2 Botnet IPs — Feodo Tracker (abuse.ch)", s_h3))
            fd = [["IP", "Port", "Malware", "Country"]]
            for f in feodo[:6]:
                try:
                    ip = pdf_plain(f.get("ip"), 45)
                    ip_link = Paragraph(
                        pdf_link(f"https://feodotracker.abuse.ch/browse/?search={quote(ip, safe='')}", ip, max_len=45),
                        s_mono
                    )
                    # Plain strings in a table cell are not parsed as markup: cleaned, not escaped.
                    fd.append([ip_link, pdf_plain(f.get("port"), 8), pdf_plain(f.get("malware"), 40),
                               pdf_plain(f.get("country"), 40)])
                except Exception as exc:
                    skipped("Feodo", exc)
            ft = Table(fd, colWidths=[PW*0.3, PW*0.12, PW*0.28, PW*0.3])
            ft.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#161b22")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#fff8f8"),colors.white]),
                ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0d7de")),("PADDING",(0,0),(-1,-1),4),
            ]))
            story.append(ft)

    # Scanner summary intentionally excluded — available in separate Scanner Intelligence Report

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width=PW, thickness=0.5, color=colors.HexColor("#d0d7de")))
    story.append(Spacer(1, 5))
    story.append(Paragraph(
        f'CONFIDENTIAL — Daily Threat Intelligence powered by <link href="https://osintph.info" color="#f85149">OSINT PH</link> · '
        f'To unsubscribe reply UNSUBSCRIBE · Report ID: OSINTPH-DIGEST-{date_label}',
        s_footer))
    doc.build(story)
    buf.seek(0)
    return buf.read()


def _esc(value, max_len: int = 2000) -> str:
    """A feed value as HTML text: cleaned, cut to max_len characters, then escaped."""
    return html.escape(pdf_plain(value, max_len), quote=True)


def _http_url(value) -> str:
    """The URL when it is a plain http(s) address, else an empty string (no link is made)."""
    url = pdf_plain(value, 2000).strip()
    if not url or any(ch.isspace() for ch in url):
        return ""
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        return ""
    return url


def _one_line(value) -> str:
    """A mail header value: no line breaks or other control characters."""
    return " ".join(pdf_plain(value, 300).split())


def digest_subject(date_str: str) -> str:
    # The date only: nothing from a feed is ever placed in a header.
    return _one_line(f"Daily Threat Intelligence - {date_str} | OSINT PH")


def digest_text(date_str: str) -> str:
    """The plain-text part. It names the date and nothing from a feed."""
    return f"Daily Threat Intelligence powered by OSINT PH\n{_one_line(date_str)}\nFull report attached.\nosintph.info"


def _valid_recipient(address) -> bool:
    """One address, with nothing that could add a second recipient or a header."""
    if not isinstance(address, str) or not 3 <= len(address) <= 254 or address.count("@") != 1:
        return False
    return not any(ch.isspace() or ord(ch) < 32 or ch in ",;<>\"'" for ch in address)


def build_email_html(feed_data: dict, date_str: str, stats: dict) -> str:  # noqa: ARG001
    """The HTML part of the digest mail.

    Feed titles, descriptions, sources and URLs are written by third parties
    (OTX pulses by anyone with an account). Every value is escaped, and only
    http and https URLs become links; with any other URL the text is kept and
    the link is dropped.
    """
    kev = feed_data.get("cisa_kev") or []
    sea_items = ([p for p in feed_data.get("otx_pulses") or [] if p.get("sea_relevant")] +
                 [r for r in feed_data.get("rss") or [] if r.get("sea_relevant")])[:6]
    global_items = [r for r in feed_data.get("rss") or [] if not r.get("sea_relevant")][:5]

    # Build KEV rows — no nested f-strings (Python 3.11 compat)
    kev_row_parts = []
    for i, v in enumerate(kev[:8]):
        row_bg = "#fff8f8" if i % 2 == 0 else "#ffffff"
        cve = pdf_plain(v.get("cve"), 40).strip()
        cve_url = html.escape(f"https://nvd.nist.gov/vuln/detail/{quote(cve, safe='')}", quote=True)
        kev_row_parts.append(
            f'<tr style="background:{row_bg}">'
            f'<td style="padding:6px 10px;font-size:11px;font-family:monospace;border-bottom:1px solid #d0d7de">'
            f'<a href="{cve_url}" style="color:#f85149;text-decoration:none">{_esc(cve)}</a></td>'
            f'<td style="padding:6px 10px;font-size:11px;border-bottom:1px solid #d0d7de">{_esc(v.get("title"), 60)}</td>'
            f'<td style="padding:6px 10px;font-size:11px;color:#57606a;border-bottom:1px solid #d0d7de">{_esc(v.get("vendor"), 80)}</td>'
            f'</tr>'
        )
    kev_rows = "".join(kev_row_parts)

    def news_rows(items, highlight=False):
        rows = ""
        for item in items:
            bg = "#fff8f8" if highlight else "#ffffff"
            title = _esc(item.get("title"), 100)
            desc = _esc(item.get("description"), 200)
            source = _esc(item.get("source"), 80)
            url = html.escape(_http_url(item.get("url")), quote=True)
            read_more = (
                f' · <a href="{url}" style="color:#58a6ff;text-decoration:none">Read more →</a>'
                if url else ""
            )
            title_html = (
                f'<a href="{url}" style="color:#0d1117;text-decoration:none;font-weight:600">{title}</a>'
                if url else f'<span style="font-weight:600">{title}</span>'
            )
            rows += (
                f'<tr style="background:{bg}">'
                f'<td style="padding:10px 12px;border-bottom:1px solid #d0d7de">'
                f'<div style="font-size:13px;margin-bottom:3px">{title_html}</div>'
                f'<div style="font-size:11px;color:#57606a;margin-bottom:4px">{desc}</div>'
                f'<div style="font-size:10px;color:#8b949e">'
                f'<b style="color:#f85149">{source}</b>{read_more}'
                f'</div></td></tr>'
            )
        return rows

    kev_section = "" if not kev else (
        f'<div style="background:#fff8f8;border-left:4px solid #f85149;padding:16px 20px">'
        f'<div style="font-size:13px;font-weight:700;color:#f85149;margin-bottom:8px">'
        f'&#x1F6A8; CISA: {len(kev)} Exploited Vulnerabilities This Week</div>'
        f'<table style="width:100%;border-collapse:collapse;background:white">'
        f'<tr style="background:#f85149">'
        f'<th style="padding:6px 10px;font-size:11px;color:white;text-align:left">CVE</th>'
        f'<th style="padding:6px 10px;font-size:11px;color:white;text-align:left">Vulnerability</th>'
        f'<th style="padding:6px 10px;font-size:11px;color:white;text-align:left">Vendor</th></tr>'
        f'{kev_rows}</table></div>'
    )

    sea_section = "" if not sea_items else (
        f'<div style="padding:16px 20px 0">'
        f'<div style="font-size:14px;font-weight:700;color:#0d1117;margin-bottom:8px">&#x1F1F5;&#x1F1ED; Philippines &amp; SEA Focus</div>'
        f'<table style="width:100%;border-collapse:collapse;border:1px solid #d0d7de">'
        f'{news_rows(sea_items, True)}</table></div>'
    )

    global_section = "" if not global_items else (
        f'<div style="padding:16px 20px 0">'
        f'<div style="font-size:14px;font-weight:700;color:#0d1117;margin-bottom:8px">&#x1F310; Global Cybersecurity News</div>'
        f'<table style="width:100%;border-collapse:collapse;border:1px solid #d0d7de">'
        f'{news_rows(global_items)}</table></div>'
    )

    return (
        f'<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;background:#f6f8fa">'
        f'<div style="background:#0d1117;padding:24px 28px;border-bottom:4px solid #f85149">'
        f'<div style="font-size:22px;font-weight:800;color:white;margin-bottom:2px">Daily Threat Intelligence</div>'
        f'<div style="font-size:12px;color:#f85149;font-weight:700;margin-bottom:6px">powered by OSINT PH</div>'
        f'<div style="font-size:11px;color:#8b949e">{_esc(date_str, 60)} · Full report attached as PDF</div>'
        f'</div>'
        f'{kev_section}{sea_section}{global_section}'
        f'<div style="padding:14px 20px 16px;background:#0d1117;margin-top:10px">'
        f'<p style="color:#8b949e;font-size:11px;margin:0">CONFIDENTIAL · '
        f'<a href="https://osintph.info" style="color:#f85149">osintph.info</a> · '
        f'Reply UNSUBSCRIBE to opt out</p>'
        f'</div>'
        f'</div>'
    )


def send_digest(storage, recipients: list = None, date: datetime = None) -> dict:
    if not MAILGUN_API_KEY:
        return {"ok": False, "error": "MAILGUN_API_KEY not set in environment"}
    if recipients is None:
        recipients = load_subscribers()
    if not recipients:
        return {"ok": False, "error": "No subscribers configured"}
    if date is None:
        date = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=8)

    date_str = date.strftime("%B %d, %Y")
    date_label = date.strftime("%Y-%m-%d")

    from .feeds import fetch_all_feeds
    try:
        feed_data = fetch_all_feeds()
    except Exception:
        logger.exception("Feed fetch failed")
        feed_data = {"otx_pulses":[],"cisa_kev":[],"urlhaus":[],"feodo":[],"rss":[]}

    stats = storage.get_stats()
    top_kw = stats.get("top_keywords", [{}])
    scanner_summary = {
        "total_hits": stats.get("total_hits", 0),
        "total_pages": stats.get("total_pages", 0),
        "total_sessions": stats.get("total_sessions", 0),
        "top_keyword": top_kw[0].get("keyword","—") if top_kw else "—",
    }

    try:
        pdf_bytes = build_digest_pdf(feed_data, scanner_summary=scanner_summary, date=date)
    except Exception:
        logger.exception("PDF build failed")
        return {"ok": False, "error": "PDF build failed. Details are in the server log."}

    filename = f"osintph-threat-digest-{date_label}.pdf"
    subject = digest_subject(date_str)
    html_body = build_email_html(feed_data, date_str, stats)
    text_body = digest_text(date_str)

    errors, sent = [], 0
    for recipient in recipients:
        if not _valid_recipient(recipient):
            errors.append(f"{_one_line(recipient)[:80]}: not a single email address, skipped")
            continue
        try:
            resp = requests.post(
                f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
                auth=("api", MAILGUN_API_KEY),
                files=[("attachment", (filename, pdf_bytes, "application/pdf"))],
                data={"from": MAILGUN_FROM, "to": recipient, "subject": subject,
                      "html": html_body, "text": text_body},
                timeout=30,
            )
            if resp.status_code == 200:
                sent += 1
                logger.info(f"Digest sent to {recipient}")
            else:
                errors.append(f"{recipient}: HTTP {resp.status_code}")
        except Exception:
            logger.exception("Digest could not be sent to %s", recipient)
            errors.append(f"{recipient}: could not be sent")

    return {"ok": sent > 0, "sent": sent, "total": len(recipients), "errors": errors}
