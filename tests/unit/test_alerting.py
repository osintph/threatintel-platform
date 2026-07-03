"""Unit tests for the Alerter class."""

from unittest.mock import MagicMock, patch

from darkweb_scanner.alerting import AlertConfig, Alerter
from darkweb_scanner.scanner import KeywordHit


def _make_hit(context: str = "normal context") -> KeywordHit:
    return KeywordHit(
        url="http://test.onion/page",
        keyword="credential dump",
        category="threat",
        context=context,
        position=0,
        depth=1,
    )


def _capture_email(alerter: Alerter, hit: KeywordHit):
    """Send email through a mock SMTP and return the captured MIMEMultipart message."""
    captured: dict = {}

    mock_server = MagicMock()
    mock_server.send_message.side_effect = lambda msg: captured.update({"msg": msg})

    with patch("darkweb_scanner.alerting.smtplib.SMTP") as mock_smtp_cls:
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
        alerter.send_email(hit)

    return captured["msg"]


def _html_body(msg) -> str:
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            payload = part.get_payload(decode=True)
            if payload is not None:
                return payload.decode("utf-8")
            return part.get_payload()
    return ""


def test_email_html_escapes_context():
    """SEC-08: HTML injected via scraped context must be escaped in the alert email."""
    config = AlertConfig(
        smtp_host="localhost",
        smtp_port=587,
        smtp_user="u@example.com",
        smtp_password="pass",
        alert_email_to="dest@example.com",
        alert_email_from="src@example.com",
    )
    alerter = Alerter(config)
    hit = _make_hit(context='<script>alert("xss")</script>')

    msg = _capture_email(alerter, hit)
    body = _html_body(msg)

    assert "<script>" not in body, "raw <script> tag must not appear in email HTML"
    assert "&lt;script&gt;" in body, "escaped &lt;script&gt; must appear instead"


def test_email_html_escapes_url():
    """SEC-08: a URL containing HTML characters must be escaped."""
    config = AlertConfig(
        smtp_host="localhost",
        smtp_port=587,
        smtp_user="u@example.com",
        smtp_password="pass",
        alert_email_to="dest@example.com",
        alert_email_from="src@example.com",
    )
    alerter = Alerter(config)
    hit = _make_hit()
    hit = KeywordHit(
        url='http://test.onion/<iframe>',
        keyword=hit.keyword,
        category=hit.category,
        context=hit.context,
        position=hit.position,
        depth=hit.depth,
    )

    msg = _capture_email(alerter, hit)
    body = _html_body(msg)

    assert "<iframe>" not in body
    assert "&lt;iframe&gt;" in body
