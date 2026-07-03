"""
Alerting module — sends notifications via webhook (Slack/Discord) or email
when keyword hits are found.
"""

import html
import json
import logging
import os
import smtplib
from dataclasses import dataclass
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from urllib.request import Request, urlopen

from .scanner import KeywordHit

logger = logging.getLogger(__name__)


@dataclass
class AlertConfig:
    webhook_url: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    alert_email_to: Optional[str] = None
    alert_email_from: Optional[str] = None

    @classmethod
    def from_env(cls) -> "AlertConfig":
        return cls(
            webhook_url=os.getenv("ALERT_WEBHOOK_URL"),
            smtp_host=os.getenv("SMTP_HOST"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_user=os.getenv("SMTP_USER"),
            smtp_password=os.getenv("SMTP_PASSWORD"),
            alert_email_to=os.getenv("ALERT_EMAIL_TO"),
            alert_email_from=os.getenv("ALERT_EMAIL_FROM", os.getenv("SMTP_USER")),
        )

    @property
    def webhook_enabled(self) -> bool:
        return bool(self.webhook_url)

    @property
    def email_enabled(self) -> bool:
        return all([self.smtp_host, self.smtp_user, self.smtp_password, self.alert_email_to])


class Alerter:
    def __init__(self, config: Optional[AlertConfig] = None):
        self.config = config or AlertConfig.from_env()

    def _format_hit_text(self, hit: KeywordHit) -> str:
        return (
            f"🔍 Keyword Hit: '{hit.keyword}'\n"
            f"Category: {hit.category}\n"
            f"URL: {hit.url}\n"
            f"Depth: {hit.depth}\n"
            f"Found at: {datetime.utcnow().isoformat()}Z\n\n"
            f"Context:\n{hit.context}"
        )

    def _format_webhook_payload(self, hit: KeywordHit) -> dict:
        """Slack/Discord compatible payload."""
        return {
            "text": "🚨 *Dark Web Keyword Alert*",
            "attachments": [
                {
                    "color": "#ff4444",
                    "fields": [
                        {"title": "Keyword", "value": hit.keyword, "short": True},
                        {"title": "Category", "value": hit.category, "short": True},
                        {"title": "URL", "value": hit.url, "short": False},
                        {"title": "Depth", "value": str(hit.depth), "short": True},
                        {
                            "title": "Context",
                            "value": hit.context[:500] + ("..." if len(hit.context) > 500 else ""),
                            "short": False,
                        },
                    ],
                    "ts": int(datetime.utcnow().timestamp()),
                }
            ],
        }

    def send_webhook(self, hit: KeywordHit) -> bool:
        if not self.config.webhook_enabled:
            return False
        try:
            payload = json.dumps(self._format_webhook_payload(hit)).encode("utf-8")
            req = Request(
                self.config.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                success = resp.status < 400
                if success:
                    logger.info(f"Webhook alert sent for keyword '{hit.keyword}'")
                else:
                    logger.warning(f"Webhook returned status {resp.status}")
                return success
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")
            return False

    def send_email(self, hit: KeywordHit) -> bool:
        if not self.config.email_enabled:
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Dark Web Scanner] Keyword hit: '{hit.keyword}'"
            msg["From"] = self.config.alert_email_from
            msg["To"] = self.config.alert_email_to

            text_content = self._format_hit_text(hit)
            html_content = f"""
            <html><body>
            <h2 style="color:#cc0000;">&#x1F6A8; Dark Web Keyword Alert</h2>
            <table style="border-collapse:collapse;width:100%">
                <tr><td style="font-weight:bold;padding:8px;background:#f5f5f5">Keyword</td>
                    <td style="padding:8px">{html.escape(hit.keyword)}</td></tr>
                <tr><td style="font-weight:bold;padding:8px;background:#f5f5f5">Category</td>
                    <td style="padding:8px">{html.escape(hit.category)}</td></tr>
                <tr><td style="font-weight:bold;padding:8px;background:#f5f5f5">URL</td>
                    <td style="padding:8px;word-break:break-all">{html.escape(hit.url)}</td></tr>
                <tr><td style="font-weight:bold;padding:8px;background:#f5f5f5">Depth</td>
                    <td style="padding:8px">{hit.depth}</td></tr>
                <tr><td style="font-weight:bold;padding:8px;background:#f5f5f5">Context</td>
                    <td style="padding:8px;font-family:monospace;white-space:pre-wrap">{html.escape(hit.context)}</td></tr>
            </table>
            </body></html>
            """

            msg.attach(MIMEText(text_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.starttls()
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.send_message(msg)

            logger.info(f"Email alert sent for keyword '{hit.keyword}'")
            return True
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
            return False

    def alert(self, hit: KeywordHit) -> bool:
        """Send all configured alerts for a hit. Returns True if at least one succeeded."""
        results = []
        if self.config.webhook_enabled:
            results.append(self.send_webhook(hit))
        if self.config.email_enabled:
            results.append(self.send_email(hit))
        if not results:
            logger.debug("No alerting channels configured")
        return any(results)

    def alert_batch(self, hits: list[KeywordHit]) -> int:
        """Alert on a batch of hits. Returns count of successful alerts."""
        return sum(1 for hit in hits if self.alert(hit))
