"""
Alerting module — sends notifications via webhook (Slack/Discord) or email
when keyword hits are found.

Nothing is sent in the caller's thread. alert() puts the hit on a bounded
queue and one background thread sends it, so a slow mail server or webhook
cannot stall a crawl. When the queue is full the alert is dropped and logged.
"""

import atexit
import html
import json
import logging
import os
import smtplib
import ssl
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Callable, Optional
from urllib.request import Request, urlopen

from .scanner import KeywordHit

logger = logging.getLogger(__name__)


def _env_number(name: str, default: float, minimum: float) -> float:
    try:
        return max(minimum, float(os.getenv(name, "") or default))
    except ValueError:
        logger.warning("%s is not a number; using %s", name, default)
        return default


# Seconds for each step of an SMTP conversation (connect, TLS, login, send).
SMTP_TIMEOUT = _env_number("SMTP_TIMEOUT", 15, 1)
WEBHOOK_TIMEOUT = 10
# Alerts waiting to be sent; one more than this is dropped.
ALERT_QUEUE_SIZE = int(_env_number("ALERT_QUEUE_SIZE", 200, 1))
# Longest a command waits at its end for queued alerts to go out.
ALERT_FLUSH_SECONDS = _env_number("ALERT_FLUSH_SECONDS", 20, 0)
# Implicit TLS from the first byte; every other port starts plain and must offer STARTTLS.
SMTPS_PORT = 465


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
        # urlopen would also open file: and ftp: addresses.
        return bool(self.webhook_url) and self.webhook_url.lower().startswith(("https://", "http://"))

    @property
    def email_enabled(self) -> bool:
        return all([self.smtp_host, self.smtp_user, self.smtp_password, self.alert_email_to])


class AlertSender:
    """A bounded queue of send jobs and the one thread that runs them."""

    def __init__(self, maxsize: int = ALERT_QUEUE_SIZE):
        self.maxsize = maxsize
        self._jobs: deque = deque()
        self._pending = 0  # waiting or being sent
        self._changed = threading.Condition()
        self._thread: Optional[threading.Thread] = None

    def submit(self, job: Callable[[], None]) -> bool:
        """Queue a job. False when the queue is full; never blocks."""
        with self._changed:
            if len(self._jobs) >= self.maxsize:
                return False
            self._jobs.append(job)
            self._pending += 1
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, daemon=True, name="alert-sender")
                self._thread.start()
            self._changed.notify_all()
        return True

    def _run(self) -> None:
        while True:
            with self._changed:
                while not self._jobs:
                    self._changed.wait()
                job = self._jobs.popleft()
            try:
                job()
            except Exception:
                logger.exception("Alert could not be sent")
            finally:
                with self._changed:
                    self._pending -= 1
                    self._changed.notify_all()

    def pending(self) -> int:
        with self._changed:
            return self._pending

    def flush(self, timeout: float) -> bool:
        """Wait until everything queued has been sent. False when ``timeout`` seconds were not enough."""
        deadline = time.monotonic() + timeout
        with self._changed:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._changed.wait(remaining)
        return True


_shared_sender: Optional[AlertSender] = None
_shared_lock = threading.Lock()


def _default_sender() -> AlertSender:
    """The sender every Alerter of this process shares."""
    global _shared_sender
    with _shared_lock:
        if _shared_sender is None:
            _shared_sender = AlertSender()
            atexit.register(_flush_at_exit)
        return _shared_sender


def _flush_at_exit() -> None:
    # A command (scan, telegram-scan) ends right after its last hit: give the
    # queued alerts a bounded time to go out before the process is gone.
    sender = _shared_sender
    if sender is not None and sender.pending() and not sender.flush(ALERT_FLUSH_SECONDS):
        logger.warning("%d alert(s) were not sent before the process ended", sender.pending())


def _one_line(value) -> str:
    """A header value: no line breaks or other control characters."""
    return "".join(" " if ord(ch) < 32 or ord(ch) == 127 else ch for ch in str(value))


class Alerter:
    def __init__(self, config: Optional[AlertConfig] = None, sender: Optional[AlertSender] = None):
        self.config = config or AlertConfig.from_env()
        self._sender = sender

    @property
    def sender(self) -> AlertSender:
        if self._sender is None:
            self._sender = _default_sender()
        return self._sender

    def _format_hit_text(self, hit: KeywordHit) -> str:
        return (
            f"🔍 Keyword Hit: '{hit.keyword}'\n"
            f"Category: {hit.category}\n"
            f"URL: {hit.url}\n"
            f"Depth: {hit.depth}\n"
            f"Found at: {datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}Z\n\n"
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
                    "ts": int(datetime.now(timezone.utc).replace(tzinfo=None).timestamp()),
                }
            ],
        }

    def send_webhook(self, hit: KeywordHit) -> bool:
        """Post the hit to the webhook now (blocks up to the timeout). Use alert() from a crawl."""
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
            # http and https only, see webhook_enabled
            with urlopen(req, timeout=WEBHOOK_TIMEOUT) as resp:
                success = resp.status < 400
                if success:
                    logger.info(f"Webhook alert sent for keyword '{hit.keyword}'")
                else:
                    logger.warning(f"Webhook returned status {resp.status}")
                return success
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")
            return False

    def _send_message(self, msg) -> None:
        """Hand a message to the mail server: timeout on every step, certificate checked."""
        context = ssl.create_default_context()
        host, port = self.config.smtp_host, self.config.smtp_port
        if port == SMTPS_PORT:
            with smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT, context=context) as server:
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.send_message(msg)
            return
        with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT) as server:
            # Fails when the server does not offer STARTTLS: the password is never sent in clear.
            server.starttls(context=context)
            server.login(self.config.smtp_user, self.config.smtp_password)
            server.send_message(msg)

    def send_email(self, hit: KeywordHit) -> bool:
        """Send the alert email now (blocks up to the timeouts). Use alert() from a crawl."""
        if not self.config.email_enabled:
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = _one_line(f"[Dark Web Scanner] Keyword hit: '{hit.keyword}'")
            msg["From"] = _one_line(self.config.alert_email_from)
            msg["To"] = _one_line(self.config.alert_email_to)

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

            self._send_message(msg)

            logger.info(f"Email alert sent for keyword '{hit.keyword}'")
            return True
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
            return False

    def send_now(self, hit: KeywordHit) -> bool:
        """Send on every configured channel, in this thread. True if at least one succeeded."""
        results = []
        if self.config.webhook_enabled:
            results.append(self.send_webhook(hit))
        if self.config.email_enabled:
            results.append(self.send_email(hit))
        return any(results)

    def alert(self, hit: KeywordHit, on_sent: Optional[Callable[[], None]] = None) -> bool:
        """Queue the alerts for a hit. Returns at once and never raises.

        True when the hit was queued; False when no channel is configured or
        the queue is full (the alert is then dropped, with a log line).
        ``on_sent`` is called from the sending thread once a channel has
        accepted the alert.
        """
        try:
            if not (self.config.webhook_enabled or self.config.email_enabled):
                logger.debug("No alerting channels configured")
                return False

            def job() -> None:
                if self.send_now(hit) and on_sent is not None:
                    on_sent()

            if self.sender.submit(job):
                return True
            logger.warning(
                "Alert queue is full (%d waiting): alert for keyword %r on %s dropped",
                self.sender.maxsize, hit.keyword, hit.url,
            )
            return False
        except Exception:
            logger.exception("Alert could not be queued")
            return False

    def flush(self, timeout: float = ALERT_FLUSH_SECONDS) -> bool:
        """Wait for the queued alerts to be sent. False when ``timeout`` seconds were not enough."""
        if self._sender is None and _shared_sender is None:
            return True
        return self.sender.flush(timeout)

    def alert_batch(self, hits: list[KeywordHit]) -> int:
        """Queue alerts for a batch of hits. Returns how many were queued."""
        return sum(1 for hit in hits if self.alert(hit))
