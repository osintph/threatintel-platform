"""
Public routes — no auth required.
Currently: /api/send-brief  (Mailgun email for threat brief gate)
"""
import logging
import os

import requests
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)
public_bp = Blueprint("public", __name__)

MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY", "")
MAILGUN_DOMAIN  = os.getenv("MAILGUN_DOMAIN", "intel.osintph.info")
FROM_ADDRESS    = f"OSINT PH <noreply@{MAILGUN_DOMAIN}>"
PDF_URL         = "https://www.osintph.info/files/osintph-threat-brief.pdf"


@public_bp.route("/api/send-brief", methods=["POST"])
def send_brief():
    data  = request.get_json(silent=True) or {}
    name  = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()

    if not name or not email or "@" not in email:
        return jsonify({"ok": False, "error": "Name and valid email required"}), 400

    # ── Email to the user ──────────────────────────────────────────────────
    user_text = "\n".join([
        f"Hi {name},",
        "",
        "Thank you for your interest in the OSINT PH Threat Intelligence Brief.",
        "",
        "You can download your copy using the link below:",
        PDF_URL,
        "",
        "The brief covers regional and global threat landscape analysis,",
        "active IOCs, CVE highlights, phishing campaign data, and dark web",
        "intelligence summary.",
        "",
        "If you have questions or would like to discuss a tailored threat",
        "assessment for your organisation, feel free to reply to this email.",
        "",
        "-- OSINT PH Team",
        "https://osintph.info",
    ])

    user_html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'IBM Plex Mono',monospace,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:40px 0">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#161b22;border:1px solid #30363d;max-width:600px;width:100%">

      <!-- Header -->
      <tr><td style="padding:28px 32px;border-bottom:1px solid #30363d;background:#161b22">
        <table cellpadding="0" cellspacing="0"><tr>
          <td style="width:10px;height:10px;background:#FF5C5C;border-radius:50%;font-size:0">&nbsp;</td>
          <td width="6"></td>
          <td style="width:10px;height:10px;background:#A8A8A8;border-radius:50%;font-size:0">&nbsp;</td>
          <td width="6"></td>
          <td style="width:10px;height:10px;background:#FFBD4A;border-radius:50%;font-size:0">&nbsp;</td>
          <td width="14"></td>
          <td style="font-family:'Syne',sans-serif;font-size:18px;font-weight:800;color:#f0f6fc;letter-spacing:1px">
            OSINT<span style="color:#FF5C5C">-</span>PH
          </td>
        </tr></table>
      </td></tr>

      <!-- Red accent line -->
      <tr><td style="height:2px;background:linear-gradient(90deg,#FF5C5C,transparent)"></td></tr>

      <!-- Body -->
      <tr><td style="padding:32px 32px 24px">
        <p style="font-family:'Share Tech Mono',monospace;font-size:9px;color:#FF5C5C;letter-spacing:3px;text-transform:uppercase;margin:0 0 20px">Threat Intelligence</p>
        <h1 style="font-family:'Syne',sans-serif;font-size:24px;font-weight:800;color:#f0f6fc;margin:0 0 16px;line-height:1.2">Your Threat Brief<br>is Ready</h1>
        <p style="color:#8b949e;font-size:13px;line-height:1.8;margin:0 0 28px">Hi {name},<br><br>
        Thank you for your interest in OSINT PH threat intelligence. Your copy of the brief is ready to download.</p>

        <!-- Download button -->
        <table cellpadding="0" cellspacing="0" style="margin-bottom:28px"><tr><td>
          <a href="{PDF_URL}" style="display:inline-block;background:#FF5C5C;color:#ffffff;font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;text-transform:uppercase;text-decoration:none;padding:13px 28px;border:1px solid #FF5C5C">
            &#8595; Download Threat Brief
          </a>
        </td></tr></table>

        <p style="color:#484f58;font-size:11px;line-height:1.7;margin:0">
          If the button above doesn't work, copy this link into your browser:<br>
          <a href="{PDF_URL}" style="color:#58a6ff;word-break:break-all">{PDF_URL}</a>
        </p>
      </td></tr>

      <!-- Footer -->
      <tr><td style="padding:20px 32px;border-top:1px solid #30363d;background:#0d1117">
        <table width="100%" cellpadding="0" cellspacing="0"><tr>
          <td style="font-family:'Share Tech Mono',monospace;font-size:10px;color:#484f58">
            &copy; 2026 OSINT PH &mdash; Digital Forensics &amp; Cybersecurity
          </td>
          <td align="right" style="font-family:'Share Tech Mono',monospace;font-size:10px">
            <a href="https://osintph.info" style="color:#8b949e;text-decoration:none">osintph.info</a>
          </td>
        </tr></table>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>
"""

    try:
        r = requests.post(
            f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
            auth=("api", MAILGUN_API_KEY),
            data={
                "from":    FROM_ADDRESS,
                "to":      f"{name} <{email}>",
                "subject": "Your OSINT PH Threat Intelligence Brief",
                "text":    user_text,
                "html":    user_html,
            },
            timeout=10,
        )
        r.raise_for_status()
        logger.info("Threat brief sent to %s (%s)", name, email)
    except Exception as exc:
        logger.error("Mailgun send failed: %s", exc)
        return jsonify({"ok": False, "error": "Failed to send email"}), 502

    # ── Internal notification (plain text, no frills) ──────────────────────
    try:
        notify_ua  = request.headers.get("User-Agent", "")[:120]
        notify_ref = request.headers.get("Referer", "direct")
        notify_ip  = request.headers.get("X-Forwarded-For", request.remote_addr)
        notify_text = "\n".join([
            "New threat brief download:",
            "",
            f"Name    : {name}",
            f"Email   : {email}",
            f"IP      : {notify_ip}",
            f"Referrer: {notify_ref}",
            f"UA      : {notify_ua}",
        ])
        requests.post(
            f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
            auth=("api", MAILGUN_API_KEY),
            data={
                "from":    FROM_ADDRESS,
                "to":      "sb@osintph.info",
                "subject": f"[OSINT PH] New download — {name}",
                "text":    notify_text,
            },
            timeout=10,
        )
    except Exception as exc:
        logger.warning("Internal notification failed (non-fatal): %s", exc)

    return jsonify({"ok": True})
