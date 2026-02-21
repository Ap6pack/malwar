# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Email notification channel via SMTP with HTML templates."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from malwar.notifications.base import NotificationChannel
from malwar.notifications.events import EventType, NotificationEvent

logger = logging.getLogger("malwar.notifications.email")

_EVENT_SUBJECTS = {
    EventType.SCAN_COMPLETE: "Scan Complete",
    EventType.THREAT_FOUND: "THREAT DETECTED",
    EventType.SCAN_FAILED: "Scan Failed",
}

_VERDICT_COLORS = {
    "MALICIOUS": "#dc3545",
    "SUSPICIOUS": "#fd7e14",
    "CAUTION": "#ffc107",
    "CLEAN": "#28a745",
}


def _build_html(event: NotificationEvent) -> str:
    """Render the notification as an HTML email body."""
    color = _VERDICT_COLORS.get(event.verdict, "#6c757d")
    label = _EVENT_SUBJECTS.get(event.event_type, "Notification")

    findings_rows = ""
    for f in event.findings_summary[:10]:
        findings_rows += (
            f"<tr>"
            f"<td style='padding:4px 8px;border-bottom:1px solid #eee'><code>{f.rule_id}</code></td>"
            f"<td style='padding:4px 8px;border-bottom:1px solid #eee'>{f.title}</td>"
            f"<td style='padding:4px 8px;border-bottom:1px solid #eee'>{f.severity}</td>"
            f"<td style='padding:4px 8px;border-bottom:1px solid #eee'>{f.confidence:.0%}</td>"
            f"</tr>"
        )

    findings_table = ""
    if findings_rows:
        findings_table = f"""
        <h3 style="margin-top:20px">Top Findings</h3>
        <table style="border-collapse:collapse;width:100%">
            <thead>
                <tr style="background:#f8f9fa">
                    <th style="padding:6px 8px;text-align:left">Rule</th>
                    <th style="padding:6px 8px;text-align:left">Title</th>
                    <th style="padding:6px 8px;text-align:left">Severity</th>
                    <th style="padding:6px 8px;text-align:left">Confidence</th>
                </tr>
            </thead>
            <tbody>{findings_rows}</tbody>
        </table>"""

    skill_line = ""
    if event.skill_name:
        skill_line = f"<p><strong>Skill:</strong> {event.skill_name}</p>"

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">
    <div style="background:{color};color:white;padding:16px;border-radius:8px 8px 0 0">
        <h1 style="margin:0;font-size:20px">malwar: {label}</h1>
    </div>
    <div style="border:1px solid #dee2e6;border-top:none;padding:20px;border-radius:0 0 8px 8px">
        <table style="width:100%">
            <tr><td><strong>Verdict:</strong></td><td style="color:{color};font-weight:bold">{event.verdict}</td></tr>
            <tr><td><strong>Risk Score:</strong></td><td>{event.risk_score}/100</td></tr>
            <tr><td><strong>Scan ID:</strong></td><td><code>{event.scan_id}</code></td></tr>
            <tr><td><strong>Findings:</strong></td><td>{event.finding_count}</td></tr>
            <tr><td><strong>Target:</strong></td><td>{event.target}</td></tr>
        </table>
        {skill_line}
        {findings_table}
        <p style="color:#6c757d;font-size:12px;margin-top:20px">
            Scanned at {event.timestamp.isoformat()} by malwar
        </p>
    </div>
</body>
</html>"""


class EmailChannel(NotificationChannel):
    """Send notification emails via SMTP with HTML formatting."""

    def __init__(
        self,
        *,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        smtp_use_tls: bool = True,
        from_addr: str = "",
        to_addrs: list[str] | None = None,
    ) -> None:
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._smtp_user = smtp_user
        self._smtp_password = smtp_password
        self._smtp_use_tls = smtp_use_tls
        self._from_addr = from_addr or smtp_user
        self._to_addrs = to_addrs or []

    @property
    def name(self) -> str:
        return "email"

    def is_configured(self) -> bool:
        return bool(self._smtp_host and self._to_addrs)

    async def send(self, event: NotificationEvent) -> bool:
        if not self.is_configured():
            logger.warning("Email channel not configured (missing host or recipients)")
            return False

        subject_label = _EVENT_SUBJECTS.get(event.event_type, "Notification")
        subject = f"[malwar] {subject_label}: {event.verdict} — {event.scan_id}"

        html_body = _build_html(event)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._from_addr
        msg["To"] = ", ".join(self._to_addrs)
        msg.attach(MIMEText(html_body, "html"))

        try:
            # Run SMTP in a blocking fashion — acceptable for notifications.
            # For production scale, consider using aiosmtplib.
            if self._smtp_use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    if self._smtp_user:
                        server.login(self._smtp_user, self._smtp_password)
                    server.sendmail(self._from_addr, self._to_addrs, msg.as_string())
            else:
                with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                    if self._smtp_user:
                        server.login(self._smtp_user, self._smtp_password)
                    server.sendmail(self._from_addr, self._to_addrs, msg.as_string())

            logger.info("Email notification sent for scan %s", event.scan_id)
            return True
        except Exception:
            logger.exception("Failed to send email notification for scan %s", event.scan_id)
            return False
