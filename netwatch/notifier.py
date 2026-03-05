"""
Real-time Notifications — sends alerts via Discord, Slack, or email.

All transports use stdlib only (urllib, smtplib, email).
Notifications are throttled per (rule, pid, remote_addr) to avoid spam.
Dispatch runs in a background daemon thread to avoid blocking the monitor.
"""

from __future__ import annotations

import json
import logging
import smtplib
import threading
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from .models import Alert, Severity

logger = logging.getLogger("netwatch.notifier")


class Notifier:
    """Dispatches alert notifications to configured channels."""

    def __init__(
        self,
        *,
        discord_webhook: str = "",
        slack_webhook: str = "",
        email_to: str = "",
        email_smtp: str = "",
        email_port: int = 587,
        email_user: str = "",
        email_password: str = "",
        email_from: str = "netwatch@localhost",
        min_severity: str = "HIGH",
        cooldown_seconds: int = 300,
    ):
        self.discord_webhook = discord_webhook
        self.slack_webhook = slack_webhook
        self.email_to = email_to
        self.email_smtp = email_smtp
        self.email_port = email_port
        self.email_user = email_user
        self.email_password = email_password
        self.email_from = email_from
        self.cooldown_seconds = cooldown_seconds

        # Parse minimum severity
        try:
            self.min_severity = Severity[min_severity.upper()]
        except KeyError:
            self.min_severity = Severity.HIGH

        # Track sent notifications: key → last_sent_timestamp
        self._sent: dict[str, float] = {}
        self._lock = threading.Lock()

        # Severity ordering for filtering
        self._severity_order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }

    @property
    def enabled(self) -> bool:
        """True if at least one notification channel is configured."""
        return bool(self.discord_webhook or self.slack_webhook or
                     (self.email_to and self.email_smtp))

    def send(self, alerts: list[Alert]) -> None:
        """Filter and dispatch alerts asynchronously."""
        if not self.enabled:
            return

        now = time.time()
        min_ord = self._severity_order.get(self.min_severity, 2)

        # Filter by severity and cooldown
        to_send: list[Alert] = []
        with self._lock:
            for alert in alerts:
                if self._severity_order.get(alert.severity, 0) < min_ord:
                    continue

                key = self._dedup_key(alert)
                last_sent = self._sent.get(key, 0)
                if now - last_sent < self.cooldown_seconds:
                    continue

                self._sent[key] = now
                to_send.append(alert)

        if not to_send:
            return

        # Dispatch in a background thread
        thread = threading.Thread(
            target=self._dispatch,
            args=(to_send,),
            daemon=True,
        )
        thread.start()

    def _dispatch(self, alerts: list[Alert]) -> None:
        """Send alerts to all configured channels."""
        if self.discord_webhook:
            try:
                self._send_discord(alerts)
            except Exception:
                logger.error("Discord notification failed", exc_info=True)

        if self.slack_webhook:
            try:
                self._send_slack(alerts)
            except Exception:
                logger.error("Slack notification failed", exc_info=True)

        if self.email_to and self.email_smtp:
            try:
                self._send_email(alerts)
            except Exception:
                logger.error("Email notification failed", exc_info=True)

    # ------------------------------------------------------------------
    # Discord
    # ------------------------------------------------------------------

    def _send_discord(self, alerts: list[Alert]) -> None:
        """Send an embed to Discord via webhook."""
        severity_colors = {
            Severity.LOW: 0x3498DB,       # blue
            Severity.MEDIUM: 0xF1C40F,    # yellow
            Severity.HIGH: 0xE74C3C,      # red
            Severity.CRITICAL: 0x9B59B6,  # purple
        }

        # Build embeds (max ~6000 chars total for Discord)
        embeds = []
        for alert in alerts[:10]:  # Limit to 10 embeds
            embed = {
                "title": f"\u26a0\ufe0f {alert.rule_name}",
                "description": alert.description,
                "color": severity_colors.get(alert.severity, 0x95A5A6),
                "fields": [
                    {"name": "Severity", "value": alert.severity.value, "inline": True},
                    {"name": "PID", "value": str(alert.pid), "inline": True},
                    {"name": "Process", "value": alert.process_name, "inline": True},
                ],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(alert.timestamp)),
            }

            # Add detail fields
            if alert.details.get("remote_addr"):
                embed["fields"].append({
                    "name": "Remote",
                    "value": f"{alert.details['remote_addr']}:{alert.details.get('remote_port', '?')}",
                    "inline": True,
                })

            embeds.append(embed)

        payload = {
            "username": "NetWatch",
            "content": f"**NetWatch Alert** \u2014 {len(alerts)} new finding(s)",
            "embeds": embeds,
        }

        self._post_json(self.discord_webhook, payload)

    # ------------------------------------------------------------------
    # Slack
    # ------------------------------------------------------------------

    def _send_slack(self, alerts: list[Alert]) -> None:
        """Send a Block Kit message to Slack via webhook."""
        severity_emoji = {
            Severity.LOW: "\U0001f535",        # blue circle
            Severity.MEDIUM: "\U0001f7e1",     # yellow circle
            Severity.HIGH: "\U0001f534",        # red circle
            Severity.CRITICAL: "\U0001f7e3",    # purple circle
        }

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"\u26a0\ufe0f NetWatch: {len(alerts)} Alert(s)"},
            },
            {"type": "divider"},
        ]

        for alert in alerts[:15]:
            emoji = severity_emoji.get(alert.severity, "\u26aa")
            remote = ""
            if alert.details.get("remote_addr"):
                remote = f" \u2192 {alert.details['remote_addr']}:{alert.details.get('remote_port', '?')}"

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *[{alert.severity.value}] {alert.rule_name}*\n"
                        f"PID {alert.pid} (`{alert.process_name}`): "
                        f"{alert.description}{remote}"
                    ),
                },
            })

        payload = {"blocks": blocks}
        self._post_json(self.slack_webhook, payload)

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------

    def _send_email(self, alerts: list[Alert]) -> None:
        """Send an HTML email with alert details."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"NetWatch Alert: {len(alerts)} finding(s)"
        msg["From"] = self.email_from
        msg["To"] = self.email_to

        # Plain text body
        text_lines = [f"NetWatch detected {len(alerts)} alert(s):\n"]
        for alert in alerts:
            text_lines.append(f"[{alert.severity.value}] {alert.rule_name}")
            text_lines.append(f"  PID {alert.pid} ({alert.process_name}): {alert.description}")
            text_lines.append("")
        plain = "\n".join(text_lines)

        # HTML body
        severity_colors = {
            Severity.LOW: "#3498db",
            Severity.MEDIUM: "#f1c40f",
            Severity.HIGH: "#e74c3c",
            Severity.CRITICAL: "#9b59b6",
        }

        rows = []
        for alert in alerts:
            color = severity_colors.get(alert.severity, "#95a5a6")
            rows.append(
                f"<tr>"
                f"<td style='background:{color};color:#fff;padding:4px 8px;font-weight:bold'>"
                f"{alert.severity.value}</td>"
                f"<td style='padding:4px 8px'>{alert.rule_name}</td>"
                f"<td style='padding:4px 8px'>PID {alert.pid} ({alert.process_name})</td>"
                f"<td style='padding:4px 8px'>{alert.description}</td>"
                f"</tr>"
            )

        html = (
            "<html><body>"
            f"<h2>\u26a0\ufe0f NetWatch Alert</h2>"
            f"<p>{len(alerts)} finding(s) detected:</p>"
            "<table border='1' cellspacing='0' style='border-collapse:collapse;font-family:monospace;font-size:13px'>"
            "<tr style='background:#333;color:#fff'>"
            "<th style='padding:4px 8px'>Severity</th>"
            "<th style='padding:4px 8px'>Rule</th>"
            "<th style='padding:4px 8px'>Process</th>"
            "<th style='padding:4px 8px'>Description</th>"
            "</tr>"
            + "\n".join(rows) +
            "</table>"
            "<p style='color:#888;font-size:11px'>Generated by NetWatch</p>"
            "</body></html>"
        )

        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(self.email_smtp, self.email_port, timeout=30) as server:
            server.ehlo()
            if self.email_port == 587:
                server.starttls()
                server.ehlo()
            if self.email_user:
                server.login(self.email_user, self.email_password)
            server.sendmail(self.email_from, [self.email_to], msg.as_string())

        logger.info("Email notification sent to %s", self.email_to)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dedup_key(alert: Alert) -> str:
        """Generate a deduplication key for throttling."""
        remote = alert.details.get("remote_addr", "")
        return f"{alert.rule_name}:{alert.pid}:{remote}"

    @staticmethod
    def _post_json(url: str, payload: dict, timeout: int = 15) -> None:
        """POST JSON to a URL (webhook)."""
        data = json.dumps(payload).encode("utf-8")
        req = Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=timeout) as resp:
                logger.debug("Webhook POST %s → %s", url[:50], resp.status)
        except URLError as exc:
            logger.error("Webhook POST failed: %s", exc)
            raise
