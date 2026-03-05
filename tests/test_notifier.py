"""Tests for netwatch.notifier"""

import time
from unittest.mock import MagicMock, patch

import pytest

from netwatch.models import Alert, Severity
from netwatch.notifier import Notifier


def _make_alert(severity=Severity.HIGH, rule="Test Rule", pid=1):
    return Alert(
        rule_name=rule,
        severity=severity,
        description="Test alert",
        pid=pid,
        process_name="test.exe",
        details={"remote_addr": "1.2.3.4"},
    )


class TestNotifierEnabled:
    def test_no_channels(self):
        n = Notifier()
        assert n.enabled is False

    def test_discord_enabled(self):
        n = Notifier(discord_webhook="https://discord.com/api/webhooks/test")
        assert n.enabled is True

    def test_slack_enabled(self):
        n = Notifier(slack_webhook="https://hooks.slack.com/test")
        assert n.enabled is True

    def test_email_needs_both(self):
        n = Notifier(email_to="user@example.com")
        assert n.enabled is False  # no SMTP
        n2 = Notifier(email_to="user@example.com", email_smtp="smtp.example.com")
        assert n2.enabled is True


class TestNotifierSeverityFilter:
    def test_filters_below_threshold(self):
        n = Notifier(discord_webhook="https://test", min_severity="HIGH")
        # LOW alert should not be sent
        with patch.object(n, "_dispatch") as mock_dispatch:
            n.send([_make_alert(severity=Severity.LOW)])
            mock_dispatch.assert_not_called()

    def test_passes_above_threshold(self):
        n = Notifier(discord_webhook="https://test", min_severity="MEDIUM")
        with patch.object(n, "_dispatch") as mock_dispatch:
            n.send([_make_alert(severity=Severity.HIGH)])
            # Should call _dispatch with at least one alert
            mock_dispatch.assert_called_once()

    def test_passes_equal_threshold(self):
        n = Notifier(discord_webhook="https://test", min_severity="HIGH")
        with patch.object(n, "_dispatch") as mock_dispatch:
            n.send([_make_alert(severity=Severity.HIGH)])
            mock_dispatch.assert_called_once()


class TestNotifierCooldown:
    def test_dedup_within_cooldown(self):
        n = Notifier(discord_webhook="https://test", cooldown_seconds=300)
        alert = _make_alert()

        with patch.object(n, "_dispatch") as mock_dispatch:
            n.send([alert])
            mock_dispatch.assert_called_once()

        # Second send of same alert should be cooled down
        with patch.object(n, "_dispatch") as mock_dispatch:
            n.send([alert])
            mock_dispatch.assert_not_called()

    def test_different_alerts_not_deduped(self):
        n = Notifier(discord_webhook="https://test", cooldown_seconds=300)
        a1 = _make_alert(rule="Rule A", pid=1)
        a2 = _make_alert(rule="Rule B", pid=2)

        with patch.object(n, "_dispatch") as mock_dispatch:
            n.send([a1, a2])
            mock_dispatch.assert_called_once()
            dispatched = mock_dispatch.call_args[0][0]
            assert len(dispatched) == 2


class TestNotifierMinSeverityParsing:
    def test_valid_severity(self):
        n = Notifier(min_severity="MEDIUM")
        assert n.min_severity == Severity.MEDIUM

    def test_invalid_falls_back_to_high(self):
        n = Notifier(min_severity="INVALID")
        assert n.min_severity == Severity.HIGH

    def test_case_insensitive(self):
        n = Notifier(min_severity="critical")
        assert n.min_severity == Severity.CRITICAL
