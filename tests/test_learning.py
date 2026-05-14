"""Tests for netwatch.learning"""

import json

from netwatch.learning import LearningWhitelistBuilder
from netwatch.models import Alert, Severity


def _make_alert(
    rule_name: str = "External Listener",
    severity: Severity = Severity.MEDIUM,
    process_name: str = "safe.exe",
    details: dict | None = None,
) -> Alert:
    return Alert(
        rule_name=rule_name,
        severity=severity,
        description="learn me",
        pid=10,
        process_name=process_name,
        details=details or {},
    )


class TestLearningWhitelistBuilder:
    def test_learns_low_and_medium_broad_rules(self):
        builder = LearningWhitelistBuilder()

        data = builder.build([
            _make_alert("External Listener", Severity.MEDIUM, "safe.exe"),
            _make_alert("Unexpected Network Process", Severity.CRITICAL, "bad.exe"),
        ])

        assert data["safe.exe"] == ["External Listener"]
        assert "bad.exe" not in data

    def test_learns_connection_specific_rules(self):
        builder = LearningWhitelistBuilder()

        data = builder.build([
            _make_alert(
                "External High-Port Connection",
                Severity.LOW,
                "browser.exe",
                {"remote_addr": "203.0.113.10", "remote_port": 55000},
            )
        ])

        assert data["browser.exe"] == [{
            "rule": "External High-Port Connection",
            "remote_addr": "203.0.113.10",
            "remote_port": 55000,
        }]

    def test_min_occurrences_filters_rare_alerts(self):
        builder = LearningWhitelistBuilder()

        data = builder.build([
            _make_alert("External Listener", Severity.MEDIUM, "one.exe"),
            _make_alert("External Listener", Severity.MEDIUM, "two.exe"),
            _make_alert("External Listener", Severity.MEDIUM, "two.exe"),
        ], min_occurrences=2)

        assert "one.exe" not in data
        assert data["two.exe"] == ["External Listener"]

    def test_write_merges_existing_whitelist(self, tmp_path):
        target = tmp_path / "whitelist.json"
        target.write_text(json.dumps({"old.exe": ["Existing Rule"]}), encoding="utf-8")
        builder = LearningWhitelistBuilder()

        builder.write([
            _make_alert("External Listener", Severity.MEDIUM, "safe.exe"),
        ], str(target))

        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["old.exe"] == ["Existing Rule"]
        assert data["safe.exe"] == ["External Listener"]
        assert "_learned_at" in data
