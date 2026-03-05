"""Tests for netwatch.models"""

import time

from netwatch.models import (
    Alert,
    ConnectionRecord,
    ProcessProfile,
    Protocol,
    Severity,
)


# ───────────────────────────── Severity enum ────────────────────────────
class TestSeverity:
    def test_values(self):
        assert Severity.LOW.value == "LOW"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_from_string(self):
        assert Severity["HIGH"] is Severity.HIGH


# ───────────────────────────── Protocol enum ────────────────────────────
class TestProtocol:
    def test_values(self):
        assert Protocol.TCP.value == "tcp"
        assert Protocol.UDP.value == "udp"
        assert Protocol.TCP6.value == "tcp6"
        assert Protocol.UDP6.value == "udp6"


# ────────────────────────── ConnectionRecord ────────────────────────────
class TestConnectionRecord:
    def _make_record(self, **overrides: object) -> ConnectionRecord:
        return ConnectionRecord(
            pid=overrides.get("pid", 100),  # type: ignore[arg-type]
            process_name=overrides.get("process_name", "test.exe"),  # type: ignore[arg-type]
            local_addr=overrides.get("local_addr", "192.168.1.10"),  # type: ignore[arg-type]
            local_port=overrides.get("local_port", 5000),  # type: ignore[arg-type]
            remote_addr=overrides.get("remote_addr", "93.184.216.34"),  # type: ignore[arg-type]
            remote_port=overrides.get("remote_port", 443),  # type: ignore[arg-type]
            protocol=overrides.get("protocol", "tcp"),  # type: ignore[arg-type]
            status=overrides.get("status", "ESTABLISHED"),  # type: ignore[arg-type]
        )

    def test_defaults(self):
        rec = self._make_record()
        assert rec.pid == 100
        assert rec.process_name == "test.exe"
        assert rec.remote_port == 443
        assert rec.exe_path is None
        assert rec.geo_country is None
        assert rec.geo_country_name is None
        assert rec.geo_asn is None

    def test_timestamp_auto_filled(self):
        before = time.time()
        rec = self._make_record()
        after = time.time()
        assert before <= rec.timestamp <= after

    def test_geo_fields_settable(self):
        rec = self._make_record()
        rec.geo_country = "US"
        rec.geo_country_name = "United States"
        rec.geo_asn = "AS13335 Cloudflare"
        assert rec.geo_country == "US"


# ─────────────────────────────── Alert ──────────────────────────────────
class TestAlert:
    def test_str(self):
        a = Alert(
            rule_name="Test Rule",
            severity=Severity.HIGH,
            description="something bad",
            pid=42,
            process_name="bad.exe",
        )
        s = str(a)
        assert "HIGH" in s
        assert "Test Rule" in s
        assert "PID 42" in s

    def test_default_details(self):
        a = Alert(
            rule_name="R",
            severity=Severity.LOW,
            description="d",
            pid=1,
            process_name="p",
        )
        assert a.details == {}


# ────────────────────────── ProcessProfile ──────────────────────────────
class TestProcessProfile:
    def test_risk_score_no_alerts(self):
        p = ProcessProfile(pid=1, name="safe.exe")
        assert p.risk_score == 0

    def test_risk_score_with_alerts(self):
        p = ProcessProfile(pid=1, name="bad.exe")
        p.alerts.append(
            Alert(
                rule_name="R",
                severity=Severity.HIGH,
                description="d",
                pid=1,
                process_name="bad.exe",
            )
        )
        assert p.risk_score > 0

    def test_risk_score_caps_at_100(self):
        p = ProcessProfile(pid=1, name="bad.exe")
        for _ in range(20):
            p.alerts.append(
                Alert(
                    rule_name="R",
                    severity=Severity.CRITICAL,
                    description="d",
                    pid=1,
                    process_name="bad.exe",
                )
            )
        assert p.risk_score <= 100
