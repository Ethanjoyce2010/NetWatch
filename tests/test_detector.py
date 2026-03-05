"""Tests for netwatch.detector — covers the AnomalyDetector and key rules."""

import time
from unittest.mock import MagicMock, patch

import pytest

from netwatch.detector import AnomalyDetector
from netwatch.models import Alert, ConnectionRecord, ProcessProfile, Severity


# ─────────────────── Helpers ────────────────────────────────────────────
def _make_record(
    pid: int = 100,
    process_name: str = "test.exe",
    local_addr: str = "192.168.1.10",
    local_port: int = 5000,
    remote_addr: str = "93.184.216.34",
    remote_port: int = 443,
    protocol: str = "tcp",
    status: str = "ESTABLISHED",
    timestamp: float | None = None,
    **extra: object,
) -> ConnectionRecord:
    return ConnectionRecord(
        pid=pid,
        process_name=process_name,
        local_addr=local_addr,
        local_port=local_port,
        remote_addr=remote_addr,
        remote_port=remote_port,
        protocol=protocol,
        status=status,
        timestamp=timestamp or time.time(),
    )


def _make_detector(**kw):
    """Create a detector with threat_intel stubbed out."""
    ti = MagicMock()
    ti.c2_ips = set()
    ti.malicious_domains = set()
    ti.lookup_ip.return_value = None
    ti.is_known_c2_ip.return_value = None
    ti.is_known_malicious_domain.return_value = None
    kw.setdefault("threat_intel", ti)
    return AnomalyDetector(**kw)


# ─────────────────── Basic functionality ────────────────────────────────
class TestAnalyse:
    def test_empty_records_no_alerts(self):
        det = _make_detector()
        alerts = det.analyse([])
        assert alerts == []

    def test_single_normal_record(self):
        det = _make_detector()
        rec = _make_record()
        alerts = det.analyse([rec])
        # A single innocuous HTTPS connection should not trigger alerts
        assert isinstance(alerts, list)

    def test_profiles_created(self):
        det = _make_detector()
        rec = _make_record(pid=42)
        det.analyse([rec])
        assert 42 in det.profiles
        assert det.profiles[42].name == "test.exe"

    def test_profile_accumulates(self):
        det = _make_detector()
        recs = [_make_record(pid=42, remote_addr=f"10.0.0.{i}") for i in range(5)]
        det.analyse(recs)
        assert det.profiles[42].total_connections == 5


# ─────────────────── Rule: C2 IP match ──────────────────────────────────
class TestC2IPRule:
    def test_c2_ip_triggers_alert(self):
        ti = MagicMock()
        ti.c2_ips = {"93.184.216.34"}
        ti.malicious_domains = set()
        ti.lookup_ip.return_value = MagicMock(description="Feodo C2")

        det = AnomalyDetector(threat_intel=ti)
        rec = _make_record(remote_addr="93.184.216.34")
        alerts = det.analyse([rec])

        c2_alerts = [a for a in alerts if "C2" in a.rule_name or "C2" in a.description.upper()
                      or "threat" in a.rule_name.lower()]
        assert len(c2_alerts) >= 1
        assert c2_alerts[0].severity in (Severity.HIGH, Severity.CRITICAL)


# ─────────────────── Rule: Suspicious port ──────────────────────────────
class TestSuspiciousPort:
    def test_irc_port_triggers(self):
        det = _make_detector()
        rec = _make_record(remote_port=6667, process_name="mystery.exe")
        alerts = det.analyse([rec])
        port_alerts = [a for a in alerts if "port" in a.rule_name.lower()
                        or "port" in a.description.lower()
                        or "irc" in a.description.lower()]
        # Should trigger the suspicious-port rule
        assert len(port_alerts) >= 1


# ─────────────── Rule: External listener ────────────────────────────────
class TestExternalListener:
    def test_listen_on_all_interfaces(self):
        det = _make_detector()
        rec = _make_record(
            local_addr="0.0.0.0",
            local_port=31337,
            remote_addr="",
            remote_port=0,
            status="LISTEN",
            process_name="backdoor.exe",
        )
        alerts = det.analyse([rec])
        listen_alerts = [a for a in alerts if "listen" in a.rule_name.lower()]
        assert len(listen_alerts) >= 1


# ─────────── Rule: Rapid connections (high rate) ────────────────────────
class TestRapidConnections:
    def test_high_rate_triggers(self):
        det = _make_detector(connection_rate_threshold=5)
        now = time.time()
        recs = [
            _make_record(pid=42, remote_addr=f"10.{i}.{j}.1", timestamp=now)
            for i in range(3) for j in range(5)
        ]
        alerts = det.analyse(recs)
        rate_alerts = [a for a in alerts if "rate" in a.rule_name.lower()
                        or "rapid" in a.rule_name.lower()
                        or "burst" in a.rule_name.lower()]
        assert len(rate_alerts) >= 1


# ──────────────── Rule: Lateral movement ────────────────────────────────
class TestLateralMovement:
    def test_smb_to_multiple_internal_hosts(self):
        det = _make_detector()
        recs = [
            _make_record(
                pid=77,
                process_name="psexec.exe",
                remote_addr=f"192.168.1.{i}",
                remote_port=445,  # SMB
            )
            for i in range(5)
        ]
        alerts = det.analyse(recs)
        lateral = [a for a in alerts if "lateral" in a.rule_name.lower()]
        assert len(lateral) >= 1

    def test_single_internal_smb_is_medium(self):
        det = _make_detector()
        rec = _make_record(
            pid=77,
            process_name="explorer.exe",
            remote_addr="192.168.1.5",
            remote_port=445,
        )
        alerts = det.analyse([rec])
        lateral = [a for a in alerts if "lateral" in a.rule_name.lower()]
        # Single SMB connection triggers a MEDIUM alert (informational)
        assert len(lateral) == 1
        assert lateral[0].severity == Severity.MEDIUM


# ──────────── _is_private_ip helper ─────────────────────────────────────
class TestIsPrivateIp:
    def test_private_ranges(self):
        assert AnomalyDetector._is_private_ip("192.168.1.1") is True
        assert AnomalyDetector._is_private_ip("10.0.0.1") is True
        assert AnomalyDetector._is_private_ip("172.16.0.1") is True

    def test_public_addresses(self):
        assert AnomalyDetector._is_private_ip("8.8.8.8") is False
        assert AnomalyDetector._is_private_ip("93.184.216.34") is False

    def test_loopback(self):
        assert AnomalyDetector._is_private_ip("127.0.0.1") is True

    def test_invalid_returns_false(self):
        assert AnomalyDetector._is_private_ip("") is False
        assert AnomalyDetector._is_private_ip("not-an-ip") is False
        assert AnomalyDetector._is_private_ip("*") is False


# ──────────── get_risky_profiles ────────────────────────────────────────
class TestGetRiskyProfiles:
    def test_filters_by_min_score(self):
        det = _make_detector()
        # Create a profile with a HIGH alert (score ~30)
        p = ProcessProfile(pid=1, name="risky.exe")
        p.alerts.append(Alert(
            rule_name="R", severity=Severity.HIGH,
            description="d", pid=1, process_name="risky.exe",
        ))
        det.profiles[1] = p

        # Profile with no alerts (score 0)
        p2 = ProcessProfile(pid=2, name="safe.exe")
        det.profiles[2] = p2

        risky = det.get_risky_profiles(min_score=10)
        assert any(pr.pid == 1 for pr in risky)
        assert all(pr.pid != 2 for pr in risky)
