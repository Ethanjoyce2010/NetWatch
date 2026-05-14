"""Tests for netwatch.reporter"""

import json
from datetime import datetime

from netwatch.models import Alert, ProcessProfile, Severity
from netwatch.reporter import Reporter


FIXED_TS = 1_700_000_000.0


def _make_alert(**overrides: object) -> Alert:
    return Alert(
        rule_name=overrides.get("rule_name", "Suspicious Port"),  # type: ignore[arg-type]
        severity=overrides.get("severity", Severity.HIGH),  # type: ignore[arg-type]
        description=overrides.get("description", "bad port"),  # type: ignore[arg-type]
        pid=overrides.get("pid", 4242),  # type: ignore[arg-type]
        process_name=overrides.get("process_name", "bad.exe"),  # type: ignore[arg-type]
        details=overrides.get("details", {"remote_port": 4444}),  # type: ignore[arg-type]
        timestamp=overrides.get("timestamp", FIXED_TS),  # type: ignore[arg-type]
    )


class TestReporterAlerts:
    def test_report_alerts_prints_and_writes_json_log(self, tmp_path, capsys):
        log_file = tmp_path / "nested" / "alerts.json"
        reporter = Reporter(log_file=str(log_file))

        reporter.report_alerts([_make_alert()])
        reporter.close()

        out = capsys.readouterr().out
        assert "[HIGH]" in out
        assert "Suspicious Port" in out
        assert "PID 4242" in out

        data = json.loads(log_file.read_text(encoding="utf-8"))
        assert data == [{
            "timestamp": datetime.fromtimestamp(FIXED_TS).isoformat(),
            "severity": "HIGH",
            "rule": "Suspicious Port",
            "pid": 4242,
            "process": "bad.exe",
            "description": "bad port",
            "details": {"remote_port": 4444},
        }]

    def test_json_log_multiple_alerts_is_valid_array(self, tmp_path):
        log_file = tmp_path / "alerts.json"
        reporter = Reporter(log_file=str(log_file))
        reporter.report_alerts([
            _make_alert(pid=1, process_name="one.exe"),
            _make_alert(pid=2, process_name="two.exe", severity=Severity.CRITICAL),
        ])
        reporter.close()

        data = json.loads(log_file.read_text(encoding="utf-8"))
        assert [row["pid"] for row in data] == [1, 2]
        assert data[1]["severity"] == "CRITICAL"

    def test_close_without_log_file_is_noop(self):
        Reporter().close()


class TestReporterStatusAndSummaries:
    def test_print_status_formats_elapsed_time(self, capsys):
        reporter = Reporter()

        reporter.print_status(n_connections=3, n_profiles=2, n_alerts=1, elapsed=65.4)

        out = capsys.readouterr().out
        assert "[01:05]" in out
        assert "Connections: 3" in out
        assert "Tracked processes: 2" in out
        assert "Total alerts: 1" in out

    def test_print_summary_empty(self, capsys):
        reporter = Reporter()

        reporter.print_summary([])

        assert "No suspicious processes detected" in capsys.readouterr().out

    def test_print_summary_includes_profile_metrics(self, capsys):
        reporter = Reporter()
        profile = ProcessProfile(pid=7, name="risky.exe", username="alice")
        profile.unique_remote_ips.update({"203.0.113.10", "203.0.113.11"})
        profile.unique_remote_ports.update({4444, 8443})
        profile.alerts.append(_make_alert(pid=7, process_name="risky.exe"))

        reporter.print_summary([profile])

        out = capsys.readouterr().out
        assert "risky.exe" in out
        assert "alice" in out
        assert "30" in out
        assert "2" in out

    def test_print_dll_scan_empty_result(self, capsys):
        reporter = Reporter()

        reporter.print_dll_scan([])

        assert "No suspicious DLL injections detected" in capsys.readouterr().out
