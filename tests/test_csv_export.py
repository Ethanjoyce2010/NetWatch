"""Tests for netwatch.csv_export"""

import csv
from datetime import datetime
from pathlib import Path

from netwatch.csv_export import export_alerts_csv, export_connections_csv
from netwatch.models import Alert, ConnectionRecord, Severity


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


def _make_record(**overrides: object) -> ConnectionRecord:
    return ConnectionRecord(
        pid=overrides.get("pid", 100),  # type: ignore[arg-type]
        process_name=overrides.get("process_name", "app.exe"),  # type: ignore[arg-type]
        local_addr=overrides.get("local_addr", "192.168.1.20"),  # type: ignore[arg-type]
        local_port=overrides.get("local_port", 51515),  # type: ignore[arg-type]
        remote_addr=overrides.get("remote_addr", "93.184.216.34"),  # type: ignore[arg-type]
        remote_port=overrides.get("remote_port", 443),  # type: ignore[arg-type]
        protocol=overrides.get("protocol", "tcp"),  # type: ignore[arg-type]
        status=overrides.get("status", "ESTABLISHED"),  # type: ignore[arg-type]
        timestamp=overrides.get("timestamp", FIXED_TS),  # type: ignore[arg-type]
        exe_path=overrides.get("exe_path", r"C:\Tools\app.exe"),  # type: ignore[arg-type]
        username=overrides.get("username", r"DESKTOP\user"),  # type: ignore[arg-type]
    )


class TestExportAlertsCsv:
    def test_writes_expected_alert_row(self, tmp_path):
        output = tmp_path / "alerts.csv"
        result = export_alerts_csv([_make_alert()], str(output))

        assert Path(result) == output.resolve()
        with output.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))

        assert rows == [{
            "timestamp": datetime.fromtimestamp(FIXED_TS).isoformat(),
            "rule_name": "Suspicious Port",
            "severity": "HIGH",
            "description": "bad port",
            "pid": "4242",
            "process_name": "bad.exe",
            "details": "{'remote_port': 4444}",
        }]

    def test_empty_alert_export_writes_header_only(self, tmp_path):
        output = tmp_path / "alerts.csv"
        export_alerts_csv([], str(output))

        with output.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            assert reader.fieldnames == [
                "timestamp", "rule_name", "severity", "description",
                "pid", "process_name", "details",
            ]
            assert list(reader) == []

    def test_default_alert_path_is_created_in_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = Path(export_alerts_csv([_make_alert()]))

        assert result.parent == tmp_path
        assert result.name.startswith("netwatch_alerts_")
        assert result.suffix == ".csv"
        assert result.is_file()


class TestExportConnectionsCsv:
    def test_writes_expected_connection_row(self, tmp_path):
        output = tmp_path / "connections.csv"
        result = export_connections_csv([_make_record()], str(output))

        assert Path(result) == output.resolve()
        with output.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))

        assert rows == [{
            "timestamp": datetime.fromtimestamp(FIXED_TS).isoformat(),
            "pid": "100",
            "process_name": "app.exe",
            "exe_path": r"C:\Tools\app.exe",
            "username": r"DESKTOP\user",
            "protocol": "tcp",
            "local_addr": "192.168.1.20",
            "local_port": "51515",
            "remote_addr": "93.184.216.34",
            "remote_port": "443",
            "status": "ESTABLISHED",
        }]

    def test_optional_connection_fields_export_as_empty_strings(self, tmp_path):
        output = tmp_path / "connections.csv"
        rec = _make_record(
            remote_addr="",
            remote_port=0,
            exe_path=None,
            username=None,
            status="",
        )
        export_connections_csv([rec], str(output))

        with output.open(newline="", encoding="utf-8") as fh:
            row = next(csv.DictReader(fh))

        assert row["remote_addr"] == ""
        assert row["remote_port"] == ""
        assert row["exe_path"] == ""
        assert row["username"] == ""
        assert row["status"] == ""

    def test_default_connection_path_is_created_in_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = Path(export_connections_csv([_make_record()]))

        assert result.parent == tmp_path
        assert result.name.startswith("netwatch_connections_")
        assert result.suffix == ".csv"
        assert result.is_file()
