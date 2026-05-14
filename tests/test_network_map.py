"""Tests for netwatch.network_map"""

from netwatch.models import Alert, ConnectionRecord, Severity
from netwatch.network_map import NetworkMapGenerator


def _make_record(**overrides: object) -> ConnectionRecord:
    return ConnectionRecord(
        pid=overrides.get("pid", 100),  # type: ignore[arg-type]
        process_name=overrides.get("process_name", "app.exe"),  # type: ignore[arg-type]
        local_addr=overrides.get("local_addr", "192.168.1.20"),  # type: ignore[arg-type]
        local_port=overrides.get("local_port", 51515),  # type: ignore[arg-type]
        remote_addr=overrides.get("remote_addr", "203.0.113.10"),  # type: ignore[arg-type]
        remote_port=overrides.get("remote_port", 443),  # type: ignore[arg-type]
        protocol=overrides.get("protocol", "tcp"),  # type: ignore[arg-type]
        status=overrides.get("status", "ESTABLISHED"),  # type: ignore[arg-type]
    )


def _make_alert() -> Alert:
    return Alert(
        rule_name="Known C2 IP (Threat Intel)",
        severity=Severity.CRITICAL,
        description="known bad",
        pid=100,
        process_name="app.exe",
        details={"remote_addr": "203.0.113.10", "remote_port": 443},
    )


class TestNetworkMapGenerator:
    def test_build_data_groups_processes_endpoints_and_edges(self):
        generator = NetworkMapGenerator()
        records = [
            _make_record(),
            _make_record(),
            _make_record(remote_addr="203.0.113.11", remote_port=8443),
        ]

        data = generator.build_data(records, alerts=[_make_alert()])

        assert data.process_count == 1
        assert data.endpoint_count == 2
        assert data.connection_count == 3
        assert data.alert_count == 1
        assert any(node["kind"] == "process" and node["risk"] == 50 for node in data.nodes)
        assert any(edge["count"] == 2 for edge in data.edges)

    def test_generate_writes_html_with_refresh(self, tmp_path):
        output = tmp_path / "map.html"
        generator = NetworkMapGenerator()

        result = generator.generate(
            str(output),
            [_make_record()],
            alerts=[_make_alert()],
            refresh_seconds=5,
        )

        html = output.read_text(encoding="utf-8")
        assert result == str(output.resolve())
        assert "NetWatch Network Map" in html
        assert "app.exe" in html
        assert "203.0.113.10" in html
        assert 'http-equiv="refresh" content="5"' in html
