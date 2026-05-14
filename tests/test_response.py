"""Tests for netwatch.response"""

from unittest.mock import MagicMock

from netwatch.models import Alert, ProcessProfile, Severity
from netwatch.response import ProcessResponder


def _critical_alert(pid: int = 42, process_name: str = "bad.exe") -> Alert:
    return Alert(
        rule_name="Unexpected Network Process",
        severity=Severity.CRITICAL,
        description="critical",
        pid=pid,
        process_name=process_name,
    )


class TestProcessResponderTerminate:
    def test_terminate_requires_confirmation(self, monkeypatch):
        fake_proc = MagicMock()
        fake_proc.name.return_value = "bad.exe"
        monkeypatch.setattr("netwatch.response.psutil.Process", lambda pid: fake_proc)
        responder = ProcessResponder()

        result = responder.terminate_pid(
            42,
            process_name="bad.exe",
            input_func=lambda prompt: "nope",
        )

        assert result.success is False
        assert result.message == "Skipped by user"
        fake_proc.terminate.assert_not_called()

    def test_terminate_process_after_typed_confirmation(self, monkeypatch):
        fake_proc = MagicMock()
        fake_proc.name.return_value = "bad.exe"
        monkeypatch.setattr("netwatch.response.psutil.Process", lambda pid: fake_proc)
        responder = ProcessResponder()

        result = responder.terminate_pid(
            42,
            process_name="bad.exe",
            input_func=lambda prompt: "TERMINATE",
        )

        assert result.success is True
        fake_proc.terminate.assert_called_once()
        fake_proc.wait.assert_called_once()

    def test_terminate_critical_only_uses_critical_alerts(self, monkeypatch):
        fake_proc = MagicMock()
        fake_proc.name.return_value = "bad.exe"
        monkeypatch.setattr("netwatch.response.psutil.Process", lambda pid: fake_proc)
        responder = ProcessResponder()
        alerts = [
            _critical_alert(42, "bad.exe"),
            Alert(
                rule_name="Low",
                severity=Severity.LOW,
                description="low",
                pid=99,
                process_name="low.exe",
            ),
        ]

        results = responder.terminate_critical(
            alerts,
            input_func=lambda prompt: "TERMINATE",
        )

        assert [r.pid for r in results] == [42]


class TestProcessResponderQuarantine:
    def test_quarantine_requires_confirmation(self, tmp_path):
        exe = tmp_path / "bad.exe"
        exe.write_text("binary", encoding="utf-8")
        responder = ProcessResponder(quarantine_dir=str(tmp_path / "quarantine"))

        result = responder.quarantine_file(
            str(exe),
            pid=42,
            process_name="bad.exe",
            input_func=lambda prompt: "nope",
        )

        assert result.success is False
        assert exe.exists()

    def test_quarantine_moves_file_after_confirmation(self, tmp_path):
        exe = tmp_path / "bad.exe"
        exe.write_text("binary", encoding="utf-8")
        responder = ProcessResponder(quarantine_dir=str(tmp_path / "quarantine"))

        result = responder.quarantine_file(
            str(exe),
            pid=42,
            process_name="bad.exe",
            input_func=lambda prompt: "QUARANTINE",
        )

        assert result.success is True
        assert not exe.exists()
        assert result.destination is not None
        assert (tmp_path / "quarantine" / "bad.exe").exists()

    def test_quarantine_critical_uses_profile_exe_path(self, tmp_path):
        exe = tmp_path / "bad.exe"
        exe.write_text("binary", encoding="utf-8")
        profile = ProcessProfile(pid=42, name="bad.exe", exe_path=str(exe))
        responder = ProcessResponder(quarantine_dir=str(tmp_path / "quarantine"))

        results = responder.quarantine_critical(
            [_critical_alert()],
            {42: profile},
            input_func=lambda prompt: "QUARANTINE",
        )

        assert len(results) == 1
        assert results[0].success is True
