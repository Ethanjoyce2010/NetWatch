"""
Opt-in incident response actions for critical NetWatch alerts.

These helpers deliberately require explicit typed confirmation by default.
They are used by CLI flags, not by the detector itself.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import psutil

from .models import Alert, ProcessProfile, Severity


ConfirmFunc = Callable[[str], str]


@dataclass
class ResponseActionResult:
    """Result of a process response action."""

    action: str
    pid: int
    process_name: str
    success: bool
    message: str
    path: Optional[str] = None
    destination: Optional[str] = None


class ProcessResponder:
    """Handles optional kill-switch and quarantine workflows."""

    def __init__(self, quarantine_dir: Optional[str] = None):
        self.quarantine_dir = Path(quarantine_dir).expanduser() if quarantine_dir else (
            Path.home() / ".netwatch" / "quarantine"
        )
        self._terminated_pids: set[int] = set()
        self._quarantined_paths: set[str] = set()

    def terminate_critical(
        self,
        alerts: list[Alert],
        *,
        input_func: ConfirmFunc = input,
        require_confirmation: bool = True,
    ) -> list[ResponseActionResult]:
        """Terminate processes with critical alerts after confirmation."""
        results = []
        for pid, process_name in self._critical_processes(alerts).items():
            if pid in self._terminated_pids:
                continue
            results.append(
                self.terminate_pid(
                    pid,
                    process_name=process_name,
                    input_func=input_func,
                    require_confirmation=require_confirmation,
                )
            )
        return results

    def quarantine_critical(
        self,
        alerts: list[Alert],
        profiles: dict[int, ProcessProfile],
        *,
        input_func: ConfirmFunc = input,
        require_confirmation: bool = True,
    ) -> list[ResponseActionResult]:
        """Move executables for critical-alert processes into quarantine."""
        results = []
        for pid, process_name in self._critical_processes(alerts).items():
            profile = profiles.get(pid)
            exe_path = profile.exe_path if profile else None
            results.append(
                self.quarantine_file(
                    exe_path,
                    pid=pid,
                    process_name=process_name,
                    input_func=input_func,
                    require_confirmation=require_confirmation,
                )
            )
        return results

    def terminate_pid(
        self,
        pid: int,
        *,
        process_name: str = "unknown",
        input_func: ConfirmFunc = input,
        require_confirmation: bool = True,
        timeout: float = 5.0,
    ) -> ResponseActionResult:
        """Terminate one process by PID."""
        if require_confirmation:
            answer = input_func(
                f"Type TERMINATE to kill PID {pid} ({process_name}): "
            ).strip()
            if answer != "TERMINATE":
                return ResponseActionResult(
                    action="terminate",
                    pid=pid,
                    process_name=process_name,
                    success=False,
                    message="Skipped by user",
                )

        try:
            proc = psutil.Process(pid)
            resolved_name = proc.name() or process_name
            proc.terminate()
            proc.wait(timeout=timeout)
            self._terminated_pids.add(pid)
            return ResponseActionResult(
                action="terminate",
                pid=pid,
                process_name=resolved_name,
                success=True,
                message="Process terminated",
            )
        except psutil.NoSuchProcess:
            self._terminated_pids.add(pid)
            return ResponseActionResult(
                action="terminate",
                pid=pid,
                process_name=process_name,
                success=True,
                message="Process already exited",
            )
        except (psutil.AccessDenied, psutil.TimeoutExpired, OSError) as exc:
            return ResponseActionResult(
                action="terminate",
                pid=pid,
                process_name=process_name,
                success=False,
                message=str(exc),
            )

    def quarantine_file(
        self,
        exe_path: Optional[str],
        *,
        pid: int,
        process_name: str,
        input_func: ConfirmFunc = input,
        require_confirmation: bool = True,
    ) -> ResponseActionResult:
        """Move an executable into the quarantine directory."""
        if not exe_path:
            return ResponseActionResult(
                action="quarantine",
                pid=pid,
                process_name=process_name,
                success=False,
                message="No executable path available",
            )

        source = Path(exe_path)
        if str(source) in self._quarantined_paths:
            return ResponseActionResult(
                action="quarantine",
                pid=pid,
                process_name=process_name,
                success=True,
                message="Executable already quarantined this session",
                path=str(source),
            )
        if not source.is_file():
            return ResponseActionResult(
                action="quarantine",
                pid=pid,
                process_name=process_name,
                success=False,
                message="Executable does not exist on disk",
                path=str(source),
            )

        if require_confirmation:
            answer = input_func(
                f"Type QUARANTINE to move {source} for PID {pid} ({process_name}): "
            ).strip()
            if answer != "QUARANTINE":
                return ResponseActionResult(
                    action="quarantine",
                    pid=pid,
                    process_name=process_name,
                    success=False,
                    message="Skipped by user",
                    path=str(source),
                )

        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        destination = self._unique_destination(source)
        try:
            shutil.move(str(source), str(destination))
            self._quarantined_paths.add(str(source))
            return ResponseActionResult(
                action="quarantine",
                pid=pid,
                process_name=process_name,
                success=True,
                message="Executable moved to quarantine",
                path=str(source),
                destination=str(destination),
            )
        except OSError as exc:
            return ResponseActionResult(
                action="quarantine",
                pid=pid,
                process_name=process_name,
                success=False,
                message=str(exc),
                path=str(source),
                destination=str(destination),
            )

    def _unique_destination(self, source: Path) -> Path:
        base = self.quarantine_dir / source.name
        if not base.exists():
            return base
        stem, suffix = source.stem, source.suffix
        index = 1
        while True:
            candidate = self.quarantine_dir / f"{stem}_{index}{suffix}"
            if not candidate.exists():
                return candidate
            index += 1

    @staticmethod
    def _critical_processes(alerts: list[Alert]) -> dict[int, str]:
        processes: dict[int, str] = {}
        for alert in alerts:
            if alert.severity == Severity.CRITICAL:
                processes.setdefault(alert.pid, alert.process_name)
        return processes
