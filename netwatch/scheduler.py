"""
Scheduled task persistence scanner.

On Windows this wraps `schtasks /Query /FO CSV /V` and applies lightweight
heuristics to flag tasks that launch LOLBins, scripts, remote URLs, or files
from user-writable locations.
"""

from __future__ import annotations

import csv
import io
import platform
import re
import subprocess
from dataclasses import dataclass, field

from .models import Severity


LOLBIN_TASK_COMMANDS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

USER_WRITABLE_PATH_MARKERS = (
    "\\appdata\\",
    "\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
)

SCRIPT_EXTENSIONS = (".ps1", ".vbs", ".js", ".jse", ".hta", ".bat", ".cmd")
REMOTE_PATTERN = re.compile(r"(https?://|ftp://|\\\\)", re.IGNORECASE)
ENCODED_PATTERN = re.compile(r"(-enc\b|-encodedcommand\b|frombase64string)", re.IGNORECASE)


@dataclass
class ScheduledTaskFinding:
    """Suspicious scheduled task finding."""

    task_name: str
    command: str
    author: str = ""
    status: str = ""
    severity: Severity = Severity.MEDIUM
    reasons: list[str] = field(default_factory=list)


class TaskSchedulerScanner:
    """Scans Windows Scheduled Tasks for persistence indicators."""

    def scan(self) -> list[ScheduledTaskFinding]:
        """Run schtasks and return suspicious task findings."""
        if platform.system().lower() != "windows":
            return []

        result = subprocess.run(
            ["schtasks", "/Query", "/FO", "CSV", "/V"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            return []
        return self.parse_schtasks_csv(result.stdout)

    @classmethod
    def parse_schtasks_csv(cls, text: str) -> list[ScheduledTaskFinding]:
        """Parse verbose schtasks CSV output and flag suspicious entries."""
        findings: list[ScheduledTaskFinding] = []
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            command = cls._first_present(row, "Task To Run", "TaskName To Run", "Action")
            if not command or command.upper() in {"N/A", "DISABLED"}:
                continue

            reasons = cls._reasons_for_command(command)
            if not reasons:
                continue

            severity = Severity.HIGH if cls._is_high_severity(reasons) else Severity.MEDIUM
            findings.append(
                ScheduledTaskFinding(
                    task_name=cls._first_present(row, "TaskName", "Task Name", "Name"),
                    command=command,
                    author=cls._first_present(row, "Author"),
                    status=cls._first_present(row, "Status"),
                    severity=severity,
                    reasons=reasons,
                )
            )
        return findings

    @staticmethod
    def _first_present(row: dict[str, str], *keys: str) -> str:
        for key in keys:
            value = row.get(key)
            if value:
                return value.strip()
        return ""

    @staticmethod
    def _reasons_for_command(command: str) -> list[str]:
        command_lower = command.lower()
        reasons: list[str] = []

        if any(exe in command_lower for exe in LOLBIN_TASK_COMMANDS):
            reasons.append("launches a LOLBin or script host")
        if any(marker in command_lower for marker in USER_WRITABLE_PATH_MARKERS):
            reasons.append("runs from a user-writable path")
        if any(ext in command_lower for ext in SCRIPT_EXTENSIONS):
            reasons.append("runs a script file")
        if REMOTE_PATTERN.search(command):
            reasons.append("references a remote path or URL")
        if ENCODED_PATTERN.search(command):
            reasons.append("contains encoded command content")

        return reasons

    @staticmethod
    def _is_high_severity(reasons: list[str]) -> bool:
        high_signals = {
            "contains encoded command content",
            "references a remote path or URL",
        }
        return any(reason in high_signals for reason in reasons) and len(reasons) >= 2
