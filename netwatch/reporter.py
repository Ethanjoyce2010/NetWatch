"""
Reporting — renders alerts, process profiles, and investigations
to the console and optionally to a JSON log file.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, TextIO

from .investigator import ProcessInvestigation
from .models import Alert, ProcessProfile, Severity

logger = logging.getLogger("netwatch.reporter")

# ANSI colours for terminal output
_COLORS = {
    Severity.LOW: "\033[94m",       # blue
    Severity.MEDIUM: "\033[93m",    # yellow
    Severity.HIGH: "\033[91m",      # red
    Severity.CRITICAL: "\033[95m",  # magenta
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _severity_color(severity: Severity) -> str:
    return _COLORS.get(severity, "")


class Reporter:
    """Formats and emits alerts, summaries, and investigation reports."""

    def __init__(self, log_file: Optional[str] = None):
        self._log_file: Optional[Path] = Path(log_file) if log_file else None
        self._alert_count = 0
        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            # Write opening bracket for JSON array
            self._log_file.write_text("[\n", encoding="utf-8")

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def report_alerts(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            self._alert_count += 1
            color = _severity_color(alert.severity)
            print(
                f"  {color}{_BOLD}⚠ [{alert.severity.value}]{_RESET} "
                f"{color}{alert.rule_name}{_RESET} — "
                f"PID {alert.pid} ({alert.process_name}): {alert.description}"
            )
            if self._log_file:
                self._append_json(self._alert_to_dict(alert))

    # ------------------------------------------------------------------
    # Live status line
    # ------------------------------------------------------------------

    def print_status(self, n_connections: int, n_profiles: int, n_alerts: int, elapsed: float) -> None:
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        print(
            f"\r{_DIM}[{mins:02d}:{secs:02d}] "
            f"Connections: {n_connections}  |  "
            f"Tracked processes: {n_profiles}  |  "
            f"Total alerts: {n_alerts}{_RESET}",
            end="",
            flush=True,
        )

    # ------------------------------------------------------------------
    # Summary table
    # ------------------------------------------------------------------

    def print_summary(self, profiles: list[ProcessProfile]) -> None:
        if not profiles:
            print(f"\n{_DIM}No suspicious processes detected.{_RESET}")
            return

        print(f"\n{'=' * 80}")
        print(f"{_BOLD}  SUSPICIOUS PROCESS SUMMARY (sorted by risk){_RESET}")
        print(f"{'=' * 80}")
        print(
            f"  {'PID':<8} {'Name':<22} {'Risk':>5}  {'Alerts':>6}  "
            f"{'IPs':>5}  {'Ports':>5}  {'User':<15}"
        )
        print(f"  {'-' * 74}")

        for p in profiles:
            risk = p.risk_score
            if risk >= 50:
                c = _COLORS[Severity.CRITICAL]
            elif risk >= 30:
                c = _COLORS[Severity.HIGH]
            elif risk >= 15:
                c = _COLORS[Severity.MEDIUM]
            else:
                c = _COLORS[Severity.LOW]

            print(
                f"  {c}{p.pid:<8} {p.name:<22} {risk:>5}  {len(p.alerts):>6}  "
                f"{len(p.unique_remote_ips):>5}  {len(p.unique_remote_ports):>5}  "
                f"{(p.username or 'N/A'):<15}{_RESET}"
            )

        print(f"{'=' * 80}\n")

    # ------------------------------------------------------------------
    # DLL injection scan report
    # ------------------------------------------------------------------

    def print_dll_scan(self, results: list) -> None:
        """Print a DLL injection scan report from DLLScanResult objects."""
        if not results:
            print(f"  {_DIM}No suspicious DLL injections detected across scanned processes.{_RESET}\n")
            return

        total_findings = sum(len(r.suspicious_modules) for r in results)
        print(f"\n{'=' * 80}")
        print(
            f"{_BOLD}  DLL INJECTION SCAN — "
            f"{total_findings} suspicious module(s) in {len(results)} process(es){_RESET}"
        )
        print(f"{'=' * 80}")

        for r in results:
            n_sus = len(r.suspicious_modules)
            color = _COLORS[Severity.CRITICAL] if n_sus >= 3 else _COLORS[Severity.HIGH] if n_sus >= 1 else ""
            print(
                f"\n  {color}{_BOLD}PID {r.pid} — {r.process_name}{_RESET}  "
                f"({r.total_modules} modules loaded, {n_sus} suspicious)"
            )
            if r.exe_path:
                print(f"     Exe: {r.exe_path}")

            for dll in r.suspicious_modules:
                exists_tag = "" if dll.get("exists_on_disk", True) else f" {_COLORS[Severity.CRITICAL]}[MISSING FROM DISK]{_RESET}"
                print(f"\n     {_COLORS[Severity.HIGH]}{_BOLD}{dll['name']}{_RESET}{exists_tag}")
                print(f"       Path: {dll['path']}")
                for reason in dll.get("reasons", []):
                    print(f"       {_COLORS[Severity.MEDIUM]}\u2192 {reason}{_RESET}")

        print(f"\n{'=' * 80}\n")

    # ------------------------------------------------------------------
    # Deep investigation report
    # ------------------------------------------------------------------

    def print_investigation(self, inv: ProcessInvestigation) -> None:
        print(f"\n  {_BOLD}── Investigation: PID {inv.pid} ({inv.name}) ──{_RESET}")
        fields = [
            ("Executable", inv.exe_path),
            ("Exists on disk", inv.exe_exists_on_disk),
            ("Command line", inv.cmdline),
            ("User", inv.username),
            ("Working dir", inv.cwd),
            ("Status", inv.status),
            ("Parent", f"PID {inv.parent_pid} ({inv.parent_name})" if inv.parent_pid else None),
            ("Threads", inv.num_threads),
            ("Memory", f"{inv.memory_mb:.1f} MB" if inv.memory_mb else None),
            ("CPU %", f"{inv.cpu_percent:.1f}%" if inv.cpu_percent is not None else None),
        ]
        for label, value in fields:
            if value is not None:
                print(f"     {label:<18}: {value}")

        if inv.children:
            print(f"     {'Children':<18}:")
            for child in inv.children[:10]:
                print(f"       - PID {child['pid']} ({child['name']})")
            if len(inv.children) > 10:
                print(f"       … and {len(inv.children) - 10} more")

        if inv.connections:
            print(f"     {'Connections':<18}:")
            for c in inv.connections[:10]:
                print(f"       {c['local']} → {c['remote']}  [{c['status']}]")
            if len(inv.connections) > 10:
                print(f"       … and {len(inv.connections) - 10} more")

        if inv.environ_suspicious_keys:
            print(f"     {_COLORS[Severity.HIGH]}Suspicious env vars:{_RESET}")
            for k, v in inv.environ_suspicious_keys.items():
                print(f"       {k} = {v[:80]}")

        if inv.suspicious_dlls:
            print(
                f"     {_COLORS[Severity.CRITICAL]}{_BOLD}"
                f"⚠ SUSPICIOUS DLLs ({len(inv.suspicious_dlls)} found, "
                f"{inv.total_loaded_modules} total modules loaded):{_RESET}"
            )
            for dll in inv.suspicious_dlls:
                exists_tag = "" if dll.get("exists_on_disk", True) else f" {_COLORS[Severity.CRITICAL]}[NOT ON DISK]{_RESET}"
                print(f"       {_COLORS[Severity.HIGH]}{dll['name']}{_RESET}{exists_tag}")
                print(f"         Path: {dll['path']}")
                for reason in dll.get('reasons', []):
                    print(f"         → {reason}")
        elif inv.total_loaded_modules:
            print(f"     {_DIM}Loaded modules    : {inv.total_loaded_modules} (none suspicious){_RESET}")

        if inv.exe_exists_on_disk is False:
            print(
                f"     {_COLORS[Severity.CRITICAL]}{_BOLD}"
                f"⚠ EXECUTABLE NOT FOUND ON DISK — possible fileless malware{_RESET}"
            )
        print()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _alert_to_dict(alert: Alert) -> dict:
        return {
            "timestamp": datetime.fromtimestamp(alert.timestamp).isoformat(),
            "severity": alert.severity.value,
            "rule": alert.rule_name,
            "pid": alert.pid,
            "process": alert.process_name,
            "description": alert.description,
            "details": alert.details,
        }

    def _append_json(self, obj: dict) -> None:
        assert self._log_file is not None
        with self._log_file.open("a", encoding="utf-8") as f:
            prefix = "  " if self._alert_count == 1 else ",\n  "
            f.write(prefix + json.dumps(obj))

    def close(self) -> None:
        if self._log_file:
            with self._log_file.open("a", encoding="utf-8") as f:
                f.write("\n]\n")
