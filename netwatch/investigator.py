"""
Process Investigator — deep-dives into a suspicious process to gather
forensic details for the operator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger("netwatch.investigator")


@dataclass
class ProcessInvestigation:
    """Full forensic dump of a single process."""

    pid: int
    name: str
    exe_path: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None
    cwd: Optional[str] = None
    status: Optional[str] = None
    create_time: Optional[float] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    children: list[dict] = field(default_factory=list)
    open_files: list[str] = field(default_factory=list)
    connections: list[dict] = field(default_factory=list)
    memory_mb: Optional[float] = None
    cpu_percent: Optional[float] = None
    num_threads: Optional[int] = None
    environ_suspicious_keys: dict = field(default_factory=dict)
    exe_exists_on_disk: Optional[bool] = None
    exe_signed: Optional[str] = None  # placeholder for future sig check
    suspicious_dlls: list[dict] = field(default_factory=list)
    total_loaded_modules: int = 0


class ProcessInvestigator:
    """Performs deep inspection of a running process."""

    # Environment variable names that may reveal lateral movement / persistence
    SUSPICIOUS_ENV_KEYS = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "COMSPEC", "PSModulePath",
    }

    def investigate(self, pid: int) -> Optional[ProcessInvestigation]:
        """Gather all available info about a process by PID."""
        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            logger.warning("PID %d no longer exists", pid)
            return None

        inv = ProcessInvestigation(pid=pid, name=proc.name() or "unknown")

        # Basic metadata
        self._safe(lambda: setattr(inv, "exe_path", proc.exe()))
        self._safe(lambda: setattr(inv, "cmdline", " ".join(proc.cmdline())))
        self._safe(lambda: setattr(inv, "username", proc.username()))
        self._safe(lambda: setattr(inv, "cwd", proc.cwd()))
        self._safe(lambda: setattr(inv, "status", proc.status()))
        self._safe(lambda: setattr(inv, "create_time", proc.create_time()))
        self._safe(lambda: setattr(inv, "num_threads", proc.num_threads()))

        # Memory & CPU
        self._safe(
            lambda: setattr(inv, "memory_mb", proc.memory_info().rss / (1024 * 1024))
        )
        self._safe(lambda: setattr(inv, "cpu_percent", proc.cpu_percent(interval=0.5)))

        # Parent
        self._safe(lambda: self._resolve_parent(proc, inv))

        # Children
        self._safe(lambda: self._resolve_children(proc, inv))

        # Open files
        self._safe(lambda: self._resolve_open_files(proc, inv))

        # Active connections
        self._safe(lambda: self._resolve_connections(proc, inv))

        # Check if the exe actually exists on disk (common for fileless malware)
        if inv.exe_path:
            inv.exe_exists_on_disk = Path(inv.exe_path).exists()

        # Suspicious env vars
        self._safe(lambda: self._check_env(proc, inv))

        # DLL injection scan
        self._safe(lambda: self._scan_dlls(pid, inv))

        return inv

    def investigate_all_risky(self, profiles) -> list[ProcessInvestigation]:
        """Investigate every process that has a non-zero risk score."""
        results = []
        for profile in profiles:
            report = self.investigate(profile.pid)
            if report:
                results.append(report)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe(fn):
        try:
            fn()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, TypeError):
            pass

    @staticmethod
    def _resolve_parent(proc, inv: ProcessInvestigation):
        parent = proc.parent()
        if parent:
            inv.parent_pid = parent.pid
            inv.parent_name = parent.name()

    @staticmethod
    def _resolve_children(proc, inv: ProcessInvestigation):
        for child in proc.children(recursive=True):
            try:
                inv.children.append({"pid": child.pid, "name": child.name()})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    @staticmethod
    def _resolve_open_files(proc, inv: ProcessInvestigation):
        for f in proc.open_files():
            inv.open_files.append(f.path)

    @staticmethod
    def _resolve_connections(proc, inv: ProcessInvestigation):
        for c in proc.net_connections(kind="inet"):
            entry = {
                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,
            }
            inv.connections.append(entry)

    def _check_env(self, proc, inv: ProcessInvestigation):
        env = proc.environ()
        for key in self.SUSPICIOUS_ENV_KEYS:
            if key in env:
                inv.environ_suspicious_keys[key] = env[key]

    @staticmethod
    def _scan_dlls(pid: int, inv: ProcessInvestigation):
        from .dll_inspector import DLLInspector
        inspector = DLLInspector()
        result = inspector.scan_process(pid)
        if result:
            inv.total_loaded_modules = result.total_modules
            inv.suspicious_dlls = result.suspicious_modules
