"""
Traffic Monitor — captures live network connections using psutil
and maps each connection back to its owning process.
"""

from __future__ import annotations

import logging
import time
from typing import Generator

import psutil

from .models import ConnectionRecord

logger = logging.getLogger("netwatch.monitor")


class TrafficMonitor:
    """Polls the OS for active network connections and yields ConnectionRecords."""

    def __init__(self, poll_interval: float = 2.0):
        self.poll_interval = poll_interval
        self._process_cache: dict[int, dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def snapshot(self) -> list[ConnectionRecord]:
        """Take a single snapshot of all current network connections."""
        records: list[ConnectionRecord] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.warning(
                "Access denied reading connections — try running as Administrator / root."
            )
            return records

        for conn in connections:
            if conn.pid is None or conn.pid == 0:
                continue  # kernel / system socket

            remote_addr, remote_port = ("", 0)
            if conn.raddr:
                remote_addr = conn.raddr.ip
                remote_port = conn.raddr.port

            local_addr = conn.laddr.ip if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0

            proc_info = self._resolve_process(conn.pid)

            record = ConnectionRecord(
                pid=conn.pid,
                process_name=proc_info.get("name", "unknown"),
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                protocol=self._conn_type(conn.type),
                status=conn.status if hasattr(conn, "status") else "NONE",
                exe_path=proc_info.get("exe"),
                cmdline=proc_info.get("cmdline"),
                username=proc_info.get("username"),
            )
            records.append(record)

        return records

    def stream(self) -> Generator[list[ConnectionRecord], None, None]:
        """Continuously yield connection snapshots at the configured interval."""
        logger.info(
            "Starting traffic monitor (poll every %.1fs)…", self.poll_interval
        )
        while True:
            yield self.snapshot()
            time.sleep(self.poll_interval)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve_process(self, pid: int) -> dict:
        """Look up process metadata, caching results."""
        if pid in self._process_cache:
            return self._process_cache[pid]

        info: dict = {"name": "unknown", "exe": None, "cmdline": None, "username": None}
        try:
            proc = psutil.Process(pid)
            info["name"] = proc.name() or "unknown"
            try:
                info["exe"] = proc.exe()
            except (psutil.AccessDenied, OSError):
                pass
            try:
                cmdline = proc.cmdline()
                info["cmdline"] = " ".join(cmdline) if cmdline else None
            except (psutil.AccessDenied, OSError):
                pass
            try:
                info["username"] = proc.username()
            except (psutil.AccessDenied, OSError):
                pass
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

        self._process_cache[pid] = info
        return info

    @staticmethod
    def _conn_type(sock_type) -> str:
        import socket

        mapping = {
            socket.SOCK_STREAM: "tcp",
            socket.SOCK_DGRAM: "udp",
        }
        return mapping.get(sock_type, str(sock_type))
