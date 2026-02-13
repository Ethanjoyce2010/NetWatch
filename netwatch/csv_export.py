"""
CSV Exporter — write alerts, connection records, and stats to CSV files.

Generates CSV output suitable for spreadsheet analysis, SIEM import,
or further processing by other tools.
"""

from __future__ import annotations

import csv
import io
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Alert, ConnectionRecord


def export_alerts_csv(
    alerts: list[Alert],
    path: Optional[str] = None,
) -> str:
    """Export alerts to CSV.  Returns the path written."""
    if path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"netwatch_alerts_{ts}.csv"

    fieldnames = [
        "timestamp", "rule_name", "severity", "description",
        "pid", "process_name", "details",
    ]

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow({
                "timestamp": datetime.fromtimestamp(alert.timestamp).isoformat(),
                "rule_name": alert.rule_name,
                "severity": alert.severity.name,
                "description": alert.description,
                "pid": alert.pid,
                "process_name": alert.process_name,
                "details": str(alert.details) if alert.details else "",
            })

    return os.path.abspath(path)


def export_connections_csv(
    records: list[ConnectionRecord],
    path: Optional[str] = None,
) -> str:
    """Export connection records to CSV.  Returns the path written."""
    if path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"netwatch_connections_{ts}.csv"

    fieldnames = [
        "timestamp", "pid", "process_name", "exe_path", "username",
        "protocol", "local_addr", "local_port",
        "remote_addr", "remote_port", "status",
    ]

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            writer.writerow({
                "timestamp": datetime.fromtimestamp(rec.timestamp).isoformat(),
                "pid": rec.pid,
                "process_name": rec.process_name,
                "exe_path": rec.exe_path or "",
                "username": rec.username or "",
                "protocol": str(rec.protocol),
                "local_addr": rec.local_addr,
                "local_port": rec.local_port,
                "remote_addr": rec.remote_addr or "",
                "remote_port": rec.remote_port or "",
                "status": rec.status or "",
            })

    return os.path.abspath(path)
