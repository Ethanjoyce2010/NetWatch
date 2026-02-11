"""Data models used throughout NetWatch."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    TCP6 = "tcp6"
    UDP6 = "udp6"


@dataclass
class ConnectionRecord:
    """A single observed network connection snapshot."""

    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    status: str
    timestamp: float = field(default_factory=time.time)
    exe_path: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None


@dataclass
class Alert:
    """An anomaly alert raised by the detection engine."""

    rule_name: str
    severity: Severity
    description: str
    pid: int
    process_name: str
    details: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def __str__(self) -> str:
        return (
            f"[{self.severity.value}] {self.rule_name} — "
            f"PID {self.pid} ({self.process_name}): {self.description}"
        )


@dataclass
class ProcessProfile:
    """Behavioural profile built up for a single process over time."""

    pid: int
    name: str
    exe_path: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None

    # Tracking counters
    total_connections: int = 0
    unique_remote_ips: set = field(default_factory=set)
    unique_remote_ports: set = field(default_factory=set)
    connection_timestamps: list = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def risk_score(self) -> int:
        """0-100 risk score based on accumulated alerts."""
        score = 0
        weights = {
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }
        for alert in self.alerts:
            score += weights.get(alert.severity, 5)
        return min(score, 100)
